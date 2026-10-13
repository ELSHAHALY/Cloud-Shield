"""IncidentRepository: the only code that writes playbook results to the incidents table.

The router creates the row (RecordDetected) and owns `status`, `eventTime`,
`findingCreatedAt` and `containedAt`. Playbooks only append to `actions` and set
evidence fields, so they can never forge a CONTAINED status or an MTTC figure.
"""

from __future__ import annotations

from typing import Any

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

_ROUTER_OWNED = frozenset(
    {
        "incidentId",
        "status",
        "eventTime",
        "firstEventTime",
        "findingCreatedAt",
        "containedAt",
        "wouldContainAt",
        "sfnStartedAt",
        "executionArn",
        "attempts",
    }
)

_serializer = TypeSerializer()
_deserializer = TypeDeserializer()


def _serialize(value: Any) -> dict[str, Any]:
    return _serializer.serialize(value)


class IncidentRepository:
    def __init__(self, table_name: str, dynamodb: Any) -> None:
        self._table = table_name
        self._ddb = dynamodb

    def get(self, incident_id: str) -> dict[str, Any]:
        item = self._ddb.get_item(
            TableName=self._table,
            Key={"incidentId": {"S": incident_id}},
            ConsistentRead=True,
        ).get("Item")
        if item is None:
            raise LookupError(f"incident {incident_id} has no row")
        return {k: _deserializer.deserialize(v) for k, v in item.items()}

    def append_action(self, incident_id: str, action: dict[str, Any]) -> None:
        self._ddb.update_item(
            TableName=self._table,
            Key={"incidentId": {"S": incident_id}},
            UpdateExpression="SET actions = list_append(if_not_exists(actions, :empty), :a)",
            ConditionExpression="attribute_exists(incidentId)",
            ExpressionAttributeValues={":a": {"L": [_serialize(action)]}, ":empty": {"L": []}},
        )

    def add_evidence(self, incident_id: str, record: dict[str, Any]) -> None:
        """Append an evidence record. `evidenceSha256` keeps the FIRST hash: a
        re-run after FAILED captures an already-remediated state and must not
        displace the original exposure evidence (audit A8)."""
        self._ddb.update_item(
            TableName=self._table,
            Key={"incidentId": {"S": incident_id}},
            UpdateExpression=(
                "SET evidenceRecords = list_append(if_not_exists(evidenceRecords, :empty), :r), "
                "evidenceSha256 = if_not_exists(evidenceSha256, :h)"
            ),
            ConditionExpression="attribute_exists(incidentId)",
            ExpressionAttributeValues={
                ":r": {"L": [_serialize(record)]},
                ":empty": {"L": []},
                ":h": {"S": record["sha256"]},
            },
        )

    def set_fields(self, incident_id: str, fields: dict[str, Any]) -> None:
        forbidden = _ROUTER_OWNED.intersection(fields)
        if forbidden:
            raise ValueError(f"playbooks may not write router-owned fields: {sorted(forbidden)}")
        if not fields:
            return
        names = {f"#f{i}": name for i, name in enumerate(fields)}
        values = {f":v{i}": _serialize(value) for i, value in enumerate(fields.values())}
        self._ddb.update_item(
            TableName=self._table,
            Key={"incidentId": {"S": incident_id}},
            UpdateExpression="SET " + ", ".join(f"#f{i} = :v{i}" for i in range(len(fields))),
            ConditionExpression="attribute_exists(incidentId)",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
