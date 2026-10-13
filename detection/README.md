# detection/ — S3 (SecOps)

| Path | What goes here |
|---|---|
| `athena-queries/` | The catalogued hunt queries (FR-8): outbound C2 from flow logs, root-cause API call from CloudTrail, and so on. One `.sql` file per query, with a header comment giving the ATT&CK technique and the scenario it answers. |

Flow logs land in the log archive as **Parquet with Hive partitions** under `vpc-flow-logs/AWSLogs/aws-account-id=<id>/aws-service=vpcflowlogs/aws-region=<region>/year=/month=/day=/hour=/`. The custom format adds `flow-direction`, `pkt-srcaddr`/`pkt-dstaddr`, `tcp-flags` and `traffic-path` (see `infra/terraform/modules/network/main.tf`). Build the Glue table schema from that field list.
