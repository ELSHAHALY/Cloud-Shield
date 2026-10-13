-- CloudShield hunt 01: attacker timeline by access key / principal / source IP
-- ATT&CK: T1078 Valid Accounts; T1552.001 / T1552.005 Unsecured Credentials
-- Scenario: A (stolen instance-role session), B (honeytoken IAM key)
-- Tables: cloudtrail
-- Parameters: 7
--   1  first partition day   'yyyy/MM/dd'
--   2  last partition day    'yyyy/MM/dd'
--   3  window start          ISO-8601 UTC, e.g. '2026-10-14T09:00:00Z'
--   4  window end            ISO-8601 UTC
--   5  access key id         (AKIA... / ASIA...)
--   6  principal ARN         exact userIdentity.arn
--   7  source IP
--   Pass 'none' for any of 5-7 you are not filtering on.
-- Usage: PREPARE h01 FROM <this>; EXECUTE h01 USING '2026/10/14', '2026/10/14',
--        '2026-10-14T09:00:00Z', '2026-10-14T11:00:00Z', 'none', 'none', '203.0.113.7'
-- Expected: one row per API call, oldest first. After PB-01/PB-02 the same
--   key or session shows errorcode AccessDenied: the containment, as seen
--   from the attacker's side.

SELECT
    from_iso8601_timestamp(eventtime)               AS event_time,
    eventsource,
    eventname,
    awsregion,
    sourceipaddress,
    useragent,
    useridentity.type                               AS identity_type,
    useridentity.arn                                AS principal_arn,
    useridentity.accesskeyid                        AS access_key_id,
    useridentity.sessioncontext.sessionissuer.arn   AS session_issuer_arn,
    errorcode,
    errormessage,
    readonly,
    requestparameters
FROM cloudtrail
WHERE "timestamp" BETWEEN ? AND ?
  AND from_iso8601_timestamp(eventtime)
      BETWEEN from_iso8601_timestamp(?) AND from_iso8601_timestamp(?)
  AND (
        useridentity.accesskeyid = ?
     OR useridentity.arn = ?
     OR sourceipaddress = ?
  )
ORDER BY event_time
LIMIT 10000
