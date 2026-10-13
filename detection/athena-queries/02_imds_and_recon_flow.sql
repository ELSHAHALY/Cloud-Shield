-- CloudShield hunt 02: report-worker recon shape + its role used from elsewhere
-- ATT&CK: T1046 Network Service Discovery; T1552.005 Cloud Instance Metadata API
-- Scenario: A (EC2 report-worker: scan from the instance, then its IMDS
--   role credentials used from an IP that is not the VPC's NAT egress)
-- Tables: vpc_flow_logs, cloudtrail
-- Parameters: 7
--   1  flow-log year     'yyyy'
--   2  flow-log month    'MM'
--   3  flow-log day      'dd'
--   4  instance id       the report-worker, e.g. 'i-0abc...'
--   5  CloudTrail day    'yyyy/MM/dd' (same day as 1-3)
--   6  worker role ARN   the session issuer, e.g. 'arn:aws:iam::<acct>:role/<name>-report-worker'
--   7  NAT egress IP     network module output nat_public_ip; calls from it are the instance itself
-- Expected: per minute, the scan signal (many distinct destination ports or
--   hosts, rejected flows) next to role API calls from a foreign IP. Both in
--   the same minutes = the scenario A chain. port_scan_shape uses a
--   threshold of 20 distinct ports/minute; tune it to the lab baseline.

WITH flows AS (
    SELECT
        date_trunc('minute', from_unixtime("start"))          AS minute,
        count(DISTINCT dstport)                               AS distinct_dst_ports,
        count(DISTINCT dstaddr)                               AS distinct_dst_hosts,
        sum(CASE WHEN action = 'REJECT' THEN 1 ELSE 0 END)    AS rejected_flows,
        sum(bytes)                                            AS bytes_out
    FROM vpc_flow_logs
    WHERE year = ? AND month = ? AND day = ?
      AND instance_id = ?
      AND flow_direction = 'egress'
    GROUP BY 1
),
role_calls AS (
    SELECT
        date_trunc('minute', from_iso8601_timestamp(eventtime)) AS minute,
        sourceipaddress,
        count(*)                                                AS api_calls,
        array_agg(DISTINCT eventname)                           AS api_names,
        sum(CASE WHEN errorcode IS NOT NULL THEN 1 ELSE 0 END)  AS failed_calls
    FROM cloudtrail
    WHERE "timestamp" = ?
      AND useridentity.sessioncontext.sessionissuer.arn = ?
      AND sourceipaddress <> ?
      AND vpcendpointid IS NULL
    GROUP BY 1, 2
)
SELECT
    coalesce(f.minute, r.minute)              AS minute,
    f.distinct_dst_ports,
    f.distinct_dst_hosts,
    f.rejected_flows,
    f.bytes_out,
    r.sourceipaddress                         AS role_used_from_ip,
    r.api_calls,
    r.api_names,
    r.failed_calls,
    coalesce(f.distinct_dst_ports >= 20, false) AS port_scan_shape,
    r.api_calls IS NOT NULL                   AS role_used_outside_vpc
FROM flows f
FULL OUTER JOIN role_calls r ON f.minute = r.minute
ORDER BY minute
