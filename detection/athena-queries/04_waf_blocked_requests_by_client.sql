-- CloudShield hunt 04: WAF blocked requests by client, terminating rule and action
-- ATT&CK: T1190 Exploit Public-Facing Application; T1595 Active Scanning; T1499 Endpoint Denial of Service
-- Scenario: QA (ZAP baseline / abusive client against the edge), E (edge IP abuse -> PB-05 block)
-- Tables: waf_logs (modules/detection, created with enable_waf_logs; both web ACLs)
-- Parameters: 2
--   1  first partition minute   'yyyy/MM/dd/HH/mm' (UTC)
--   2  last partition minute    'yyyy/MM/dd/HH/mm' (UTC)
-- Usage: PREPARE h04 FROM <this>; EXECUTE h04 USING '2026/10/16/09/00', '2026/10/16/11/00'
-- Expected: one row per client IP / web ACL / terminating rule / action for
--   every request that was not simply allowed, busiest first:
--   * RateLimitPerIp rows = the per-IP rate limit answering 429; the
--     rate_limited_keys column shows the IPs WAF was limiting (what the
--     PB-05 harvester publishes).
--   * soar_block_hits > 0 = requests stopped by the SoarBlockedIps rule,
--     i.e. the PB-05 block list taking effect at the edge.
--   * OriginVerify rows (regional ACL, waf_region = the API's region) =
--     direct execute-api calls that bypassed CloudFront.
--   * AWSManagedRules* rows = scanner / exploit payloads (ZAP, SQLi probes).
--   client_ip on the regional ACL is CloudFront's address (F3); use the
--   cloudfront rows for real client IPs.

SELECT
    httprequest.clientip                                               AS client_ip,
    httprequest.country                                                AS country,
    waf_region,
    webacl,
    terminatingruleid                                                  AS terminating_rule,
    action,
    count(*)                                                           AS requests,
    from_unixtime(min("timestamp") / 1000)                             AS first_seen,
    from_unixtime(max("timestamp") / 1000)                             AS last_seen,
    slice(array_agg(DISTINCT httprequest.uri), 1, 10)                  AS sample_uris,
    array_distinct(flatten(
        array_agg(transform(ratebasedrulelist, r -> r.limitkey))
            FILTER (WHERE cardinality(ratebasedrulelist) > 0)
    ))                                                                 AS rate_limited_keys,
    sum(CASE WHEN terminatingruleid = 'SoarBlockedIps' THEN 1 ELSE 0 END) AS soar_block_hits
FROM waf_logs
WHERE log_time BETWEEN ? AND ?
  AND action <> 'ALLOW'
GROUP BY
    httprequest.clientip,
    httprequest.country,
    waf_region,
    webacl,
    terminatingruleid,
    action
ORDER BY requests DESC
LIMIT 1000
