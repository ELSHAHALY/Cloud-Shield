-- CloudShield hunt 03: S3 exposure changes and object access around the window
-- ATT&CK: T1530 Data from Cloud Storage
-- Scenario: C (bucket Block Public Access disabled -> PB-03 restore)
-- Tables: cloudtrail (management events + S3 data events, modules/detection)
-- Parameters: 5
--   1  first partition day   'yyyy/MM/dd'
--   2  last partition day    'yyyy/MM/dd'
--   3  window start          ISO-8601 UTC
--   4  window end            ISO-8601 UTC
--   5  bucket name
-- Expected: the exposure-change rows (who turned BPA off, PB-03's role
--   turning it back on) and every object read in between, with
--   external-access flagged. No external-access rows inside the window =
--   no data left through the exposure. Object reads appear only for buckets
--   in data_event_bucket_arns.

SELECT
    from_iso8601_timestamp(eventtime)                           AS event_time,
    eventcategory,
    eventname,
    json_extract_scalar(requestparameters, '$.bucketName')      AS bucket,
    json_extract_scalar(requestparameters, '$.key')             AS object_key,
    useridentity.type                                           AS identity_type,
    coalesce(useridentity.arn, useridentity.accountid)          AS principal,
    sourceipaddress,
    useragent,
    errorcode,
    CASE
        WHEN eventname IN (
            'DeleteBucketPublicAccessBlock', 'PutBucketPublicAccessBlock',
            'PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl', 'PutObjectAcl'
        ) THEN 'exposure-change'
        WHEN eventcategory = 'Data'
             AND (useridentity.accountid = 'anonymous'
                  OR useridentity.accountid IS DISTINCT FROM recipientaccountid)
            THEN 'external-access'
        WHEN eventcategory = 'Data' THEN 'data-access'
        ELSE 'other'
    END                                                         AS classification,
    requestparameters
FROM cloudtrail
WHERE "timestamp" BETWEEN ? AND ?
  AND from_iso8601_timestamp(eventtime)
      BETWEEN from_iso8601_timestamp(?) AND from_iso8601_timestamp(?)
  AND eventsource = 's3.amazonaws.com'
  AND json_extract_scalar(requestparameters, '$.bucketName') = ?
ORDER BY event_time
LIMIT 10000
