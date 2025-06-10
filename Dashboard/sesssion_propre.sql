SELECT
  100.0 * SUM(CASE WHEN attack = FALSE THEN 1 ELSE 0 END)
    / NULLIF(COUNT(*), 0)                     AS clean_pct
FROM flow_aggregates
WHERE window_start >= NOW() - INTERVAL '30 minutes'
