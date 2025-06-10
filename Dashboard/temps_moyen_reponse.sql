SELECT
  $__timeGroup(window_start, '60s') AS time,
  AVG(duration_ms)                   AS rtt_ms
FROM flow_aggregates
GROUP BY 1
ORDER BY 1