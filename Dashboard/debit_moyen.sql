SELECT
  $__timeGroup(window_start, '5s') AS time,
  SUM(total_bytes)  AS mbps
FROM flow_aggregates
GROUP BY 1
ORDER BY 1