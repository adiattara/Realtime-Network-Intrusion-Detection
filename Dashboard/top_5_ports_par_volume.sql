SELECT
  dport::text AS port,
  SUM(total_bytes) AS bytes_total
FROM flow_aggregates
WHERE $__timeFilter(window_start)
GROUP BY dport
ORDER BY bytes_total DESC
LIMIT 5