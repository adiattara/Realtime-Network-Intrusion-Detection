#!/bin/bash
set -e

echo "Starting Spark Flow Aggregator with Java options: ${JAVA_OPTS}"

# Export Java options to be picked up by PySpark
export PYSPARK_SUBMIT_ARGS="--driver-java-options '${JAVA_OPTS}' --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.0.3,org.postgresql:postgresql:42.7.3 pyspark-shell"

echo "PYSPARK_SUBMIT_ARGS: ${PYSPARK_SUBMIT_ARGS}"

# Run the Spark application
echo "Launching Spark application..."
exec python spark_flow_aggregator.py
