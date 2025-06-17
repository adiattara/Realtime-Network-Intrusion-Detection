import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, least, greatest, when, sum, count, min, max, expr,
    window, concat_ws, lit, unix_timestamp
)
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, BooleanType, DoubleType

# Dépendance Kafka

# CORRECTION : Ajout du driver PostgreSQL aux packages
os.environ["PYSPARK_SUBMIT_ARGS"] = "--packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.0.3,org.postgresql:postgresql:42.7.3 pyspark-shell"
# Schéma JSON
schema = StructType([
    StructField("timestamp", DoubleType()),
    StructField("src_ip", StringType()),
    StructField("dst_ip", StringType()),
    StructField("proto", IntegerType()),
    StructField("sport", IntegerType()),
    StructField("dport", IntegerType()),
    StructField("flags", IntegerType()),
    StructField("payload_len", IntegerType()),
    StructField("attack", BooleanType())
])

# Session Spark
spark = SparkSession.builder \
    .appName("NetworkFlowAggregator") \
    .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.0.3,org.postgresql:postgresql:42.7.3") \
    .getOrCreate()
spark.sparkContext.setLogLevel("WARN")


raw_df = spark.readStream.format("kafka") \
    .option("kafka.bootstrap.servers", "pkc-p11xm.us-east-1.aws.confluent.cloud:9092") \
    .option("subscribe", "raw-packets") \
    .option("kafka.security.protocol", "SASL_SSL") \
    .option("kafka.sasl.mechanism", "PLAIN") \
    .option("kafka.sasl.jaas.config",
        'org.apache.kafka.common.security.plain.PlainLoginModule required username="MRZSJLNDLOTJQFN4" password="QP9p0PYrfSsXK+RNhhDBcNegcBpQeAbrsr664O+Lj1qMMScjtV2fn/sovW3fdRsx";') \
    .option("startingOffsets", "latest") \
    .option("failOnDataLoss", "false") \
    .load()

# Lecture Kafka
# raw_df = spark.readStream.format("kafka") \
#     .option("kafka.bootstrap.servers", "localhost:29092") \
#     .option("subscribe", "raw-packets") \
#     .option("startingOffsets", "latest") \
#     .option("failOnDataLoss", "false")\
#     .load()

# Parsing JSON
json_df = raw_df.selectExpr("CAST(value AS STRING) as json_str") \
    .select(from_json(col("json_str"), schema).alias("data")) \
    .select("data.*")

# Enrichissement
df = json_df \
    .withColumn("timestamp", col("timestamp").cast("timestamp")) \
    .withColumn("ip_min", least(col("src_ip"), col("dst_ip"))) \
    .withColumn("ip_max", greatest(col("src_ip"), col("dst_ip"))) \
    .withColumn("port_min", least(col("sport"), col("dport"))) \
    .withColumn("port_max", greatest(col("sport"), col("dport"))) \
    .withColumn("proto_str", when(col("proto") == 6, "TCP")
                              .when(col("proto") == 17, "UDP")
                              .otherwise("OTHER")) \
    .withColumn("flow_key", concat_ws("",
        col("ip_min"), lit(":"), col("port_min").cast("string"),
        lit("-"), col("ip_max"), lit(":"), col("port_max").cast("string"),
        lit("-"), col("proto_str")
    ))

# Agrégation avec watermark de 1 seconde et fenêtre de 1 minute
windowed = df \
    .withWatermark("timestamp", "1 second") \
    .groupBy(
        window(col("timestamp"), "1 minute"),
        col("flow_key")
    ).agg(
        min("timestamp").alias("start_ts"),
        max("timestamp").alias("end_ts"),
        sum("payload_len").alias("total_bytes"),
        count("*").alias("pkt_count"),
        sum(when(expr("flags & 8 != 0"), 1).otherwise(0)).alias("psh_count"),
        sum(when(expr("flags & 32 != 0"), 1).otherwise(0)).alias("urg_count"),
        sum(when(col("src_ip") == col("ip_min"), col("payload_len")).otherwise(0)).alias("fwd_bytes"),
        sum(when(col("src_ip") != col("ip_min"), col("payload_len")).otherwise(0)).alias("bwd_bytes"),
        sum(when(col("src_ip") == col("ip_min"), 1).otherwise(0)).alias("fwd_pkts"),
        sum(when(col("src_ip") != col("ip_min"), 1).otherwise(0)).alias("bwd_pkts"),
        max("dport").alias("dport"),
        max("attack").alias("attack")
    )

# Calculs + fix struct window
agg_df = windowed \
    .withColumn("duration_ms", expr("(CAST(end_ts AS DOUBLE) - CAST(start_ts AS DOUBLE)) * 1000")) \
    .withColumn("flow_pkts_per_s", col("pkt_count") / (col("duration_ms") / 1000 + lit(1))) \
    .withColumn("fwd_bwd_ratio", expr("(fwd_bytes + 1) / (bwd_bytes + 1)")) \
    .filter(col("pkt_count") >= 5) \
    .filter((col("duration_ms") >= 0) & (col("total_bytes") > 0)) \
    .withColumn("window_start", col("window.start")) \
    .withColumn("window_end", col("window.end")) \
    .drop("window")

# Écriture vers un CSV coalescé, uniquement si le batch n'est pas vide
# query = agg_df.writeStream \
#     .outputMode("append") \
#     .trigger(processingTime="1 minute") \
#     .option("checkpointLocation", "/tmp/checkpoint_networkflow") \
#     .foreachBatch(lambda df, _: df.coalesce(1)
#         .write.mode("append")
#         .option("header", True)
#         .csv("output/normal")
#     ).start()

jdbc_url = "jdbc:postgresql://database-1.c1a68y6y81zu.eu-north-1.rds.amazonaws.com:5432/postgres"
connection_properties = {
    "user": "postgres",
    "password": "postgres_password",
    "driver": "org.postgresql.Driver"
}

def write_to_postgres(batch_df, batch_id):
    (
        batch_df
        .write
        .jdbc(
            url=jdbc_url,
            table="flow_aggregates",
            mode="append",
            properties=connection_properties
        )
    )

query = agg_df.writeStream \
    .outputMode("append") \
    .trigger(processingTime="1 minute") \
    .option("checkpointLocation", "/tmp/checkpoint_networkflow_pg") \
    .foreachBatch(write_to_postgres) \
    .start()

# kafka_query = (agg_df
#     .selectExpr("to_json(struct(*)) AS value")
#     .writeStream
#     .format("kafka")
#     .option("kafka.bootstrap.servers","localhost:29092")
#     .option("topic","aggregated-flows")
#     .option("checkpointLocation","chk_kafka")
#     .trigger(processingTime="1 minute")
#     .outputMode("append")
#     .start()
# )

kafka_query = (agg_df
    .selectExpr("to_json(struct(*)) AS value")
    .writeStream
    .format("kafka")
    .option("kafka.bootstrap.servers", "pkc-p11xm.us-east-1.aws.confluent.cloud:9092") \
    .option("kafka.security.protocol", "SASL_SSL") \
    .option("kafka.sasl.mechanism", "PLAIN") \
    .option("kafka.sasl.jaas.config",
        'org.apache.kafka.common.security.plain.PlainLoginModule required username="MRZSJLNDLOTJQFN4" password="QP9p0PYrfSsXK+RNhhDBcNegcBpQeAbrsr664O+Lj1qMMScjtV2fn/sovW3fdRsx";') \
    .option("topic", "aggregated-flows")
    .option("checkpointLocation","chk_kafka")
    .trigger(processingTime="1 minute")
    .outputMode("append")
    .start()
)


spark.streams.awaitAnyTermination()
