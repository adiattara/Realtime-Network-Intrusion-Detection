import os
import logging
from dotenv import load_dotenv
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, least, greatest, when, sum, count, min, max, expr,
    window, concat_ws, lit, unix_timestamp
)
from pyspark.sql.types import StructType, StructField, StringType, IntegerType, BooleanType, DoubleType

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SparkFlowAggregator")

# Dépendance Kafka
# CORRECTION : Ajout du driver PostgreSQL aux packages
# Note: PYSPARK_SUBMIT_ARGS is now set in entrypoint.sh with additional JVM options

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

# Get environment variables
kafka_bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
kafka_input_topic = os.environ.get("KAFKA_TOPIC", "raw-packets")
kafka_output_topic = os.environ.get("KAFKA_OUTPUT_TOPIC", "aggregated-flows")

logger.info(f"Using Kafka bootstrap servers: {kafka_bootstrap_servers}")
logger.info(f"Reading from Kafka topic: {kafka_input_topic}")
logger.info(f"Writing to Kafka topic: {kafka_output_topic}")

# Session Spark
spark = SparkSession.builder \
    .appName("NetworkFlowAggregator") \
    .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.0.3,org.postgresql:postgresql:42.7.3") \
    .getOrCreate()
spark.sparkContext.setLogLevel("WARN")

# Lecture Kafka
raw_df = spark.readStream.format("kafka") \
    .option("kafka.bootstrap.servers", kafka_bootstrap_servers) \
    .option("subscribe", kafka_input_topic) \
    .option("startingOffsets", "latest") \
    .option("failOnDataLoss", "false")\
    .load()

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

# Configuration de la connexion PostgreSQL
database_url = os.environ.get("DATABASE_URL", "postgresql://nfuser:nfpass@localhost:5432/postgres")
# Parse the DATABASE_URL to extract components
db_parts = database_url.replace("postgresql://", "").split("@")
user_pass = db_parts[0].split(":")
host_port_db = db_parts[1].split("/")
host_port = host_port_db[0].split(":")

jdbc_url = f"jdbc:postgresql://{host_port[0]}:{host_port[1]}/{host_port_db[1]}"
connection_properties = {
    "user": user_pass[0],
    "password": user_pass[1],
    "driver": "org.postgresql.Driver"
}

logger.info(f"Using PostgreSQL connection: {jdbc_url}")
logger.info(f"PostgreSQL user: {user_pass[0]}")

def write_to_postgres(batch_df, batch_id):
    try:
        # Log the number of records being written
        count = batch_df.count()
        logger.info(f"Writing {count} records to PostgreSQL table flow_aggregates (batch ID: {batch_id})")

        if count > 0:
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
            logger.info(f"Successfully wrote {count} records to PostgreSQL")
        else:
            logger.info("Batch is empty, skipping write to PostgreSQL")
    except Exception as e:
        logger.error(f"Error writing to PostgreSQL: {str(e)}")
        # Continue processing despite errors
        pass

# Écriture vers PostgreSQL
logger.info("Starting PostgreSQL output stream")
query = agg_df.writeStream \
    .outputMode("append") \
    .trigger(processingTime="1 minute") \
    .option("checkpointLocation", "/tmp/checkpoint_networkflow_pg") \
    .foreachBatch(write_to_postgres) \
    .start()
logger.info("PostgreSQL output stream started")

# Écriture vers Kafka
kafka_query = (agg_df
    .selectExpr("to_json(struct(*)) AS value")
    .writeStream
    .format("kafka")
    .option("kafka.bootstrap.servers", kafka_bootstrap_servers)
    .option("topic", kafka_output_topic)
    .option("checkpointLocation", "chk_kafka")
    .trigger(processingTime="1 minute")
    .outputMode("append")
    .start()
)

logger.info(f"Started Kafka output stream to topic: {kafka_output_topic}")

# Attendre la terminaison des streams
logger.info("All streams started, waiting for termination...")
try:
    spark.streams.awaitAnyTermination()
except KeyboardInterrupt:
    logger.info("Received interrupt, stopping streams")
finally:
    logger.info("Streams terminated")
