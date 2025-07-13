from dagster import Definitions
from dagster_code.fine_tune_ops import model_retraining_job

defs = Definitions(
    jobs=[model_retraining_job]
)
