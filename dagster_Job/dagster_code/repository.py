from dagster import Definitions, ScheduleDefinition
from dagster_code.fine_tune_ops import model_retraining_job

# Schedule to run every Monday at 6:00 AM
weekly_monday_schedule = ScheduleDefinition(
    job=model_retraining_job,
    cron_schedule="0 6 * * 1",  # At 06:00 on Monday
    name="weekly_monday_retraining",
    description="Retrain the model every Monday at 6:00 AM"
)

defs = Definitions(
    jobs=[model_retraining_job],
    schedules=[weekly_monday_schedule]
)
