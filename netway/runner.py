"""Container entry point with APScheduler for non-Lambda deployments."""
from __future__ import annotations

import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_once() -> None:
    from lambda_handler import handler
    result = handler({"trigger": "scheduled"}, None)
    logger.info("Scan result: %s", result)


if __name__ == "__main__":
    schedule = os.environ.get("SCHEDULE", "weekly")

    if schedule == "once":
        run_once()
    else:
        try:
            from apscheduler.schedulers.blocking import BlockingScheduler
            scheduler = BlockingScheduler()
            if schedule == "weekly":
                scheduler.add_job(run_once, "interval", weeks=1)
            elif schedule == "daily":
                scheduler.add_job(run_once, "interval", days=1)
            logger.info("Starting scheduler: %s", schedule)
            run_once()  # Run immediately on start
            scheduler.start()
        except ImportError:
            logger.warning("APScheduler not installed — running once")
            run_once()
