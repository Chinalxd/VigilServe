"""Structured rolling logger for VigilServe Agent.

Logs are organized by date and task under the install directory:
  {INSTALL_DIR}/logs/YYYY-MM-DD/{task}.log

Old log directories older than KEEP_DAYS are automatically removed on init.
"""
import os
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path

import paths

KEEP_DAYS = 7

LOG_ROOT = Path(paths.LOG_DIR)

# the user's %LOCALAPPDATA% directory so logging never crashes on startup.
try:
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    _test_file = LOG_ROOT / ".write_test"
    _test_file.write_text("")
    _test_file.unlink()
except Exception:
    _fallback = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "VigilServe" / "Agent" / "logs"
    _fallback.mkdir(parents=True, exist_ok=True)
    LOG_ROOT = _fallback


class TaskLogFilter(logging.Filter):
    """Injects {task} record attribute for formatter."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "task"):
            record.task = "main"
        return True


def _cleanup_old_logs() -> None:
    """Remove log directories older than KEEP_DAYS."""
    if not LOG_ROOT.exists():
        return
    cutoff = datetime.now() - timedelta(days=KEEP_DAYS)
    for entry in LOG_ROOT.iterdir():
        if not entry.is_dir():
            continue
        try:
            entry_date = datetime.strptime(entry.name, "%Y-%m-%d")
            if entry_date < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
        except ValueError:
            continue


def _today_dir() -> Path:
    d = LOG_ROOT / datetime.now().strftime("%Y-%m-%d")
    d.mkdir(parents=True, exist_ok=True)
    return d


class _TaskAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {})["task"] = self.extra["task"]
        return msg, kwargs


_loggers: dict[str, logging.LoggerAdapter] = {}


def get_logger(task: str = "main") -> logging.LoggerAdapter:
    """Return a logger adapter that tags records with the given task name."""
    if task in _loggers:
        return _loggers[task]

    logger = logging.getLogger(f"VigilServeAgent.{task}")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        log_path = _today_dir() / f"{task}.log"
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] [%(levelname)s] [%(task)s] %(message)s")
        )
        handler.addFilter(TaskLogFilter())
        logger.addHandler(handler)

    adapter = _TaskAdapter(logger, {"task": task})
    _loggers[task] = adapter
    return adapter


_cleanup_old_logs()

logger = get_logger("main")
