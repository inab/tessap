import logging
from typing import (
    Any,
    Sequence,
)

logger: logging.Logger
LEVEL: int
PREFIX: str
PREFIX_MPROC: str
COLOURED: bool
TIME_FORMAT: str

class LogFormatter(logging.Formatter):
    PREFIX = PREFIX
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def format(self, record: logging.LogRecord) -> str: ...

def debug(s: str, inst: Any | None = None) -> None: ...
def is_logging_configured() -> bool: ...
def config_logging(
    level: int = ...,
    prefix: str = ...,
    other_loggers: Sequence[logging.Logger] | None = None,
) -> None: ...
