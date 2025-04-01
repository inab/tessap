from tes.models import (
    Executor as Executor,
    ExecutorLog as ExecutorLog,
    Input as Input,
    Output as Output,
    OutputFileLog as OutputFileLog,
    Resources as Resources,
    Task as Task,
    TaskLog as TaskLog,
)
from typing import Any, Pattern

first_cap_re: Pattern[str]
all_cap_re: Pattern[str]

def camel_to_snake(name: str) -> str: ...

class UnmarshalError(Exception):
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

class TimeoutError(Exception):
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

def unmarshal(j: Any, o: type, convert_camel_case: bool = True) -> Any: ...
