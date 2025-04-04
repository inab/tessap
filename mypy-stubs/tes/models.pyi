# This is needed to avoid shortcomings in the original py-tes code
# mypy: disable-error-code="arg-type, assignment"

from attr import attrib, attrs, Attribute
from attr.validators import in_, instance_of, optional
from datetime import datetime
from typing import Sequence, Any

@attrs(repr=False)
class _ListOfValidator:
    type: type = attrib()
    def __call__(
        self, inst: Any, attr: Attribute[Any], value: Sequence[Any]
    ) -> None: ...

def list_of(_type: Any) -> _ListOfValidator: ...
def strconv(value: Any) -> Any: ...
def int64conv(value: str | None) -> int | None: ...
def timestampconv(value: str | None) -> datetime | None: ...
def datetime_json_handler(x: Any) -> str: ...
@attrs
class Base:
    def as_dict(self, drop_empty: bool = True) -> dict[str, Any]: ...
    def as_json(self, drop_empty: bool = True, **kwargs: Any) -> str: ...

@attrs
class Input(Base):
    url: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    path: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    type: str = attrib(default="FILE", validator=in_(["FILE", "DIRECTORY"]))
    name: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    description: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    content: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    streamable: bool | None = attrib(
        default=None, validator=optional(instance_of(bool))
    )

@attrs
class Output(Base):
    url: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    path: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    path_prefix: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    type: str = attrib(default="FILE", validator=in_(["FILE", "DIRECTORY"]))
    name: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    description: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )

@attrs
class Resources(Base):
    cpu_cores: int | None = attrib(default=None, validator=optional(instance_of(int)))
    ram_gb: float | int | None = attrib(
        default=None, validator=optional(instance_of((float, int)))
    )
    disk_gb: float | int | None = attrib(
        default=None, validator=optional(instance_of((float, int)))
    )
    preemptible: bool | None = attrib(
        default=None, validator=optional(instance_of(bool))
    )
    zones: list[str] | None = attrib(
        default=None, converter=strconv, validator=optional(list_of(str))
    )
    backend_parameters: dict[str, str] | None = attrib(
        default=None, validator=optional(instance_of(dict))
    )
    backend_parameters_strict: bool | None = attrib(
        default=None, validator=optional(instance_of(bool))
    )

@attrs
class Executor(Base):
    image: str = attrib(converter=strconv, validator=instance_of(str))
    command: list[str] = attrib(converter=strconv, validator=list_of(str))
    ignore_error: str = attrib(
        default=None, converter=strconv, validator=optional(instance_of(bool))
    )
    workdir: str = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    stdin: str = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    stdout: str = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    stderr: str = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    env: dict[str, str] | None = attrib(
        default=None, validator=optional(instance_of(dict))
    )

@attrs
class ExecutorLog(Base):
    start_time: datetime = attrib(
        default=None, converter=timestampconv, validator=optional(instance_of(datetime))
    )
    end_time: datetime = attrib(
        default=None, converter=timestampconv, validator=optional(instance_of(datetime))
    )
    stdout: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    stderr: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    exit_code: int | None = attrib(default=None, validator=optional(instance_of(int)))

@attrs
class OutputFileLog(Base):
    url: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    path: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    size_bytes: int | None = attrib(
        default=None, converter=int64conv, validator=optional(instance_of(int))
    )

@attrs
class TaskLog(Base):
    start_time: datetime = attrib(
        default=None, converter=timestampconv, validator=optional(instance_of(datetime))
    )
    end_time: datetime = attrib(
        default=None, converter=timestampconv, validator=optional(instance_of(datetime))
    )
    metadata: dict[str, Any] | None = attrib(
        default=None, validator=optional(instance_of(dict))
    )
    logs: list[ExecutorLog] | None = attrib(
        default=None, validator=optional(list_of(ExecutorLog))
    )
    outputs: list[OutputFileLog] | None = attrib(
        default=None, validator=optional(list_of(OutputFileLog))
    )
    system_logs: list[str] | None = attrib(
        default=None, validator=optional(list_of(str))
    )

@attrs
class Task(Base):
    id: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    state: str | None = attrib(
        default=None,
        validator=optional(
            in_(
                [
                    "UNKNOWN",
                    "QUEUED",
                    "INITIALIZING",
                    "RUNNING",
                    "PAUSED",
                    "COMPLETE",
                    "EXECUTOR_ERROR",
                    "SYSTEM_ERROR",
                    "CANCELED",
                    "CANCELING",
                    "PREEMPTED",
                ]
            )
        ),
    )
    name: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    description: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    inputs: list[Input] | None = attrib(
        default=None, validator=optional(list_of(Input))
    )
    outputs: list[Output] | None = attrib(
        default=None, validator=optional(list_of(Output))
    )
    resources: Resources | None = attrib(
        default=None, validator=optional(instance_of(Resources))
    )
    executors: list[Executor] | None = attrib(
        default=None, validator=optional(list_of(Executor))
    )
    volumes: list[str] | None = attrib(default=None, validator=optional(list_of(str)))
    tags: dict[str, str] | None = attrib(
        default=None, validator=optional(instance_of(dict))
    )
    logs: list[TaskLog] | None = attrib(
        default=None, validator=optional(list_of(TaskLog))
    )
    creation_time: datetime = attrib(
        default=None, converter=timestampconv, validator=optional(instance_of(datetime))
    )
    def is_valid(self) -> tuple[bool, None | TypeError]: ...

@attrs
class GetTaskRequest(Base):
    id: str = attrib(converter=strconv, validator=instance_of(str))
    view: str | None = attrib(
        default=None, validator=optional(in_(["MINIMAL", "BASIC", "FULL"]))
    )

@attrs
class CreateTaskResponse(Base):
    id: str = attrib(converter=strconv, validator=instance_of(str))

@attrs
class ServiceInfoRequest(Base): ...

@attrs
class Organization:
    name: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    url: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )

@attrs
class Type:
    artifact: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    group: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    version: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )

@attrs
class ServiceInfo(Base):
    contact_url: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    created_at: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    description: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    documentation_url: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    environment: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    id: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    name: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    organization: dict[str, Any] | None = attrib(
        default=None, validator=optional(instance_of(dict))
    )
    storage: list[str] | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(list))
    )
    tes_resources_backend_parameters: list[str] | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(list))
    )
    type: dict[str, Any] | None = attrib(
        default=None, validator=optional(instance_of(dict))
    )
    updated_at: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    version: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )

@attrs
class CancelTaskRequest(Base):
    id: str = attrib(converter=strconv, validator=instance_of(str))

@attrs
class CancelTaskResponse(Base): ...

@attrs
class ListTasksRequest(Base):
    project: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    name_prefix: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    page_size: int | None = attrib(default=None, validator=optional(instance_of(int)))
    page_token: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    view: str | None = attrib(
        default=None, validator=optional(in_(["MINIMAL", "BASIC", "FULL"]))
    )

@attrs
class ListTasksResponse(Base):
    tasks: list[Task] | None = attrib(default=None, validator=optional(list_of(Task)))
    next_page_token: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
