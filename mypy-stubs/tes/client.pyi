import requests
from attr import attrib, attrs
from attr.validators import instance_of, optional
from tes.models import (
    CancelTaskRequest as CancelTaskRequest,
    CreateTaskResponse as CreateTaskResponse,
    GetTaskRequest as GetTaskRequest,
    ListTasksRequest as ListTasksRequest,
    ListTasksResponse as ListTasksResponse,
    ServiceInfo as ServiceInfo,
    Task as Task,
    strconv as strconv,
)
from tes.utils import TimeoutError as TimeoutError, unmarshal as unmarshal
from typing import Any

def append_suffixes_to_url(urls: list[str], suffixes: list[str]) -> list[str]: ...
def send_request(
    paths: list[str],
    method: str = "get",
    kwargs_requests: dict[str, Any] | None = None,
    **kwargs: Any
) -> requests.Response: ...
def process_url(value: str) -> str: ...
@attrs
class HTTPClient:
    url: str = attrib(converter=process_url, validator=instance_of(str))
    timeout: int = attrib(default=10, validator=instance_of(int))
    user: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    password: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    token: str | None = attrib(
        default=None, converter=strconv, validator=optional(instance_of(str))
    )
    urls: list[str] = ...
    def __attrs_post_init__(self) -> None: ...
    def get_service_info(self) -> ServiceInfo: ...
    def create_task(self, task: Task) -> CreateTaskResponse: ...
    def get_task(self, task_id: str, view: str = "BASIC") -> Task: ...
    def cancel_task(self, task_id: str) -> None: ...
    def list_tasks(
        self,
        view: str = "MINIMAL",
        page_size: int | None = None,
        page_token: str | None = None,
    ) -> ListTasksResponse: ...
    def wait(self, task_id: str, timeout: int | None = None) -> Task: ...
