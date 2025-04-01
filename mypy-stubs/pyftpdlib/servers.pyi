from .ioloop import Acceptor, _IOLoop
from .handlers import FTPHandler

import socket
from typing import (
    Any,
    MutableSequence,
    Tuple,
    Type,
)

__all__ = ["FTPServer", "ThreadedFTPServer", "MultiprocessFTPServer"]

class FTPServer(Acceptor):  # type: ignore[misc]
    max_cons: int
    max_cons_per_ip: int
    handler: FTPHandler
    backlog: int
    ip_map: MutableSequence[str]
    def __init__(
        self,
        address_or_socket: Tuple[str, int] | socket.socket,
        handler: Type[FTPHandler],
        ioloop: _IOLoop | None = None,
        backlog: int = 100,
    ) -> None: ...
    def __enter__(self) -> FTPServer: ...
    def __exit__(self, *args: Any) -> None: ...
    @property
    def address(self) -> Tuple[str, int]: ...
    def serve_forever(
        self,
        timeout: float | None = None,
        blocking: bool = True,
        handle_exit: bool = True,
        worker_processes: int = 1,
    ) -> None: ...
    def handle_accepted(self, sock: socket.socket, addr: Tuple[str, int]) -> None: ...
    def handle_error(self) -> None: ...
    def close_all(self) -> bool: ...

class _SpawnerBase(FTPServer):  # type: ignore[misc]
    join_timeout: int
    refresh_interval: int
    def __init__(
        self,
        address_or_socket: Tuple[str, int] | socket.socket,
        handler: Type[FTPHandler],
        ioloop: _IOLoop | None = None,
        backlog: int = 100,
    ) -> None: ...
    def handle_accepted(self, sock: socket.socket, addr: Tuple[str, int]) -> None: ...
    # Had to tweak it "a bit"
    def serve_forever(self, timeout: float = 1.0, blocking: bool = True, handle_exit: bool = True) -> None: ...  # type: ignore[override]
    def close_all(self) -> None: ...  # type: ignore[override]

class ThreadedFTPServer(_SpawnerBase):  # type: ignore[misc]
    poll_timeout: float

class MultiprocessFTPServer(_SpawnerBase): ...  # type: ignore[misc]
