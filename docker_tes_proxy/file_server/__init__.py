#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Barcelona Supercomputing Center (BSC), Spain
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc
import inspect
import logging

from typing import (
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    import os

    from typing import (
        Optional,
        Union,
    )


class AbstractFileServerForTES(abc.ABC):
    def __init__(
        self,
        public_name: "str" = "localhost",
        public_port: "Optional[int]" = None,
        listen_ip: "str" = "::",
        listen_port: "int" = 2121,
    ):
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.public_name = public_name
        self.public_port = listen_port if public_port is None else public_port

    @property
    @abc.abstractmethod
    def supports_dirs(self) -> "bool":
        pass

    @abc.abstractmethod
    def add_ro_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        pass

    @abc.abstractmethod
    def add_rw_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        pass

    @abc.abstractmethod
    def add_wo_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        pass

    @abc.abstractmethod
    def synchronize(self) -> "None":
        pass

    @abc.abstractmethod
    def daemonize(self, log_file: "str" = "/dev/null") -> "bool":
        pass

    @abc.abstractmethod
    def kill_daemon(self) -> "bool":
        pass
