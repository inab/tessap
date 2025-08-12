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
import importlib
import inspect
import logging

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse

    from typing import (
        Any,
        Callable,
        Dict,
        IO,
        Iterator,
        List,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Type,
    )

    import tes

    from ..file_server import AbstractFileServerForTES

from ..misc.common_discovery import implemented_classes_in_module


class AbstractSubcommand(abc.ABC):
    def __init__(
        self,
        docker_cmd: "str",
        tes_client: "tes.HTTPClient",
        input_file_service: "AbstractFileServerForTES",
        output_file_service: "AbstractFileServerForTES",
        tes_service_supports_dirs: "bool" = True,
    ):
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        self.tes_cli = tes_client
        self.input_file_service = input_file_service
        self.output_file_service = output_file_service
        self.same_file_service = input_file_service == output_file_service
        self.tes_service_supports_dirs_for_input = (
            tes_service_supports_dirs and input_file_service.supports_dirs
        )
        self.tes_service_supports_dirs_for_output = (
            tes_service_supports_dirs and output_file_service.supports_dirs
        )

    @classmethod
    @abc.abstractmethod
    def SUBCOMMAND(cls) -> "str":
        pass

    @classmethod
    @abc.abstractmethod
    def PopulateArgsParser(cls, sp: "argparse.ArgumentParser") -> "None":
        pass

    @abc.abstractmethod
    def subcommand(
        self,
        args: "argparse.Namespace",
        unknown: "Sequence[str]",
    ) -> "int":
        pass


def _ImplementedSubcommands(
    the_module_name: "str" = __name__,
    logger: "Optional[logging.Logger]" = None,
) -> "Sequence[Type[AbstractSubcommand]]":
    try:
        the_module = importlib.import_module(the_module_name)
        return implemented_classes_in_module(the_module, AbstractSubcommand, logger=logger)  # type: ignore[type-abstract]
    except Exception as e:
        if logger is None:
            logger = logging.getLogger(__name__)
        errmsg = f"Unable to import module {the_module_name} in order to gather implemented subcommands, due errors:"
        logger.exception(errmsg)
        raise Exception(errmsg) from e


SUBCOMMAND_CLASSES: "Sequence[Type[AbstractSubcommand]]" = _ImplementedSubcommands()
