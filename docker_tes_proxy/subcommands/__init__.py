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
import pkgutil

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse

    from types import (
        ModuleType,
    )

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


class AbstractSubcommand(abc.ABC):
    def __init__(
        self,
        docker_cmd: "str",
        tes_client: "tes.HTTPClient",
        file_server: "AbstractFileServerForTES",
        tes_service_supports_dirs: "bool" = True,
    ):
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        self.tes_cli = tes_client
        self.file_server = file_server
        self.tes_service_supports_dirs = (
            tes_service_supports_dirs and file_server.supports_dirs
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
        return _ImplementedSubcommandsInModule(the_module, logger=logger)
    except Exception as e:
        if logger is None:
            logger = logging.getLogger(__name__)
        errmsg = f"Unable to import module {the_module_name} in order to gather implemented subcommands, due errors:"
        logger.exception(errmsg)
        raise Exception(errmsg) from e


def _iter_namespace(ns_pkg: "ModuleType") -> "Iterator[pkgutil.ModuleInfo]":
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


def _ImplementedSubcommandsInModule(
    the_module: "ModuleType",
    logger: "Optional[logging.Logger]" = None,
) -> "Sequence[Type[AbstractSubcommand]]":
    subcommands: "MutableSequence[Type[AbstractSubcommand]]" = []

    for finder, module_name, ispkg in _iter_namespace(the_module):
        try:
            named_module = importlib.import_module(module_name)
        except:
            if logger is None:
                logger = logging.getLogger(__name__)
            logger.exception(
                f"Skipping module {module_name} in order to gather implemented subcommands, due errors:"
            )
            continue

        for name, obj in inspect.getmembers(named_module):
            if (
                inspect.isclass(obj)
                and not inspect.isabstract(obj)
                and issubclass(obj, AbstractSubcommand)
            ):
                subcommands.append(obj)

    return subcommands


SUBCOMMAND_CLASSES: "Sequence[Type[AbstractSubcommand]]" = _ImplementedSubcommands()
