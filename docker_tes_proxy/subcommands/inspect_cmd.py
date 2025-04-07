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

import argparse
import datetime
import json
import logging
import os
import re
import sys

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        Dict,
        IO,
        List,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Type,
    )

    from typing_extensions import (
        Final,
    )

    from ..file_server import (
        AbstractFileServerForTES,
    )

from . import AbstractSubcommand

import tes

import babel.dates

from ..dxf_helper import DockerRegistryHelper


class InspectSubcommand(AbstractSubcommand):
    @classmethod
    def SUBCOMMAND(cls) -> "str":
        return "inspect"

    @classmethod
    def PopulateArgsParser(cls, sp: "argparse.ArgumentParser") -> "None":
        # inspect parameters
        sp.add_argument(
            "-f",
            "--format",
            metavar="string",
            default="table",
            help="""\
Format output using a custom template:
'json':             Print in JSON format
'TEMPLATE':         Print output using the given Go template.
Refer to https://docs.docker.com/go/formatting/ for more information about formatting output with
templates""",
        )

        sp.add_argument(
            "-s",
            "--size",
            action="store_true",
            help="Display total file sizes if the type is container",
        )

        sp.add_argument(
            "--type",
            metavar="string",
            help="Return JSON for specified type",
        )

        sp.add_argument(
            "tags",
            metavar="NAME|ID",
            nargs="+",
            help="Docker image tag",
        )

    def subcommand(
        self,
        args: "argparse.Namespace",
        unknown: "Sequence[str]",
    ) -> "int":
        if args.format:
            self.logger.debug(
                f"--format {args.format} cannot be honoured, as it cannot be emulated in GA4GH TES"
            )

        if args.size:
            self.logger.debug(
                f"--size cannot be honoured, as it cannot be emulated in GA4GH TES"
            )

        if args.type:
            self.logger.debug(
                f"--type {args.type} cannot be honoured, as it cannot be emulated in GA4GH TES"
            )

        drh = DockerRegistryHelper()

        retinspect = []
        retval = 0
        for tag in args.tags:
            try:
                inspect_tag, inspect_payload = drh.query_inspect(tag)
                retinspect.append(inspect_payload)
            except Exception as e:
                if self.logger.getEffectiveLevel() <= logging.DEBUG:
                    self.logger.exception(f"Error inspecting {tag}")
                print(f"Error: No such object: {tag}", file=sys.stderr)
                retval = 1

        json.dump(retinspect, sys.stdout, indent=4)
        print()

        return retval
