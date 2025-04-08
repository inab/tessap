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
import time

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
        Set,
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

TES2DockerState = {
    "COMPLETE": "exited",
    "EXECUTOR_ERROR": "exited",
    "SYSTEM_ERROR": "exited",
    "QUEUED": "created",
    "INITIALIZING": "up",
    "RUNNING": "up",
    "PAUSED": "paused",
}

DockerTemplateVars = {
    "Container": "CONTAINER",
    "Name": "NAME",
    "ID": "CONTAINER ID",
    "CPUPerc": "CPU %",
    "MemUsage": "MEM USAGE / LIMIT",
    "MemPerc": "MEM %",
    "NetIO": "NET I/O",
    "BlockIO": "BLOCK I/O",
    "PIDs": "PIDS",
}

DEFAULT_TEMPLATE = [
    "ID",
    "Name",
    "CPUPerc",
    "MemUsage",
    "NetIO",
    "BlockIO",
    "PIDs",
]

JSON_TEMPLATE = [
    "BlockIO",
    "CPUPerc",
    "Container",
    "ID",
    "MemPerc",
    "MemUsage",
    "Name",
    "NetIO",
    "PIDs",
]


class StatsSubcommand(AbstractSubcommand):
    """
    As of GA4GH TES 1.1 there is no equivalent to stats to
    gather live or cumulative stats from a list of submitted tasks,
    this implementation is a no-op stub.
    """

    @classmethod
    def SUBCOMMAND(cls) -> "str":
        return "stats"

    @classmethod
    def PopulateArgsParser(cls, sp: "argparse.ArgumentParser") -> "None":
        # ps parameters
        sp.add_argument(
            "-a",
            "--all",
            action="store_true",
            help="Show all containers (default shows just running)",
        )

        sp.add_argument(
            "--format",
            metavar="string",
            default="table",
            help="""\
Format output using a custom template:
'table':            Print output in table format with column headers (default)
'table TEMPLATE':   Print output in table format using the given Go template
'json':             Print in JSON format
'TEMPLATE':         Print output using the given Go template.
Refer to https://docs.docker.com/go/formatting/ for more information about formatting output with
templates""",
        )

        sp.add_argument(
            "--no-stream",
            action="store_true",
            help="Disable streaming stats and only pull the first result",
        )

        sp.add_argument(
            "--no-trunc",
            action="store_true",
            help="Don't truncate output",
        )

        sp.add_argument(
            "CONTAINER",
            nargs=argparse.REMAINDER,
            help="Container instance id(s)",
        )

    def subcommand(
        self,
        args: "argparse.Namespace",
        unknown: "Sequence[str]",
    ) -> "int":
        more_tasks = True
        page_token: "Optional[str]" = None

        list_all = args.all or (args.CONTAINER is not None and len(args.CONTAINER) > 0)
        only_these_containers: "Optional[Set[str]]" = None
        if args.CONTAINER is not None and len(args.CONTAINER) > 0:
            list_all = True
            only_these_containers = set(args.CONTAINER)
        else:
            list_all = args.all

        template = DEFAULT_TEMPLATE
        join_char = "\t"

        format_style = args.format
        if format_style != "json" and not format_style.startswith("table"):
            # Raw format style
            format_style = "table " + format_style
            join_char = " "

        if format_style.startswith("table"):
            format_style_remainder = format_style[6:].strip()
            if len(format_style_remainder) > 0:
                template = []
                for token in format_style_remainder.split():
                    matched = re.match(r"^\{\{\.([^}]+)\}\}", token)
                    if matched is not None:
                        if matched[1] in DockerTemplateVars:
                            template.append(matched[1])
                        else:
                            template.append(token)
                    else:
                        template.append(token)
            # No header for raw format
            if args.format.startswith("table"):
                print(
                    join_char.join(
                        map(lambda t: DockerTemplateVars.get(t, t), template)
                    )
                )

        now_ref = datetime.datetime.now().astimezone()
        while True:
            tasks_ans = self.tes_cli.list_tasks(view="BASIC", page_token=page_token)
            self.logger.debug(tasks_ans)

            if tasks_ans.tasks is not None:
                for task in tasks_ans.tasks:
                    if task.executors is None:
                        continue

                    if task.state != "RUNNING" and (
                        not list_all
                        or (
                            only_these_containers is not None
                            and task.id not in only_these_containers
                        )
                    ):
                        continue

                    for i_executor, executor in enumerate(task.executors):
                        template_vars = {
                            "Container": task.id,
                            "Name": task.name,
                            "ID": task.id,
                            "CPUPerc": "100%" if task.state == "RUNNING" else "0.00%",
                            "MemUsage": "0B /0B",
                            "MemPerc": "0.00%",
                            "NetIO": "0B / 0B",
                            "BlockIO": "0B / 0B",
                            "PIDs": 1 if task.state == "RUNNING" else 0,
                        }
                        if format_style == "json":
                            retjson = {var: template_vars[var] for var in JSON_TEMPLATE}
                            json.dump(retjson, sys.stdout)
                            print()
                        else:
                            print(
                                join_char.join(
                                    map(
                                        lambda t: str(template_vars.get(t, t)),
                                        template,
                                    )
                                )
                            )
                if args.no_stream:
                    break

                time.sleep(1)
            else:
                break

        return 0
