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
import atexit
import datetime
import io
import json
import logging
import os
import pathlib
import re
import shutil
import stat
import sys
import tempfile

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
    "Command": "COMMAND",
    "CreatedAt": "CREATED AT",
    "ID": "CONTAINER ID",
    "Image": "IMAGE",
    "Labels": "LABELS",
    "LocalVolumes": "LOCAL VOLUMES",
    "Mounts": "MOUNTS",
    "Names": "NAMES",
    "Networks": "NETWORKS",
    "Ports": "PORTS",
    "RunningFor": "CREATED",
    "Size": "SIZE",
    "State": "STATE",
    "Status": "STATUS",
}

DEFAULT_TEMPLATE = [
    "ID",
    "Image",
    "Command",
    "RunningFor",
    "Status",
    "Ports",
    "Names",
]

JSON_TEMPLATE = [
    "Command",
    "CreatedAt",
    "ID",
    "Image",
    "Labels",
    "LocalVolumes",
    "Mounts",
    "Names",
    "Networks",
    "Ports",
    "RunningFor",
    "Size",
    "State",
    "Status",
]


class RunSubcommand(AbstractSubcommand):
    @classmethod
    def SUBCOMMAND(cls) -> "str":
        return "ps"

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
            "-f",
            "--filter",
            metavar="filter",
            help="Filter output based on conditions provided",
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
            "-n" "--last",
            metavar="int",
            type=int,
            default=-1,
            help="Show n last created containers (includes all states)",
        )

        sp.add_argument(
            "-l",
            "--latest",
            action="store_true",
            help="Show the latest created container (includes all states)",
        )

        sp.add_argument(
            "--no-trunc",
            action="store_true",
            help="Don't truncate output",
        )

        sp.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Only display container IDs",
        )

        sp.add_argument(
            "-s",
            "--size",
            action="store_true",
            help="Display total file sizes",
        )

    def subcommand(
        self,
        args: "argparse.Namespace",
        unknown: "Sequence[str]",
    ) -> "int":
        more_tasks = True
        page_token: "Optional[str]" = None

        list_all = args.all or args.latest or args.n__last != -1
        num_to_print = sys.maxsize
        if args.latest:
            num_to_print = 1
        elif args.n__last != -1:
            num_to_print = args.n__last

        template = DEFAULT_TEMPLATE
        join_char = "\t"

        format_style = args.format
        if format_style != "json" and not format_style.startswith("table"):
            # Raw format style
            format_style = "table " + format_style
            join_char = " "

        if not args.quiet and format_style.startswith("table"):
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
        while num_to_print > 0 and more_tasks:
            tasks_ans = self.tes_cli.list_tasks(view="BASIC", page_token=page_token)
            self.logger.debug(tasks_ans)

            if tasks_ans.tasks is not None:
                for task in tasks_ans.tasks:
                    if list_all or task.state == "RUNNING":
                        if args.quiet:
                            print(task.id)
                            num_to_print -= 1
                        elif task.executors is None:
                            continue
                        else:
                            for i_executor, executor in enumerate(task.executors):
                                num_to_print -= 1

                                if (
                                    isinstance(task.logs, list)
                                    and task.logs[-1].logs is not None
                                    and len(task.logs[-1].logs) > i_executor
                                ):
                                    executor_log = task.logs[-1].logs[i_executor]
                                    created_at = (
                                        executor_log.start_time.astimezone().isoformat()
                                    )
                                    running_for = (
                                        babel.dates.format_timedelta(
                                            now_ref - executor_log.start_time,
                                            locale="en_US",
                                        )
                                        + " ago"
                                    )
                                    status = (
                                        "Unknown"
                                        if task.state is None
                                        else TES2DockerState.get(
                                            task.state, task.state
                                        ).capitalize()
                                    )
                                    if executor_log.exit_code is not None:
                                        status += f" ({executor_log.exit_code})"
                                    status += (
                                        " "
                                        + babel.dates.format_timedelta(
                                            now_ref - executor_log.end_time,
                                            locale="en_US",
                                        )
                                        + " ago"
                                    )
                                else:
                                    created_at = (
                                        task.creation_time.astimezone().isoformat()
                                    )
                                    running_for = "Created"
                                    status = "Created"

                                command = " ".join(executor.command)
                                if (
                                    format_style != "json"
                                    and not args.no_trunc
                                    and len(command) > 20
                                ):
                                    command = command[0:20] + "…"
                                command = '"' + command + '"'

                                labels = ""
                                if task.tags is not None:
                                    labels = ",".join(
                                        [k + "=" + v for k, v in task.tags.items()]
                                    )

                                template_vars = {
                                    "Command": command,
                                    "CreatedAt": created_at,
                                    "ID": task.id,
                                    "Image": executor.image,
                                    "Labels": labels,
                                    "LocalVolumes": (
                                        0 if task.volumes is None else len(task.volumes)
                                    ),
                                    "Mounts": "",
                                    "Names": task.name,
                                    "Networks": "",
                                    "Ports": "",
                                    "RunningFor": running_for,
                                    "Size": "0B",
                                    "State": (
                                        "unknown"
                                        if task.state is None
                                        else TES2DockerState.get(task.state, task.state)
                                    ),
                                    "Status": status,
                                }
                                if format_style == "json":
                                    retjson = {
                                        var: template_vars[var] for var in JSON_TEMPLATE
                                    }
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
                                if num_to_print <= 0:
                                    break

                        if num_to_print <= 0:
                            break

                page_token = tasks_ans.next_page_token
                if page_token in (None, ""):
                    more_tasks = False
            else:
                more_tasks = False

        return 0
