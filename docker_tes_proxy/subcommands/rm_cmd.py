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

    import tes

from . import AbstractSubcommand


class RmSubcommand(AbstractSubcommand):
    """
    As of GA4GH TES 1.1 there is no equivalent to docker rm to
    clean up the list of submitted tasks, this implementation is a
    no-op stub (but for the -f flag).
    """

    @classmethod
    def SUBCOMMAND(cls) -> "str":
        return "rm"

    @classmethod
    def PopulateArgsParser(cls, sp: "argparse.ArgumentParser") -> "None":
        # rm parameters
        sp.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="Force the removal of a running container",
        )

        sp.add_argument(
            "-l",
            "--link",
            action="store_true",
            help="Remove the specified link",
        )

        sp.add_argument(
            "-v",
            "--volumes",
            action="store_true",
            help="Remove anonymous volumes associated with the container",
        )

        sp.add_argument(
            "CONTAINER",
            nargs="+",
            help="Container instance id(s)",
        )

    def subcommand(
        self,
        args: "argparse.Namespace",
        unknown: "Sequence[str]",
    ) -> "int":
        retval = 0
        if args.link:
            self.logger.debug(
                f"--link cannot be honoured, as is cannot be emulated in GA4GH TES"
            )

        if args.volumes:
            self.logger.debug(
                f"--volumes cannot be honoured, as is cannot be emulated in GA4GH TES"
            )

        if args.force:
            self.logger.debug(f"--force is only partially emulated in GA4GH TES")

        for task_id in args.CONTAINER:
            real_task_id = task_id
            the_task: "Optional[tes.Task]" = None
            try:
                the_task = self.tes_cli.get_task(task_id)
            except Exception as e:
                if self.logger.getEffectiveLevel() <= logging.DEBUG:
                    self.logger.exception(f"Could not find task {task_id}")

            if the_task is None:
                # Searching by task name
                more_tasks = True
                page_token: "Optional[str]" = None
                while more_tasks:
                    tasks_ans = self.tes_cli.list_tasks(
                        view="BASIC", page_token=page_token
                    )
                    if tasks_ans.tasks is not None:
                        for task in tasks_ans.tasks:
                            if task.name == task_id:
                                the_task = task
                                real_task_id = task.id
                                more_tasks = False
                                break

                    page_token = tasks_ans.next_page_token
                    if page_token in (None, ""):
                        more_tasks = False

            if the_task is None:
                if self.logger.getEffectiveLevel() <= logging.DEBUG:
                    self.logger.exception(f"Could not find task {task_id}")
                print(
                    "Error response from daemon: No such container: " + task_id,
                    file=sys.stderr,
                )
                retval = 1
            elif args.force or the_task.state in (
                "QUEUED",
                "INITIALIZING",
                "RUNNING",
                "PAUSED",
                "PREEMPTED",
            ):
                try:
                    self.tes_cli.cancel_task(task_id)
                    print(task_id)
                except Exception as e:
                    retval = 1
                    self.logger.exception(f"Error while cancelling task {task_id}")

        return retval
