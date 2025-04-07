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
        Type,
    )

    from typing_extensions import (
        Final,
    )

    from ..file_server import (
        AbstractFileServerForTES,
    )

from . import AbstractSubcommand


class StopSubcommand(AbstractSubcommand):
    """
    As of GA4GH TES 1.1 tasks can be cancelled, but the signal used for
    that cannot be chosen.
    """

    @classmethod
    def SUBCOMMAND(cls) -> "str":
        return "stop"

    @classmethod
    def PopulateArgsParser(cls, sp: "argparse.ArgumentParser") -> "None":
        # stop parameters
        sp.add_argument(
            "-s",
            "--signal",
            metavar="string",
            help="Signal to send to the container",
        )

        sp.add_argument(
            "-t",
            "--time",
            metavar="int",
            type=float,
            help="Seconds to wait before killing the container",
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
        if args.signal:
            self.logger.debug(
                f"--signal {args.signal} cannot be honoured, as is cannot be emulated in GA4GH TES"
            )

        for task_id in args.CONTAINER:
            try:
                task = self.tes_cli.get_task(task_id)
                if task.state in (
                    "QUEUED",
                    "INITIALIZING",
                    "RUNNING",
                    "PAUSED",
                    "PREEMPTED",
                ):
                    if args.time is not None and args.time > 0:
                        time.sleep(args.time)
                    try:
                        self.tes_cli.cancel_task(task_id)
                        print(task_id)
                    except Exception as e:
                        retval = 1
                        self.logger.exception(f"Error while cancelling task {task_id}")
                else:
                    print(task_id)

            except Exception as e:
                if self.logger.getEffectiveLevel() <= logging.DEBUG:
                    self.logger.exception(f"Could not find task {task_id}")
                print(
                    "Error response from daemon: No such container: " + task_id,
                    file=sys.stderr,
                )
                retval = 1

        return retval
