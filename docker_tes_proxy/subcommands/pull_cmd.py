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
import io
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

    from ..file_server import (
        AbstractFileServerForTES,
    )

from . import AbstractSubcommand

import tes


class PullSubcommand(AbstractSubcommand):
    """
    docker pull can be minimally emulated through the execution of
    a minimal task which validates it is fetchable.
    """

    @classmethod
    def SUBCOMMAND(cls) -> "str":
        return "pull"

    @classmethod
    def PopulateArgsParser(cls, sp: "argparse.ArgumentParser") -> "None":
        # pull parameters
        sp.add_argument(
            "-a",
            "--all-tags",
            action="store_true",
            help="Download all tagged images in the repository",
        )

        sp.add_argument(
            "--disable-content-trust",
            action="store_true",
            help="Skip image verification (default true)",
        )

        sp.add_argument(
            "--platform",
            metavar="string",
            help="Set platform if server is multi-platform capable",
        )

        sp.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Suppress verbose output",
        )

        sp.add_argument(
            "tag",
            metavar="NAME[:TAG|@DIGEST]",
            help="Docker image tag",
        )

    def subcommand(
        self,
        args: "argparse.Namespace",
        unknown: "Sequence[str]",
    ) -> "int":
        if args.all_tags:
            self.logger.debug(
                "--all-tags cannot be honoured, as is cannot be emulated in GA4GH TES"
            )

        if args.disable_content_trust:
            self.logger.debug(
                "--disable-content-trust cannot be honoured, as is cannot be emulated in GA4GH TES"
            )

        if args.platform is not None:
            self.logger.debug(
                f"--platform {args.platform} cannot be honoured, as is cannot be emulated in GA4GH TES"
            )

        # Define task
        task = tes.Task(
            executors=[
                tes.Executor(
                    image=args.tag,
                    command=["ls"],
                )
            ],
        )

        # Create and run task
        try:
            task_resp_id = self.tes_cli.create_task(task)
        except Exception as e:
            self.logger.exception(f"Could not create task")
            return 1

        retval = 1
        w_task = self.tes_cli.wait(task_resp_id)

        if w_task.state != "COMPLETE":
            print(
                f"Error response from daemon: pull access denied for {args.tag}, repository does not exist or may require 'docker login': denied: requested access to the resource is denied",
                file=sys.stderr,
            )
        else:
            retval = 0

        self.logger.debug(w_task)

        # task_info = self.tes_cli.get_task(
        #     task_resp_id, view="FULL" if args.tty or len(args.attach) > 0 else "BASIC"
        # )
        #
        # self.logger.debug(task_info)
        return retval
