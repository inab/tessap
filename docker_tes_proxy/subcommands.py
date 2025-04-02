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

import io
import os
import sys

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import argparse
    import logging

    from typing import (
        Any,
        Callable,
        Dict,
        IO,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
    )

    from typing_extensions import (
        Final,
        TypeAlias,
    )

    SubcommandProc: TypeAlias = Callable[
        [
            logging.Logger,
            str,
            argparse.Namespace,
            Sequence[str],
        ],
        int,
    ]


import tes

DEFAULT_DEBUG_HOST: "Final[str]" = "http://localhost:8000"


def subcommand_run(
    logger: "logging.Logger",
    docker_cmd: "str",
    args: "argparse.Namespace",
    unknown: "Sequence[str]",
) -> "int":
    # This shim cannot work without command-line args
    if len(args.CMDARGS) == 0:
        return 125

    logger.debug(f"args {args}")
    logger.debug(f"unk {unknown}")

    host = (
        args.host[0]
        if isinstance(args.host, list) and len(args.host)
        else DEFAULT_DEBUG_HOST
    )
    try:
        cli = tes.HTTPClient(host, timeout=5)
    except:
        return 125

    task_env: "Optional[Dict[Any, Any]]" = None
    if isinstance(args.env, list) or isinstance(args.env_file, list):
        task_env = dict()
        env_files: "MutableSequence[IO[str]]" = []
        # Queuing files
        if isinstance(args.env_file, list):
            for env_file in args.env_file:
                oeF = open(env_file, mode="r", encoding="utf-8")
                env_files.append(oeF)

        if isinstance(args.env, list):
            env_files.append(io.StringIO("\n".join(args.env)))

        for eF in env_files:
            try:
                for env_line in eF:
                    if env_line.startswith("#"):
                        continue
                    # Remove the end of the line
                    env_line = env_line.rstrip("\n")
                    # Now, detect the equals
                    equal_pos = env_line.find("=")
                    if equal_pos == 0:
                        continue
                    elif equal_pos == -1:
                        task_env[env_line] = os.environ.get(env_line, "")
                    else:
                        task_env[env_line[0:equal_pos]] = env_line[equal_pos + 1 :]
            finally:
                eF.close()

    # Define task
    task = tes.Task(
        executors=[
            tes.Executor(
                image=args.IMAGE,
                command=args.CMDARGS,
                env=task_env,
            )
        ]
    )

    if args.interactive:
        logger.debug(
            "--interactive cannot be honoured as there is no STDIN streaming communication in GA4GH TES"
        )

    # Register the task id
    if args.cidfile:
        try:
            cF = open(args.cidfile, mode="w", encoding="utf-8")
        except Exception as e:
            logger.error(
                f"docker: failed to create the container ID file: open {args.cidfile}: {e}."
            )
            return 126
    else:
        cF = None

    # Create and run task
    try:
        task_resp_id = cli.create_task(task)
    except:
        return 126

    retval = 0
    if cF is not None:
        try:
            cF.write(task_resp_id)
        except Exception as e:
            logger.error(
                f"docker: failed to write the container ID file {args.cidfile}: {e}."
            )
            retval = 126
        finally:
            cF.close()

    if args.detach:
        return retval

    timeout = None
    w_task = cli.wait(task_resp_id, timeout=timeout)

    logger.debug(w_task)

    task_info = cli.get_task(task_resp_id, view="FULL" if args.tty else "BASIC")

    retval = 126
    if isinstance(task_info.logs, list) and len(task_info.logs) > 0:
        task_log = task_info.logs[-1]
        if isinstance(task_log.logs, list) and len(task_log.logs) > 0:
            exec_log = task_log.logs[-1]

            if exec_log.exit_code is not None:
                retval = exec_log.exit_code
            if args.tty:
                if exec_log.stdout is not None:
                    sys.stdout.write(exec_log.stdout)
                if exec_log.stderr is not None:
                    sys.stderr.write(exec_log.stderr)

    logger.debug(task_info)
    # j = json.loads(task_info.as_json())
    # print(j)

    if args.rm:
        logger.debug(
            "--rm cannot be honoured, as there is no standard way to remove the task from the list of already completed tasks in GA4GH TES"
        )

    return retval


SUBCOMMAND_ROUTER: "Mapping[str, SubcommandProc]" = {
    "run": subcommand_run,
}
