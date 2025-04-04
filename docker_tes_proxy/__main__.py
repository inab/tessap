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
import json
import logging
import os
import pathlib
import re
import subprocess
import sys

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Mapping,
        MutableSequence,
        Sequence,
        Type,
        Union,
    )

    from typing_extensions import (
        NotRequired,
        TypedDict,
    )

    from .subcommands import (
        AbstractSubcommand,
    )

    class BasicLoggingConfigDict(TypedDict):
        filename: NotRequired[str]
        format: str
        level: int


from .argparse_helper import _SubParsersGroupAction
from .subcommands import SUBCOMMAND_CLASSES

LOGGING_FORMAT = "%(asctime)-15s - [%(levelname)s] %(message)s"
DEBUG_LOGGING_FORMAT = (
    "%(asctime)-15s - [%(name)s %(funcName)s %(lineno)d][%(levelname)s] %(message)s"
)

DEFAULT_DOCKER_CMD = "/usr/bin/docker"

#  run         Create and run a new container from an image
#  exec        Execute a command in a running container
#  ps          List containers
#  build       Build an image from a Dockerfile
#  pull        Download an image from a registry
#  push        Upload an image to a registry
#  images      List images
#  login       Authenticate to a registry
#  logout      Log out from a registry
#  search      Search Docker Hub for images
#  version     Show the Docker version information
#  info        Display system-wide information


def run_local_docker(
    logger: "logging.Logger",
    docker_cmd: "str",
    args: "argparse.Namespace",
    *params: "str"
) -> "int":
    retval = subprocess.call(
        [
            docker_cmd,
            *params,
        ],
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True,
    )

    return retval


def local_docker_help(docker_cmd: "str") -> "str":
    proc = subprocess.Popen(
        [
            docker_cmd,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        outs, errs = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        outs, errs = proc.communicate()

    return errs


SUBCOMMAND_RE = re.compile(r"^  ([a-z]+)\*?\s+(.*)")


def inject_subparsers(
    p: "argparse.ArgumentParser",
    docker_cmd: "str",
    subcommand_router: "Mapping[str, Type[AbstractSubcommand]]",
) -> "None":
    # Let's learn the sub-commands
    help_block = local_docker_help(docker_cmd=docker_cmd)
    # print(help_block)

    current_sp = cast(
        "_SubParsersGroupAction", p.add_subparsers(dest="command", metavar="COMMAND")
    )
    current_sp_grp = None
    for line in help_block.split("\n"):
        if line.endswith("Options:"):
            current_sp_grp = None
        elif line.endswith("Commands:"):
            current_sp_grp = current_sp.add_parser_group(line)
        elif current_sp_grp is not None:
            match = SUBCOMMAND_RE.match(line)
            if match is not None:
                subcommand_clazz = subcommand_router.get(match[1])
                if subcommand_clazz is not None:
                    sp = current_sp_grp.add_parser(
                        match[1],
                        help=match[2],
                        add_help=False,
                    )
                    subcommand_clazz.PopulateArgsParser(sp)
                else:
                    current_sp_grp.add_parser(
                        match[1],
                        help=match[2],
                    )


LOG_MAPPING = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "error": logging.ERROR,
    "fatal": logging.FATAL,
}


def main(
    docker_cmd: "str" = DEFAULT_DOCKER_CMD,
    subcommand_classes: "Sequence[Type[AbstractSubcommand]]" = SUBCOMMAND_CLASSES,
) -> "int":
    subcommand_router: "Mapping[str, Type[AbstractSubcommand]]" = {
        sub_clazz.SUBCOMMAND(): sub_clazz for sub_clazz in subcommand_classes
    }

    p = argparse.ArgumentParser(
        prog="docker",
        description="Docker GA4GH TES shim",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.register("action", "parsers", _SubParsersGroupAction)

    p.add_argument(
        "--config",
        metavar="string",
        default=(pathlib.Path.home() / ".docker").as_posix(),
        help="Location of client config files",
    )
    p.add_argument(
        "-c",
        "--context",
        metavar="string",
        help='Name of the context to use to connect to the daemon (overrides DOCKER_HOST env var and default context set with "docker context use")',
    )
    p.add_argument(
        "-D",
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )
    p.add_argument(
        "-H",
        "--host",
        metavar="list",
        action="append",
        # default=["unix:///var/run/docker.sock"],
        help="Daemon socket to connect to",
    )
    p.add_argument(
        "-l",
        "--log-level",
        metavar="string",
        choices=["debug", "info", "warn", "error", "fatal"],
        default="info",
        help="Set the logging level",
    )
    p.add_argument(
        "--tls",
        action="store_true",
        help="Use TLS; implied by --tlsverify",
    )
    p.add_argument(
        "--tlscacert",
        metavar="string",
        default=(pathlib.Path.home() / ".docker" / "ca.pem").as_posix(),
        help="Trust certs signed only by this CA",
    )
    p.add_argument(
        "--tlscert",
        metavar="string",
        default=(pathlib.Path.home() / ".docker" / "cert.pem").as_posix(),
        help="Path to TLS certificate file",
    )
    p.add_argument(
        "--tlskey",
        metavar="string",
        default=(pathlib.Path.home() / ".docker" / "key.pem").as_posix(),
        help="Path to TLS key file",
    )
    p.add_argument(
        "--tlsverify",
        action="store_true",
        help="Use TLS and verify the remote",
    )
    p.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Print version information and quit",
    )

    inject_subparsers(p, docker_cmd=docker_cmd, subcommand_router=subcommand_router)

    args, unknown = p.parse_known_args()

    log_level_str = "info"
    if args.debug:
        log_level_str = "debug"
    elif args.log_level is not None:
        log_level_str = args.log_level

    log_level = LOG_MAPPING.get(log_level_str, logging.INFO)
    if log_level < logging.INFO:
        log_format = DEBUG_LOGGING_FORMAT
    else:
        log_format = LOGGING_FORMAT

    logging_config: "BasicLoggingConfigDict" = {
        "level": log_level,
        "format": log_format,
    }
    logging.basicConfig(**logging_config)
    logger = logging.getLogger("docker-tes-proxy")

    if args.version:
        return run_local_docker(logger, docker_cmd, args, "-v")

    if args.command is None:
        return run_local_docker(logger, docker_cmd, args, *unknown)
    elif args.command not in subcommand_router:
        return run_local_docker(logger, docker_cmd, args, args.command, *unknown)
    else:
        subcommand_instance = subcommand_router[args.command](docker_cmd)
        return subcommand_instance.subcommand(args, unknown)

    return 0


def main_and_exit() -> "None":
    sys.exit(main())


if __name__ == "__main__":
    main_and_exit()
