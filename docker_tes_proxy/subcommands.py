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
import argparse
import atexit
import inspect
import io
import logging
import os
import pathlib
import shutil
import stat
import sys
import tempfile

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging

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


from .ftp_server_helper import FTPServerForTES
import tes

DEFAULT_DEBUG_HOST: "Final[str]" = "http://localhost:8000"


class AbstractSubcommand(abc.ABC):
    def __init__(self, docker_cmd: "str"):
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
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


class RunSubcommand(AbstractSubcommand):
    @classmethod
    def SUBCOMMAND(cls) -> "str":
        return "run"

    @classmethod
    def PopulateArgsParser(cls, sp: "argparse.ArgumentParser") -> "None":
        # run parameters
        sp.add_argument(
            "--add-host",
            metavar="list",
            action="append",
            help="Add a custom host-to-IP mapping (host:ip)",
        )

        sp.add_argument(
            "--annotation",
            metavar="map",
            action="append",
            help="Add an annotation to the container (passed through to the OCI runtime)",
        )

        sp.add_argument(
            "-a",
            "--attach",
            metavar="list",
            action="append",
            choices=["stdin", "stdout", "stderr"],
            help="Attach to STDIN, STDOUT or STDERR",
        )

        sp.add_argument(
            "--blkio-weight",
            metavar="uint16",
            type=int,
            default=0,
            help="Block IO (relative weight), between 10 and 1000, or 0 to disable",
        )

        sp.add_argument(
            "--blkio-weight-device",
            metavar="list",
            action="append",
            help="Block IO weight (relative device weight)",
        )

        sp.add_argument(
            "--cap-add",
            metavar="list",
            action="append",
            help="Add Linux capabilities",
        )

        sp.add_argument(
            "--cap-drop",
            metavar="list",
            action="append",
            help="Drop Linux capabilities",
        )

        sp.add_argument(
            "--cgroup-parent",
            metavar="string",
            help="Optional parent cgroup for the container",
        )

        sp.add_argument(
            "--cgroupns",
            metavar="string",
            help="""\
Cgroup namespace to use (host|private)
'host':    Run the container in the Docker host's cgroup namespace
'private': Run the container in its own private cgroup namespace
'':        Use the cgroup namespace as configured by the
default-cgroupns-mode option on the daemon (default)""",
        )

        sp.add_argument(
            "--cidfile",
            metavar="string",
            help="Write the container ID to the file",
        )

        sp.add_argument(
            "--cpu-period",
            metavar="int",
            type=int,
            help="Limit CPU CFS (Completely Fair Scheduler) period",
        )

        sp.add_argument(
            "--cpu-quota",
            metavar="int",
            type=int,
            help="Limit CPU CFS (Completely Fair Scheduler) quota",
        )

        sp.add_argument(
            "--cpu-rt-period",
            metavar="int",
            type=int,
            help="Limit CPU real-time period in microseconds",
        )

        sp.add_argument(
            "--cpu-rt-runtime",
            metavar="int",
            type=int,
            help="Limit CPU real-time runtime in microseconds",
        )

        sp.add_argument(
            "-c",
            "--cpu-shares",
            metavar="int",
            type=int,
            help="CPU shares (relative weight)",
        )

        sp.add_argument(
            "--cpus",
            metavar="decimal",
            type=float,
            help="Number of CPUs",
        )

        sp.add_argument(
            "--cpuset-cpus",
            metavar="string",
            help="CPUs in which to allow execution (0-3, 0,1)",
        )

        sp.add_argument(
            "--cpuset-mems",
            metavar="string",
            help="MEMs in which to allow execution (0-3, 0,1)",
        )

        sp.add_argument(
            "-d",
            "--detach",
            action="store_true",
            help="Run container in background and print container ID",
        )

        sp.add_argument(
            "--detach-keys",
            metavar="string",
            help="Override the key sequence for detaching a container",
        )

        sp.add_argument(
            "--device",
            metavar="list",
            action="append",
            help="Add a host device to the container",
        )

        sp.add_argument(
            "--device-cgroup-rule",
            metavar="list",
            action="append",
            help="Add a rule to the cgroup allowed devices list",
        )

        sp.add_argument(
            "--device-read-bps",
            metavar="list",
            action="append",
            help="Limit read rate (bytes per second) from a device",
        )

        sp.add_argument(
            "--device-read-iops",
            metavar="list",
            action="append",
            help="Limit read rate (IO per second) from a device",
        )

        sp.add_argument(
            "--device-write-bps",
            metavar="list",
            action="append",
            help="Limit write rate (bytes per second) from a device",
        )

        sp.add_argument(
            "--device-write-iops",
            metavar="list",
            action="append",
            help="Limit write rate (IO per second) from a device",
        )

        sp.add_argument(
            "--disable-content-trust",
            action="store_true",
            help="Skip image verification",
        )

        sp.add_argument(
            "--dns",
            metavar="list",
            action="append",
            help="Set custom DNS servers",
        )

        sp.add_argument(
            "--dns-option",
            metavar="list",
            action="append",
            help="Set DNS options",
        )

        sp.add_argument(
            "--dns-search",
            metavar="list",
            action="append",
            help="Set custom DNS search domains",
        )

        sp.add_argument(
            "--domainname",
            metavar="string",
            help="Container NIS domain name",
        )

        sp.add_argument(
            "--entrypoint",
            metavar="string",
            help="Overwrite the default ENTRYPOINT of the image",
        )

        sp.add_argument(
            "-e",
            "--env",
            metavar="list",
            action="append",
            help="Set environment variables",
        )

        sp.add_argument(
            "--env-file",
            metavar="list",
            action="append",
            help="Read in a file of environment variables",
        )

        sp.add_argument(
            "--expose",
            metavar="list",
            action="append",
            help="Expose a port or a range of ports",
        )

        sp.add_argument(
            "--gpus",
            metavar="gpu-request",
            action="append",
            help="GPU devices to add to the container ('all' to pass all GPUs)",
        )

        sp.add_argument(
            "--group-add",
            metavar="list",
            action="append",
            help="Add additional groups to join",
        )

        sp.add_argument(
            "--health-cmd",
            metavar="string",
            help="Command to run to check health",
        )

        sp.add_argument(
            "--health-interval",
            metavar="duration",
            default="0s",
            help="Time between running the check (ms|s|m|h)",
        )

        sp.add_argument(
            "--health-retries",
            metavar="int",
            type=int,
            help="Consecutive failures needed to report unhealthy",
        )

        sp.add_argument(
            "--health-start-interval",
            metavar="duration",
            default="0s",
            help="Time between running the check during the start period (ms|s|m|h)",
        )

        sp.add_argument(
            "--health-timeout",
            metavar="duration",
            default="0s",
            help="Maximum time to allow one check to run (ms|s|m|h)",
        )

        sp.add_argument(
            "-h",
            "--hostname",
            metavar="string",
            help="Container host name",
        )

        sp.add_argument(
            "--init",
            action="store_true",
            help="Run an init inside the container that forwards signals and reaps processes",
        )

        sp.add_argument(
            "-i",
            "--interactive",
            action="store_true",
            help="Keep STDIN open even if not attached",
        )

        sp.add_argument(
            "--ip",
            metavar="string",
            help="IPv4 address (e.g., 172.30.100.104)",
        )

        sp.add_argument(
            "--ip6",
            metavar="string",
            help="IPv6 address (e.g., 2001:db8::33)",
        )

        sp.add_argument(
            "--ipc",
            metavar="string",
            help="IPC mode to use",
        )

        sp.add_argument(
            "--isolation",
            metavar="string",
            help="Container isolation technology",
        )

        sp.add_argument(
            "--kernel-memory",
            metavar="bytes",
            help="Kernel memory limit",
        )

        sp.add_argument(
            "-l",
            "--label",
            metavar="list",
            action="append",
            help="Set meta data on a container",
        )

        sp.add_argument(
            "--label-file",
            metavar="list",
            action="append",
            help="Read in a line delimited file of labels",
        )

        sp.add_argument(
            "--link",
            metavar="list",
            action="append",
            help="Add link to another container",
        )

        sp.add_argument(
            "--link-local-ip",
            metavar="list",
            action="append",
            help="Container IPv4/IPv6 link-local addresses",
        )

        sp.add_argument(
            "--log-driver",
            metavar="string",
            help="Logging driver for the container",
        )

        sp.add_argument(
            "--log-opt",
            metavar="list",
            action="append",
            help="Log driver options",
        )

        sp.add_argument(
            "--mac-address",
            metavar="string",
            help="Container MAC address (e.g., 92:d0:c6:0a:29:33)",
        )

        sp.add_argument(
            "-m",
            "--memory",
            metavar="bytes",
            help="Memory limit",
        )

        sp.add_argument(
            "--memory-reservation",
            metavar="bytes",
            help="Memory soft limit",
        )

        sp.add_argument(
            "--memory-swap",
            metavar="bytes",
            help="Swap limit equal to memory plus swap: '-1' to enable unlimited swap",
        )

        sp.add_argument(
            "--memory-swappiness",
            metavar="int",
            type=int,
            default=-1,
            help="Tune container memory swappiness (0 to 100)",
        )

        sp.add_argument(
            "--mount",
            metavar="mount",
            action="append",
            help="Attach a filesystem mount to the container",
        )

        sp.add_argument(
            "--name",
            metavar="string",
            help="Assign a name to the container",
        )

        sp.add_argument(
            "--network",
            metavar="network",
            action="append",
            help="Connect a container to a network",
        )

        sp.add_argument(
            "--network-alias",
            metavar="list",
            action="append",
            help="Add network-scoped alias for the container",
        )

        sp.add_argument(
            "--no-healthcheck",
            action="store_true",
            help="Disable any container-specified HEALTHCHECK",
        )

        sp.add_argument(
            "--oom-kill-disable",
            action="store_true",
            help="Disable OOM Killer",
        )

        sp.add_argument(
            "--oom-score-adj",
            metavar="int",
            type=int,
            help="Tune host's OOM preferences (-1000 to 1000)",
        )

        sp.add_argument(
            "--pid",
            metavar="string",
            help="PID namespace to use",
        )

        sp.add_argument(
            "--pids-limit",
            metavar="int",
            type=int,
            help="Tune container pids limit (set -1 for unlimited)",
        )

        sp.add_argument(
            "--platform",
            metavar="string",
            help="Set platform if server is multi-platform capable",
        )

        sp.add_argument(
            "--privileged",
            action="store_true",
            help="Give extended privileges to this container",
        )

        sp.add_argument(
            "-p" "--publish",
            metavar="list",
            action="append",
            help="Publish a container's port(s) to the host",
        )

        sp.add_argument(
            "-P" "--publish-all",
            action="store_true",
            help="Publish all exposed ports to random ports",
        )

        sp.add_argument(
            "--pull",
            metavar="string",
            choices=["always", "missing", "never"],
            default="missing",
            help='Pull image before running ("always", "missing", "never")',
        )

        sp.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Suppress the pull output",
        )

        sp.add_argument(
            "--read-only",
            action="store_true",
            help="Mount the container's root filesystem as read only",
        )

        sp.add_argument(
            "--restart",
            metavar="string",
            default="no",
            help="Restart policy to apply when a container exits",
        )

        sp.add_argument(
            "--rm",
            action="store_true",
            help="Automatically remove the container and its associated anonymous volumes when it exits",
        )

        sp.add_argument(
            "--runtime",
            metavar="string",
            default="no",
            help="Runtime to use for this container",
        )

        sp.add_argument(
            "--security-opt",
            metavar="list",
            action="append",
            help="Security Options",
        )

        sp.add_argument(
            "--shm-size",
            metavar="bytes",
            help="Size of /dev/shm",
        )

        sp.add_argument(
            "--sig-proxy",
            action="store_true",
            help="Proxy received signals to the process",
        )

        sp.add_argument(
            "--stop-signal",
            metavar="string",
            help="Signal to stop the container",
        )

        sp.add_argument(
            "--stop-timeout",
            metavar="int",
            type=int,
            help="Timeout (in seconds) to stop a container",
        )

        sp.add_argument(
            "--storage-opt",
            metavar="list",
            action="append",
            help="Storage driver options for the container",
        )

        sp.add_argument(
            "--sysctl",
            metavar="map",
            action="append",
            help="Sysctl options",
        )

        sp.add_argument(
            "--tmpfs",
            metavar="list",
            action="append",
            help="Mount a tmpfs directory",
        )

        sp.add_argument(
            "-t",
            "--tty",
            action="store_true",
            help="Allocate a pseudo-TTY",
        )

        sp.add_argument(
            "--ulimit",
            metavar="ulimit",
            action="append",
            help="Ulimit options",
        )

        sp.add_argument(
            "-u",
            "--user",
            metavar="string",
            help="Username or UID (format: <name|uid>[:<group|gid>])",
        )

        sp.add_argument(
            "--userns",
            metavar="string",
            help="User namespace to use",
        )

        sp.add_argument(
            "--uts",
            metavar="string",
            help="UTS namespace to use",
        )

        sp.add_argument(
            "-v",
            "--volume",
            metavar="list",
            action="append",
            help="Bind mount a volume",
        )

        sp.add_argument(
            "--volume-driver",
            metavar="string",
            help="Optional volume driver for the container",
        )

        sp.add_argument(
            "--volumes-from",
            metavar="list",
            action="append",
            help="Mount volumes from the specified container(s)",
        )

        sp.add_argument(
            "-w",
            "--workdir",
            metavar="string",
            help="Working directory inside the container",
        )

        sp.add_argument(
            "IMAGE",
            help="Docker image tag",
        )
        sp.add_argument(
            "CMDARGS",
            nargs=argparse.REMAINDER,
            help="Command line and args",
        )

    def subcommand(
        self,
        args: "argparse.Namespace",
        unknown: "Sequence[str]",
    ) -> "int":
        # This shim cannot work without command-line args
        if len(args.CMDARGS) == 0:
            return 125

        self.logger.debug(f"args {args}")
        self.logger.debug(f"unk {unknown}")

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

        # Register the task id
        if args.cidfile:
            try:
                cF = open(args.cidfile, mode="w", encoding="utf-8")
            except Exception as e:
                self.logger.error(
                    f"docker: failed to create the container ID file: open {args.cidfile}: {e}."
                )
                return 126
        else:
            cF = None

        # Parse the volumes
        file_server: "Optional[FTPServerForTES]" = None
        inputs: "List[tes.Input]" = []
        outputs: "List[tes.Output]" = []

        tstdin: "Optional[tempfile._TemporaryFileWrapper[bytes]]" = None
        if args.tty or ("stdin" in args.attach):
            self.logger.debug("Capturing stdin")
            capture_stdin = not os.isatty(sys.stdin.fileno())
            if capture_stdin:
                mode = os.fstat(sys.stdin.fileno()).st_mode
                capture_stdin = not (stat.S_ISBLK(mode) or stat.S_ISCHR(mode))

            if capture_stdin:
                tstdin = tempfile.NamedTemporaryFile(
                    delete=False, delete_on_close=False
                )
                atexit.register(os.unlink, tstdin.name)
                with tstdin as tFH:
                    shutil.copyfileobj(sys.stdin.buffer, tFH)

        stdin_input: "Optional[tes.Input]" = None
        if isinstance(args.volume, list) or tstdin is not None:
            file_server = FTPServerForTES()

            # Add the stdin
            if tstdin:
                the_uri = file_server.add_ro_volume(tstdin.name)
                remote_path = "/" + os.path.basename(tstdin.name)
                stdin_input = tes.Input(
                    url=the_uri,
                    path=remote_path,
                    type="FILE",
                )
                inputs.append(stdin_input)

            for volume_decl in args.volume:
                volume_parts = volume_decl.split(":")
                flags = ""
                if len(volume_parts) == 1:
                    local_path = volume_parts
                    remote_path = pathlib.Path(local_path).resolve().as_posix()
                else:
                    local_path, remote_path = volume_parts[0:2]
                    if len(volume_parts) > 2:
                        flags = volume_parts[2]

                local_path_exists = os.path.exists(local_path)
                is_ro = flags.startswith("ro")

                if local_path_exists:
                    if is_ro:
                        the_uri = file_server.add_ro_volume(local_path)
                    else:
                        the_uri = file_server.add_rw_volume(local_path)
                elif is_ro:
                    # This is not an error in docker, as it blindly creates
                    # an empty directory for it.
                    self.logger.error(
                        f"docker: failed to map inexistent {local_path} as a read only volume"
                    )
                    return 126
                else:
                    the_uri = file_server.add_wo_volume(local_path)

                if is_ro:
                    inputs.append(
                        tes.Input(
                            url=the_uri,
                            path=remote_path,
                            type="FILE" if os.path.isfile(local_path) else "DIRECTORY",
                        )
                    )
                else:
                    outputs.append(
                        tes.Output(
                            url=the_uri,
                            path=remote_path,
                            type=(
                                "FILE"
                                if not local_path_exists or os.path.isfile(local_path)
                                else "DIRECTORY"
                            ),
                        )
                    )

            # Start the file server
            if self.logger.getEffectiveLevel() > logging.DEBUG:
                file_server.daemonize()
            else:
                file_server.daemonize("/tmp/ftp-log.txt")

        # Define task
        task = tes.Task(
            executors=[
                tes.Executor(
                    image=args.IMAGE,
                    command=args.CMDARGS,
                    env=task_env,
                    stdin=None if stdin_input is None else stdin_input.path,
                )
            ],
            inputs=inputs,
            outputs=outputs,
        )

        if args.interactive:
            self.logger.debug(
                "--interactive cannot be honoured as there is no STDIN streaming communication in GA4GH TES"
            )

        # Create and run task
        try:
            task_resp_id = cli.create_task(task)
        except Exception as e:
            self.logger.exception(f"Could not create task")
            return 126

        retval = 126
        if cF is not None:
            try:
                cF.write(task_resp_id)
            except Exception as e:
                self.logger.error(
                    f"docker: failed to write the container ID file {args.cidfile}: {e}."
                )
            else:
                if args.detach:
                    retval = 0
            finally:
                cF.close()

        if args.detach:
            return retval

        timeout = None
        w_task = cli.wait(task_resp_id, timeout=timeout)

        self.logger.debug(w_task)

        task_info = cli.get_task(
            task_resp_id, view="FULL" if args.tty or len(args.attach) > 0 else "BASIC"
        )

        retval = 126
        if isinstance(task_info.logs, list) and len(task_info.logs) > 0:
            task_log = task_info.logs[-1]
            if isinstance(task_log.logs, list) and len(task_log.logs) > 0:
                exec_log = task_log.logs[-1]

                if exec_log.exit_code is not None:
                    retval = exec_log.exit_code
                if args.tty or ("stdout" in args.attach):
                    if exec_log.stdout is not None:
                        sys.stdout.write(exec_log.stdout)
                if args.tty or ("stderr" in args.attach):
                    if exec_log.stderr is not None:
                        sys.stderr.write(exec_log.stderr)

        if file_server is not None:
            file_server.synchronize()

        self.logger.debug(task_info)
        # j = json.loads(task_info.as_json())
        # print(j)

        if args.rm:
            self.logger.debug(
                "--rm cannot be honoured, as there is no standard way to remove the task from the list of already completed tasks in GA4GH TES"
            )

        return retval


SUBCOMMAND_CLASSES: "Sequence[Type[AbstractSubcommand]]" = [
    RunSubcommand,
]
