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
import tarfile
import tempfile

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        Dict,
        IO,
        Iterable,
        List,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Set,
        Tuple,
        Type,
        Union,
    )

    from ..file_server import (
        AbstractFileServerForTES,
    )

    from _typeshed import (
        StrOrBytesPath,
        StrPath,
    )

from . import AbstractSubcommand

import tes

from builtins import open as bltn_open


class TarFileSkipper(tarfile.TarFile):

    def add_skipping_unreadable(
        self,
        name: "StrPath",
        arcname: "Optional[StrPath]" = None,
        recursive: "bool" = True,
        skip_names: "Set[str]" = set(),
        *,
        filter: "Optional[Callable[[tarfile.TarInfo], tarfile.TarInfo | None]]" = None,
    ) -> "None":
        """Add the file `name' to the archive. `name' may be any type of file
        (directory, fifo, symbolic link, etc.). If given, `arcname'
        specifies an alternative name for the file in the archive.
        Directories are added recursively by default. This can be avoided by
        setting `recursive' to False. `filter' is a function
        that expects a TarInfo object argument and returns the changed
        TarInfo object, if it returns None the TarInfo object will be
        excluded from the archive.
        """
        # self._check("awx")

        if arcname is None:
            arcname = name

        # Skip if somebody tries to archive the archive...
        if self.name is not None and os.path.abspath(name) == self.name:
            # self._dbg(2, "tarfile: Skipped %r" % name)
            return

        # self._dbg(1, name)

        # Create a TarInfo object from the file.
        tarinfo: "Optional[tarfile.TarInfo]" = self.gettarinfo(name, str(arcname))

        if tarinfo is None:
            # self._dbg(1, "tarfile: Unsupported type %r" % name)
            return

        # Change or exclude the TarInfo object.
        if filter is not None:
            tarinfo = filter(tarinfo)
            if tarinfo is None:
                # self._dbg(2, "tarfile: Excluded %r" % name)
                return

        # Append the tar header and data to the archive.
        if tarinfo.isreg():
            try:
                with bltn_open(name, "rb") as f:
                    self.addfile(tarinfo, f)
            except:
                # self._dbg(2, "tarfile: Skipped %r due it is unreadable" % name)
                pass

        elif tarinfo.isdir():
            self.addfile(tarinfo)
            if recursive:
                try:
                    for lf in sorted(os.listdir(name)):
                        # Skip these names
                        if lf in skip_names:
                            continue
                        self.add_skipping_unreadable(
                            os.path.join(name, lf),
                            os.path.join(arcname, lf),
                            recursive,
                            filter=filter,
                        )
                except:
                    # self._dbg(2, "tarfile: Skipped %r due it is unreadable" % name)
                    pass

        else:
            self.addfile(tarinfo)

    def extractall_skipping_unwritable(
        self,
        path: "StrOrBytesPath" = ".",
        members: "Optional[Iterable[tarfile.TarInfo]]" = None,
        *,
        numeric_owner: "bool" = False,
        filter: "Optional[tarfile._TarfileFilter]" = None,
    ) -> "None":
        """Extract all members from the archive to the current working
        directory and set owner, modification time and permissions on
        directories afterwards. `path' specifies a different directory
        to extract to. `members' is optional and must be a subset of the
        list returned by getmembers(). If `numeric_owner` is True, only
        the numbers for user/group names are used and not the names.

        The `filter` function will be called on each member just
        before extraction.
        It can return a changed TarInfo or None to skip the member.
        String names of common filters are accepted.
        """
        directories = []

        filter_function = self._get_filter_function(filter)  # type: ignore[attr-defined]
        if members is None:
            members = self

        for member in members:
            tarinfo, _ = self._get_extract_tarinfo(member, filter_function, path)  # type: ignore[attr-defined]
            if tarinfo is None:
                continue
            if tarinfo.isdir():
                # For directories, delay setting attributes until later,
                # since permissions can interfere with extraction and
                # extracting contents can reset mtime.
                directories.append(tarinfo)
            try:
                self._extract_one(  # type: ignore[attr-defined]
                    tarinfo,
                    path,
                    set_attrs=not tarinfo.isdir(),
                    numeric_owner=numeric_owner,
                )
            except:
                pass

        # Reverse sort directories.
        directories.sort(key=lambda a: a.name, reverse=True)

        # Set correct owner, mtime and filemode on directories.
        for tarinfo in directories:
            dirpath = os.path.join(path, tarinfo.name)
            try:
                self.chown(tarinfo, dirpath, numeric_owner=numeric_owner)
                self.utime(tarinfo, dirpath)
                self.chmod(tarinfo, dirpath)
            except tarfile.ExtractError as e:
                self._handle_nonfatal_error(e)  # type: ignore[attr-defined]


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
            "--cpu-count",
            metavar="int",
            type=int,
            help="Number of CPUs",
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
            nargs="?",
            action="store",
            type=bool,
            const=True,
            default=False,
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
            nargs="?",
            action="store",
            type=bool,
            const=True,
            default=False,
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

        # Let's detect whether this shim was called from Nextflow
        NXF_TASK_WORKDIR: "Optional[str]" = None
        NXF_TASK_WORKDIR_RO: "Optional[str]" = None
        num_nxf_vars: "int" = 0
        for keyname in os.environ.keys():
            if keyname.startswith("NXF_"):
                num_nxf_vars += 1
                if keyname == "NXF_TASK_WORKDIR":
                    NXF_TASK_WORKDIR = os.environ[keyname]
                self.logger.debug(f"Matched Nextflow envvar {keyname}")

        # At least NXF_BOXID, NXF_CLI, NXF_ORG and NXF_HOME
        if num_nxf_vars >= 4 and args.workdir is not None:
            if NXF_TASK_WORKDIR is not None and NXF_TASK_WORKDIR != args.workdir:
                self.logger.debug(
                    f"Mismatch in workdir: {NXF_TASK_WORKDIR} vs {args.workdir}"
                )

            NXF_TASK_WORKDIR = args.workdir
            if TYPE_CHECKING:
                assert NXF_TASK_WORKDIR is not None
            NXF_TASK_WORKDIR_RO = NXF_TASK_WORKDIR + "_ro"
        else:
            self.logger.debug("Disabling misdetected Nextflow call")
            NXF_TASK_WORKDIR = None

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
            if os.path.exists(args.cidfile):
                print(
                    f"""\
docker: container ID file found, make sure the other container isn't running or delete {args.cidfile}.
See 'docker run --help'."""
                )
                return 125
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
        file_server: "Optional[AbstractFileServerForTES]" = None
        inputs: "List[tes.Input]" = []
        outputs: "List[tes.Output]" = []

        tstdin: "Optional[tempfile._TemporaryFileWrapper[bytes]]" = None
        args_attach = args.attach if isinstance(args.attach, list) else []
        if args.tty or ("stdin" in args_attach):
            self.logger.debug("Capturing stdin")
            capture_stdin = not os.isatty(sys.stdin.fileno())
            if capture_stdin:
                mode = os.fstat(sys.stdin.fileno()).st_mode
                capture_stdin = not (stat.S_ISBLK(mode) or stat.S_ISCHR(mode))

            if capture_stdin:
                tstdin = tempfile.NamedTemporaryFile(delete=False)
                atexit.register(os.unlink, tstdin.name)
                with tstdin as tFH:
                    shutil.copyfileobj(sys.stdin.buffer, tFH)
            else:
                self.logger.debug(
                    "--tty or --attach stdin cannot be completely honoured with pipes as there is no STDIN streaming communication in GA4GH TES"
                )

        file_server = self.file_server

        stdin_input: "Optional[tes.Input]" = None
        # Add the stdin
        if tstdin:
            the_uri = file_server.add_ro_volume(tstdin.name)
            remote_path_t = "/" + os.path.basename(tstdin.name)
            stdin_input = tes.Input(
                url=the_uri,
                path=remote_path_t,
                type="FILE",
            )
            inputs.append(stdin_input)

        # The digested volume tuples are stored here
        volumes_tuples: "MutableSequence[Tuple[str, str, Union[str, Set[str]]]]" = []

        # --volume
        if isinstance(args.volume, list):
            for volume_decl in args.volume:
                volume_parts = volume_decl.split(":")
                flags = ""
                if len(volume_parts) == 1:
                    local_path = volume_parts
                    remote_path_v = pathlib.Path(local_path).resolve().as_posix()
                else:
                    local_path, remote_path_v = volume_parts[0:2]
                    if len(volume_parts) > 2:
                        flags = volume_parts[2]
                volumes_tuples.append((local_path, remote_path_v, flags))

        # subset of --mount
        if isinstance(args.mount, list):
            for mount_decl in args.mount:
                mount_attrs: "MutableMapping[str, str]" = {}
                mount_parts = mount_decl.split(",")
                for mount_part in mount_parts:
                    keyval = mount_part.split("=", 1)
                    mount_attrs[keyval[0]] = keyval[-1]

                if mount_attrs.get("type") == "bind":
                    local_path = mount_attrs.get("src", mount_attrs.get("source"))
                    remote_path_m = mount_attrs.get("dst")
                    if remote_path_m is None:
                        remote_path_m = mount_attrs.get("destination")
                        if remote_path_m is None:
                            remote_path_m = mount_attrs.get("target")

                    flags = (
                        "ro"
                        if ("ro" in mount_attrs) or ("readonly" in mount_attrs)
                        else ""
                    )
                    if local_path is not None and remote_path_m is not None:
                        volumes_tuples.append((local_path, remote_path_m, flags))
                else:
                    self.logger.debug(
                        f"--mount={mount_decl} cannot be honoured, as only type=bind can be emulated in GA4GH TES"
                    )

        tags = dict()
        # Emulation of --annotation, which is mapped to tags
        if isinstance(args.annotation, list):
            for annotation_decl in args.annotation:
                parts = annotation_decl.split("=", 1)
                tags[parts[0]] = parts[-1]

        task_volumes: "List[str]" = []
        volume_extractions: "MutableSequence[Tuple[str, str]]" = []
        volume_packings: "MutableSequence[Tuple[str, str, Set[str]]]" = []
        local_volume_extractions: "MutableSequence[Tuple[str, str]]" = []

        added_wo_volume: "bool" = False
        wo_volume_name: "str" = f"/__outputs__{os.getpid()}"

        # Populate the list of volumes to remove
        # now we know we have to "improve" Nextflow setup
        skip_volumes: "Set[str]" = set()
        if NXF_TASK_WORKDIR_RO is not None:
            # First the task ro volume for input only files and directories
            self.logger.debug(f"Before tuples {volumes_tuples}")

            # Now, translate the symlinks into ro volumes
            skip_entries: "Set[str]" = set()
            for entry in os.scandir(NXF_TASK_WORKDIR):
                # Symlink
                if entry.is_symlink():
                    skip_entries.add(entry.name)
                    sympath = os.readlink(entry.path)
                    if os.path.isabs(sympath):
                        if os.path.isdir(sympath):
                            skip_volumes.add(sympath)
                        else:
                            skip_volumes.add(os.path.dirname(sympath))
                        # Now, let's inject the right volume
                        volumes_tuples.append(
                            (
                                sympath,
                                os.path.join(NXF_TASK_WORKDIR_RO, entry.name),
                                "ro",
                            )
                        )
                elif entry.is_file() and entry.stat().st_nlink > 1:
                    # Hardlink
                    volumes_tuples.append(
                        (
                            entry.path,
                            os.path.join(NXF_TASK_WORKDIR_RO, entry.name),
                            "ro",
                        )
                    )

            # Now, look for special PATH declarations related to bin
            for cmdarg in args.CMDARGS:
                if cmdarg.startswith("eval "):
                    semicolon_pos = cmdarg.find(";")
                    if semicolon_pos != -1:
                        evalarg = cmdarg[len("eval ") : semicolon_pos].strip()
                        for match in re.finditer(
                            r"([^\n =]+)=(['\"]?)([^\"]*)\2[\n ]?", evalarg
                        ):
                            if match[1] == "PATH":
                                for path_token in match[3].split(":"):
                                    if path_token.startswith("/"):
                                        volumes_tuples.append(
                                            (path_token, path_token, "ro")
                                        )

            if TYPE_CHECKING:
                assert NXF_TASK_WORKDIR is not None
            volumes_tuples = list(
                filter(
                    lambda vt: vt[0] != vt[1]
                    or (
                        os.path.commonpath([NXF_TASK_WORKDIR, vt[0]]) != vt[0]
                        and (vt[0] not in skip_volumes)
                    ),
                    volumes_tuples,
                )
            )

            volumes_tuples.append((NXF_TASK_WORKDIR, NXF_TASK_WORKDIR, skip_entries))
            self.logger.debug(f"After tuples {volumes_tuples}")
            self.logger.debug(f"Skip volumes {skip_volumes}")

        # Now, process all the volume tuples
        for local_path, remote_path, flags_or_skip in volumes_tuples:
            local_path_exists = os.path.exists(local_path)
            is_ro = isinstance(flags_or_skip, str) and flags_or_skip.startswith("ro")
            remote_path_rw = remote_path

            if local_path_exists:
                if os.path.isdir(local_path) and (
                    not self.tes_service_supports_dirs or isinstance(flags_or_skip, set)
                ):
                    skip_names = (
                        flags_or_skip if isinstance(flags_or_skip, set) else set()
                    )
                    # The destination for the content
                    local_path_dir = local_path
                    remote_path_dir = remote_path

                    task_volumes.append(remote_path_dir)

                    volume_tar_file = tempfile.NamedTemporaryFile(delete=False)
                    local_path = volume_tar_file.name
                    atexit.register(os.unlink, local_path)

                    with TarFileSkipper.open(
                        local_path, mode="w:gz", bufsize=10 * 1024**2
                    ) as vtFH:
                        vtFH.add_skipping_unreadable(
                            local_path_dir, arcname=".", skip_names=skip_names
                        )

                    remote_path = "/__tars__/" + os.path.basename(local_path)
                    remote_path_rw = "/__rw__/" + os.path.basename(local_path)

                    volume_extractions.append((remote_path, remote_path_dir))
                    if not is_ro:
                        volume_packings.append(
                            (remote_path_dir, remote_path_rw, skip_names)
                        )
                        local_volume_extractions.append((local_path, local_path_dir))
                else:
                    remote_path_rw = "/__rw__" + remote_path

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
                if not added_wo_volume:
                    task_volumes.append(wo_volume_name)
                if not self.tes_service_supports_dirs:
                    local_path_dir = local_path
                    remote_path_dir = remote_path

                    volume_tar_file = tempfile.NamedTemporaryFile(delete=False)
                    # It should not exist
                    os.unlink(volume_tar_file.name)
                    atexit.register(os.unlink, volume_tar_file.name)

                    local_path = volume_tar_file.name

                    task_volumes.append(remote_path_dir)

                    remote_path_rw = wo_volume_name + "/" + os.path.basename(local_path)

                    volume_packings.append((remote_path_dir, remote_path_rw, set()))
                    local_volume_extractions.append((local_path, local_path_dir))

                the_uri = file_server.add_wo_volume(local_path)

            if local_path_exists:
                inputs.append(
                    tes.Input(
                        url=the_uri,
                        path=remote_path,
                        type="FILE" if os.path.isfile(local_path) else "DIRECTORY",
                    )
                )
            if not is_ro:
                outputs.append(
                    tes.Output(
                        url=the_uri,
                        path=remote_path_rw,
                        type=(
                            "FILE"
                            if not local_path_exists or os.path.isfile(local_path)
                            else "DIRECTORY"
                        ),
                    )
                )

        # Keep the file server running only if it is needed
        if len(inputs) > 0 or len(outputs) > 0:
            if self.logger.getEffectiveLevel() > logging.DEBUG:
                file_server.daemonize()
            else:
                file_server.daemonize("/tmp/ftp-log.txt")
        else:
            file_server = None

        task_resources: "Optional[tes.Resources]" = None
        cpu_count = 0
        # Maps --cpu-count
        if args.cpu_count is not None and args.cpu_count > cpu_count:
            cpu_count = args.cpu_count

        # Maps --cpus rounding up
        if args.cpus is not None and round(args.cpus) > cpu_count:
            cpu_count = round(args.cpus)

        # Maps --memory and --memory-swap to the needed memory (in GB)
        task_memory: "float" = 0
        units_div_to_gb = {
            "g": 1,
            "m": 1024,
            "k": 1024**2,
            "b": 1024**3,
            "": 1024**3,
        }
        for memory_decl in (args.memory, args.memory_swap):
            if memory_decl is None:
                continue
            m = re.match(r"^([0-9]+\.?[0-9]*)([bkmg]?)", memory_decl)
            if m is None:
                self.logger.error(f"Wrong memory definition {memory_decl}")
                return 126
            if m[2] not in units_div_to_gb:
                self.logger.error(f"Wrong memory units definition {memory_decl}")
                return 126

            # The memory, in GB, is computed
            memory_computed = float(m[1]) / units_div_to_gb[m[2]]
            if memory_computed > task_memory:
                task_memory = memory_computed

        if cpu_count > 0 or task_memory > 0:
            task_resources = tes.Resources(
                cpu_cores=cpu_count if cpu_count > 0 else None,
                ram_gb=task_memory if task_memory > 0 else None,
            )

        executors = []
        if len(volume_extractions) > 0:
            executors.append(
                tes.Executor(
                    image="alpine:3.12",
                    command=[
                        "sh",
                        "-c",
                        'for A in "$@"; do tar -x -C "${A#*:}" -f "${A%%:*}" ; done',
                        "extractor",
                        *map(lambda ve: ve[0] + ":" + ve[1], volume_extractions),
                    ],
                )
            )

        # Created the proper symlinks for the read only contents
        if NXF_TASK_WORKDIR_RO is not None:
            executors.append(
                tes.Executor(
                    image="alpine:3.12",
                    command=[
                        "sh",
                        "-c",
                        'ln -s "$1"/* "$2"',
                        "symlinker",
                        NXF_TASK_WORKDIR_RO,
                        NXF_TASK_WORKDIR,
                    ],
                )
            )

            # executors.append(
            #    tes.Executor(
            #        image="alpine:3.12",
            #        command=[
            #            "sh",
            #            "-c",
            #            '(for A in "$@" ; do echo "$A" ; ls -la "$A" ; done) 1>&2 ; exit 9',
            #            "debugger",
            #            NXF_TASK_WORKDIR_RO,
            #            NXF_TASK_WORKDIR,
            #        ],
            #    )
            # )

        cmdargs: "Sequence[str]" = args.CMDARGS
        # Several nextflow versions use the dirty trick of
        # overriding the entrypoint, building an incomplete
        # command line
        if args.entrypoint is not None:
            cmdargs = [args.entrypoint, *args.CMDARGS]
        main_task_idx = len(executors)
        executors.append(
            tes.Executor(
                image=args.IMAGE,
                command=cmdargs,
                env=task_env,
                stdin=None if stdin_input is None else stdin_input.path,
                workdir=args.workdir,
                # This is needed, so the last step saves back what it was generated
                ignore_error=True,
            )
        )

        if len(volume_packings) > 0:
            executors.append(
                tes.Executor(
                    image="alpine:3.12",
                    command=[
                        "sh",
                        "-c",
                        'for A in "$@"; do from="${A%%:*}" ; toexcl="${A#*:}" ; to="${toexcl%%:*}" ; if [ -f "$from" ] ; then cp -p "$from" "$to" ; else excl_raw="${toexcl#*:}" ; if [ -z "$excl_raw" ] ; then excl="" ; else excl="$(echo "$excl_raw" | tr ":" "\n" | xargs -n 1 echo --exclude)" ; fi ; tar $excl -c -z -C "$from" -f "$to" . ; fi ; done',
                        "packer",
                        *map(
                            lambda vp: vp[0]
                            + ":"
                            + vp[1]
                            + ":"
                            + (":".join(vp[2]) if isinstance(vp[2], set) else ""),
                            volume_packings,
                        ),
                    ],
                )
            )

        # Define task
        task = tes.Task(
            executors=executors,
            inputs=inputs,
            outputs=outputs,
            volumes=task_volumes if len(task_volumes) > 0 else None,
            tags=tags if len(tags) > 0 else None,
            resources=task_resources,
            name=args.name,
        )

        self.logger.debug(task.as_json(indent=4))

        # Create and run task
        try:
            task_resp_id = self.tes_cli.create_task(task)
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
        w_task = self.tes_cli.wait(task_resp_id, timeout=timeout)

        self.logger.debug(w_task)

        task_info = self.tes_cli.get_task(
            task_resp_id,
            view="FULL" if args.interactive or len(args_attach) > 0 else "BASIC",
        )

        if isinstance(task_info.logs, list):
            self.logger.debug(f"Log entries {len(task_info.logs)}")
            for task_log in task_info.logs:
                if isinstance(task_log.logs, list):
                    self.logger.debug(f"Exec Log entries {len(task_log.logs)}")

        retval = 126
        if isinstance(task_info.logs, list) and len(task_info.logs) > 0:
            task_log = task_info.logs[-1]
            if isinstance(task_log.logs, list) and len(task_log.logs) > main_task_idx:
                exec_log = task_log.logs[main_task_idx]

                if exec_log.exit_code is not None:
                    retval = exec_log.exit_code
                if args.interactive or ("stdout" in args_attach):
                    if exec_log.stdout is not None:
                        sys.stdout.write(exec_log.stdout)
                if args.interactive or ("stderr" in args_attach):
                    if exec_log.stderr is not None:
                        sys.stderr.write(exec_log.stderr)

        # Now, post-processing of results
        for tarfile, destpath in local_volume_extractions:
            self.logger.debug(f"extract {tarfile} => {destpath}")
            with TarFileSkipper.open(tarfile, mode="r:*") as tfH:
                # This is needed for cases where locally read-only content
                # is remotely updated because the volume was writable
                tfH.extractall_skipping_unwritable(destpath)

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
