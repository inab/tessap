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

import atexit
import copy
import inspect
import logging
import os
import pathlib
import shutil
import signal
import sys
import tempfile
import time
import urllib.parse
import uuid

# import pyftpdlib.ioloop
# pyftpdlib.ioloop.IOLoop = pyftpdlib.ioloop.Poll

import pyftpdlib.handlers

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        MutableMapping,
        Optional,
        Union,
    )
    from pyftpdlib.handlers import (
        ProtoCmd,
    )

from . import AbstractFileServerForTES

# BEWARE!!!! This is needed because FTP client implementation
# used by funnel (and funnel itself) forgets the kind of input file
# and tries listing a file as a directory
funnel_proto_cmds = cast(
    "MutableMapping[str, ProtoCmd]", copy.copy(pyftpdlib.handlers.proto_cmds)
)
del funnel_proto_cmds["MLSD"]
del funnel_proto_cmds["MLST"]


class FixedFTPHandler(FTPHandler):
    proto_cmds = funnel_proto_cmds


#    def ftp_OPTS(self, line):
#        """Specify options for FTP commands as specified in RFC-2389."""
#        try:
#            if line.count(' ') > 1:
#                raise ValueError('Invalid number of arguments')
#            if ' ' in line:
#                cmd, arg = line.split(' ')
#                #if ';' not in arg:
#                #    raise ValueError('Invalid argument')
#            else:
#                cmd, arg = line, ''
#            # actually the only command able to accept options is MLST
#            if cmd.upper() != 'MLST' or 'MLST' not in self.proto_cmds:
#                raise ValueError(f'Unsupported command "{cmd}"')
#        except ValueError as err:
#            self.respond(f'501 {err}.')
#        else:
#            facts = [x.lower() for x in arg.split(';')]
#            self._current_facts = [
#                x for x in facts if x in self._available_facts
#            ]
#            f = ''.join([x + ';' for x in self._current_facts])
#            self.respond('200 MLST OPTS ' + f)


class PermissiveFS(AbstractedFS):
    def validpath(self, path: "str") -> "bool":
        return True

    def get_user_by_uid(self, uid: "Union[int, str]") -> "str":
        return "owner"

    def get_group_by_gid(self, gid: "Union[int, str]") -> "str":
        return "group"

    # We are hiding here the symbolic links
    def lstat(self, path: "str") -> "os.stat_result":
        return self.stat(path)

    # We are hiding here the symbolic links
    def islink(self, path: "str") -> "bool":
        """Return True if path is a symbolic link."""
        return False


def pid_exists(pid: "int") -> "bool":
    """Return True if a process with the given PID is currently running."""
    try:
        os.kill(pid, 0)
    except PermissionError:
        # EPERM clearly means there's a process to deny access to
        return True
    except:
        return False
    else:
        return True


class DaemonRunningException(Exception):
    pass


class FTPServerForTES(AbstractFileServerForTES):
    USER_RO = "user_ro"
    USER_RW = "user_rw"
    USER_WO = "user_wo"

    def __init__(
        self,
        public_name: "str" = "localhost",
        public_port: "Optional[int]" = None,
        listen_ip: "str" = "::",
        listen_port: "int" = 2121,
    ):
        super().__init__(
            public_name=public_name,
            public_port=public_port,
            listen_ip=listen_ip,
            listen_port=listen_port,
        )

        self.authorizer = DummyAuthorizer()

        self.handler_clazz = FixedFTPHandler
        self.handler_clazz.authorizer = self.authorizer
        self.handler_clazz.abstracted_fs = PermissiveFS

        # Directories holding the read-only
        # and read-write volumes
        self.ro_dir = tempfile.mkdtemp(prefix="dtp", suffix="tmpexport")
        atexit.register(shutil.rmtree, self.ro_dir, True)
        self.ro_input_dir = pathlib.Path(self.ro_dir) / "input"
        self.ro_input_dir.mkdir()
        self.rw_dir = tempfile.mkdtemp(prefix="dtp", suffix="tmpei")
        atexit.register(shutil.rmtree, self.rw_dir, True)
        self.rw_io_dir = pathlib.Path(self.rw_dir) / "io"
        self.rw_io_dir.mkdir()
        self.wo_dir = tempfile.mkdtemp(prefix="dtp", suffix="tmpimport")
        atexit.register(shutil.rmtree, self.wo_dir, True)
        self.wo_output_dir = pathlib.Path(self.wo_dir) / "output"
        self.wo_output_dir.mkdir()

        self.user_ro_pass = str(uuid.uuid4())
        self.user_rw_pass = str(uuid.uuid4())
        self.user_wo_pass = str(uuid.uuid4())
        self.authorizer.add_user(
            self.USER_RO, self.user_ro_pass, self.ro_dir, perm="elr"
        )
        self.authorizer.add_user(
            self.USER_RW, self.user_rw_pass, self.rw_dir, perm="elradfmwMT"
        )
        self.authorizer.add_user(
            self.USER_WO, self.user_wo_pass, self.wo_dir, perm="elradfmwMT"
        )

        self.wo_mapping: "MutableMapping[str, pathlib.Path]" = dict()

        self.daemon_pid: "Optional[int]" = None

    def add_ro_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        if self.daemon_pid is not None:
            self.logger.warning(
                f"FTP daemon is already running at {self.daemon_pid}. Changes could not be visible"
            )

        if os.path.isfile(local_path):
            prefix = "file_"
            postfix = ""
        else:
            prefix = "dir_"
            postfix = "/"
        rand_name = prefix + str(uuid.uuid4())
        ftp_path = os.path.join(self.ro_input_dir, rand_name)
        os.symlink(os.path.realpath(local_path), ftp_path)

        return urllib.parse.urlunparse(
            (
                "ftp",
                urllib.parse.quote(self.USER_RO)
                + ":"
                + urllib.parse.quote(self.user_ro_pass)
                + "@"
                + self.public_name
                + ":"
                + str(self.public_port),
                "/" + os.path.relpath(ftp_path, self.ro_dir) + postfix,
                "",
                "",
                "",
            )
        )

    def add_rw_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        if self.daemon_pid is not None:
            self.logger.warning(
                f"FTP daemon is already running at {self.daemon_pid}. Changes could not be visible"
            )

        if os.path.isfile(local_path):
            prefix = "file_"
            postfix = ""
        else:
            prefix = "dir_"
            postfix = "/"
        rand_name = prefix + str(uuid.uuid4())
        ftp_path = os.path.join(self.rw_io_dir, rand_name)
        os.symlink(os.path.realpath(local_path), ftp_path)

        return urllib.parse.urlunparse(
            (
                "ftp",
                urllib.parse.quote(self.USER_RW)
                + ":"
                + urllib.parse.quote(self.user_rw_pass)
                + "@"
                + self.public_name
                + ":"
                + str(self.public_port),
                "/" + os.path.relpath(ftp_path, self.rw_dir) + postfix,
                "",
                "",
                "",
            )
        )

    def add_wo_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        if self.daemon_pid is not None:
            self.logger.warning(
                f"FTP daemon is already running at {self.daemon_pid}. Changes could not be visible"
            )

        rand_name = str(uuid.uuid4())
        ftp_path = os.path.join(self.wo_output_dir, rand_name)
        self.wo_mapping[rand_name] = pathlib.Path(local_path).resolve()

        return urllib.parse.urlunparse(
            (
                "ftp",
                urllib.parse.quote(self.USER_WO)
                + ":"
                + urllib.parse.quote(self.user_wo_pass)
                + "@"
                + self.public_name
                + ":"
                + str(self.public_port),
                "/" + os.path.relpath(ftp_path, self.wo_dir),
                "",
                "",
                "",
            )
        )

    def synchronize(self) -> "None":
        # Bring back contents
        if self.daemon_pid is None:
            self.logger.warning(
                f"FTP daemon is not running. Changes could have been removed"
            )

        for rand_name, local_path in self.wo_mapping.items():
            ftp_path = self.wo_output_dir / rand_name

            if ftp_path.exists():
                shutil.move(ftp_path, local_path)
            else:
                self.logger.error(
                    f"File {ftp_path} could not be moved to {local_path}, as it does not exist"
                )

        # Last, clear it!
        self.wo_mapping = dict()

    def daemonize(self, log_file: "str" = "/dev/null") -> "bool":
        """Based on https://github.com/giampaolo/pyftpdlib/blob/29ad496d9a4f2bc3944fe2adbe0064a8fe702df4/demo/unix_daemon.py"""
        """A wrapper around python-daemonize context manager."""

        def _daemonize(log_file: "str") -> int:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                return pid

            # decouple from parent environment
            # os.chdir(WORKDIR)
            os.chdir("/")
            os.setsid()
            # os.umask(0)
            os.umask(0o077)

            # # do second fork
            # pid = os.fork()
            # if pid > 0:
            #     # exit from second parent
            #     sys.exit(0)

            # redirect standard file descriptors
            sys.stdout.flush()
            sys.stderr.flush()
            so_fileno = os.open(log_file, os.O_CREAT | os.O_WRONLY | os.O_APPEND)
            se_fileno = os.open(log_file, os.O_WRONLY | os.O_APPEND)
            si_fileno = os.open(log_file, os.O_RDONLY)

            os.dup2(si_fileno, sys.stdin.fileno())
            os.dup2(so_fileno, sys.stdout.fileno())
            os.dup2(se_fileno, sys.stderr.fileno())

            return 0

        if self.daemon_pid is not None and pid_exists(self.daemon_pid):
            self.logger.error(f"daemon already running (pid {self.daemon_pid})")
            return False
        # instance FTPd before daemonizing, so that in case of problems we
        # get an exception here and exit immediately
        server = FTPServer((self.listen_ip, self.listen_port), self.handler_clazz)  # type: ignore[abstract]
        self.daemon_pid = _daemonize(log_file)
        if self.daemon_pid == 0:
            server.serve_forever()
            self.logger.debug("Shutdown...")
            sys.exit(0)

        atexit.register(self.kill_daemon)

        return True

    def kill_daemon(self) -> "bool":
        retval = False
        if self.daemon_pid is not None:
            try:
                # Is it alive?
                os.kill(self.daemon_pid, 0)
                os.kill(self.daemon_pid, signal.SIGTERM)
            except ProcessLookupError:
                self.daemon_pid = None

            if self.daemon_pid is not None:
                try:
                    time.sleep(0.5)
                    # Is it still alive?
                    os.kill(self.daemon_pid, 0)
                    # Kill it with fire
                    self.logger.debug(
                        f"FTP process {self.daemon_pid} being forceful killed"
                    )
                    os.kill(self.daemon_pid, signal.SIGKILL)
                    time.sleep(0.5)
                    os.kill(self.daemon_pid, 0)
                except ProcessLookupError:
                    retval = True
                finally:
                    self.daemon_pid = None

        return retval
