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

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Union,
    )

# Needed for the monkey patching
import ftplib

import ftputil
import ftputil.session

from . import (
    AbstractFileServerForTES,
)


# Monkeypatching approach borrowed from WfExS-backend code
# This monkeypatching approach is needed to fix the cases where the FTP
# server does not support FEAT command, or it is not allowed.
# For instance ftp.broadinstitute.org (tested on 2025-05-19)
def _maybe_send_opts_utf8_on_patched(session: "ftplib.FTP", encoding: "str") -> None:
    """
    If the requested encoding is UTF-8 and the server supports the `UTF8`
    feature, send "OPTS UTF8 ON".

    See https://datatracker.ietf.org/doc/html/rfc2640.html .
    """
    if ((encoding is None) and ftputil.path_encoding.RUNNING_UNDER_PY39_AND_UP) or (
        encoding in ["UTF-8", "UTF8", "utf-8", "utf8"]
    ):
        server_supports_opts_utf8_on = False
        try:
            feat_output = session.sendcmd("FEAT")
            for line in feat_output.splitlines():
                # The leading space is important. See RFC 2640.
                if line.upper().rstrip() == " UTF8":
                    server_supports_opts_utf8_on = True
        except ftplib.error_perm:
            # FEAT is not supported
            pass
        if server_supports_opts_utf8_on:
            session.sendcmd("OPTS UTF8 ON")


ftputil.session._maybe_send_opts_utf8_on = _maybe_send_opts_utf8_on_patched  # type: ignore[attr-defined]


class ExternalFTPServerForTES(AbstractFileServerForTES):

    def __init__(
        self,
        public_name: "str" = "localhost",
        public_port: "Optional[int]" = 21,
        listen_ip: "str" = "::",
        listen_port: "int" = 2121,
        user_ro: "str" = AbstractFileServerForTES.DEFAULT_USER_RO,
        user_ro_pass: "Optional[str]" = None,
        user_rw: "str" = AbstractFileServerForTES.DEFAULT_USER_RW,
        user_rw_pass: "Optional[str]" = None,
        user_wo: "str" = AbstractFileServerForTES.DEFAULT_USER_WO,
        user_wo_pass: "Optional[str]" = None,
        ro_rel_dir: "str" = AbstractFileServerForTES.DEFAULT_RO_REL_DIR,
        rw_rel_dir: "str" = AbstractFileServerForTES.DEFAULT_RW_REL_DIR,
        wo_rel_dir: "str" = AbstractFileServerForTES.DEFAULT_WO_REL_DIR,
        remote_path_prefix: "str" = "",
        create_session_rel_dir: "bool" = True,
        public_ro_user: "Optional[str]" = None,
        public_ro_pass: "Optional[str]" = None,
        public_rw_user: "Optional[str]" = None,
        public_rw_pass: "Optional[str]" = None,
        public_wo_user: "Optional[str]" = None,
        public_wo_pass: "Optional[str]" = None,
        public_remote_path_prefix: "Optional[str]" = None,
        remote_retries: "int" = AbstractFileServerForTES.DEFAULT_MAX_RETRIES,
        public_remote_retries: "int" = AbstractFileServerForTES.DEFAULT_MAX_RETRIES,
    ):
        super().__init__(
            public_name=public_name,
            public_port=public_port,
            listen_ip=listen_ip,
            listen_port=listen_port,
            user_ro=user_ro,
            user_ro_pass=user_ro_pass,
            user_rw=user_rw,
            user_rw_pass=user_rw_pass,
            user_wo=user_wo,
            user_wo_pass=user_wo_pass,
            ro_rel_dir=ro_rel_dir,
            rw_rel_dir=rw_rel_dir,
            wo_rel_dir=wo_rel_dir,
            remote_path_prefix=remote_path_prefix,
            create_session_rel_dir=create_session_rel_dir,
            public_ro_user=public_ro_user,
            public_ro_pass=public_ro_pass,
            public_rw_user=public_rw_user,
            public_rw_pass=public_rw_pass,
            public_wo_user=public_wo_user,
            public_wo_pass=public_wo_pass,
            public_remote_path_prefix=public_remote_path_prefix,
            remote_retries=remote_retries,
            public_remote_retries=public_remote_retries,
        )

        self.session_factory = ftputil.session.session_factory(
            port=self.listen_port,
            encoding="UTF-8",
            # debug_level=2,
        )

        # Next one is not used, it is only for completeness
        self.public_session_factory = ftputil.session.session_factory(
            port=self.public_port,
            encoding="UTF-8",
            # debug_level=2,
        )

    @property
    def supports_dirs(self) -> "bool":
        return True

    def _download_dir(
        self,
        ftp_host: "ftputil.FTPHost",
        download_path: "str",
        utdPath: "pathlib.Path",
    ) -> "Sequence[pathlib.Path]":
        """
        This method mirrors a whole directory into a destination one
        dfdPath must be absolute
        """
        self.logger.debug(f"Get files list {download_path}")

        utdPath.mkdir(parents=True, exist_ok=True)
        retries = self.public_remote_retries
        directories: "MutableSequence[Tuple[str, str]]" = []
        downloaded_path: "MutableSequence[pathlib.Path]" = []
        while retries > 0:
            try:
                directories = []
                downloaded_path = []
                names = ftp_host.listdir(download_path)
                for name in names:
                    full_name = ftp_host.path.join(download_path, name)
                    if ftp_host.path.isfile(full_name):
                        dest_file = utdPath / name
                        ftp_host.download_if_newer(full_name, dest_file.as_posix())
                        downloaded_path.append(dest_file)
                    elif ftp_host.path.isdir(full_name):
                        directories.append((full_name, name))
            except Exception as e:
                retries -= 1
                self.logger.debug("Left {} tries".format(retries))
                if retries == 0:
                    raise e

        if downloaded_path:
            self.logger.debug(
                f"({len(downloaded_path)}) {download_path} -> " f"{utdPath}"
            )

        for full_name, name in directories:
            dest_dir = utdPath / name
            fetched = self._download_dir(ftp_host, full_name, dest_dir)
            downloaded_path.extend(fetched)

        self.logger.debug(f"Files from {download_path} downloaded to {downloaded_path}")

        return downloaded_path

    def _download_file(
        self,
        ftp_host: "ftputil.FTPHost",
        download_path: "str",
        local_file_path: "pathlib.Path",
    ) -> "pathlib.Path":
        """
        download_path must be absolute
        """

        self.logger.debug(f"Get file {download_path}")

        downloaded = ftp_host.download_if_newer(
            download_path, local_file_path.as_posix()
        )

        if downloaded:
            self.logger.debug("Loading: Complete")
        else:
            self.logger.debug("Nothing new to download")

        self.logger.debug(f"File {download_path} downloaded to {local_file_path}")

        return local_file_path

    def _download(
        self,
        download_url: "str",
        local_path_instance: "pathlib.Path",
    ) -> "Union[pathlib.Path, Sequence[pathlib.Path]]":
        """
        This method returns a pathlib.Path when a file is fetched
        and a list of pathlib.Path when it is a directory
        """
        parsed_ftp_url = urllib.parse.urlparse(download_url)
        download_path = parsed_ftp_url.path
        with ftputil.FTPHost(
            parsed_ftp_url.hostname,
            parsed_ftp_url.username,
            parsed_ftp_url.password,
            session_factory=self.session_factory,
        ) as ftp_host:
            # Changing to absolute path
            if not ftp_host.path.isabs(download_path):
                download_path = ftp_host.path.abspath(download_path)

            retval: "Union[pathlib.Path, Sequence[pathlib.Path]]"
            if ftp_host.path.isdir(download_path):
                retval = self._download_dir(
                    ftp_host, download_path, local_path_instance
                )
            else:
                retval = self._download_file(
                    ftp_host, download_path, local_path_instance
                )

        return retval

    def _upload_dir(
        self,
        ftp_host: "ftputil.FTPHost",
        local_path_instance: "pathlib.Path",
        upload_path: "str",
        checks: "bool" = True,
    ) -> "int":
        # Be sure the destination directory does exist
        created = 0
        parent_upload_path = ftp_host.path.dirname(upload_path)
        if not ftp_host.path.exists(parent_upload_path):
            ftp_host.makedirs(parent_upload_path, exist_ok=False)
            created += 1
        elif not ftp_host.path.isdir(parent_upload_path):
            raise Exception(f"Parent path of {upload_path} is a file")

        for local_item in local_path_instance.iterdir():
            created += self._upload(
                ftp_host, local_item, upload_path + "/" + local_item.name, checks=False
            )

        return created

    def _upload_file(
        self,
        ftp_host: "ftputil.FTPHost",
        local_path_instance: "pathlib.Path",
        upload_path: "str",
        checks: "bool" = True,
    ) -> "int":
        # Be sure the destination directory does exist
        if checks:
            parent_upload_path = ftp_host.path.dirname(upload_path)
            if not ftp_host.path.exists(parent_upload_path):
                ftp_host.makedirs(parent_upload_path, exist_ok=False)
            elif not ftp_host.path.isdir(parent_upload_path):
                raise Exception(f"Parent path of {upload_path} is a file")

        ftp_host.upload(local_path_instance.as_posix(), upload_path)

        return 1

    def _upload(
        self,
        ftp_host: "ftputil.FTPHost",
        local_path_instance: "pathlib.Path",
        upload_path: "str",
        checks: "bool" = True,
    ) -> "int":
        if checks and not ftp_host.path.isabs(upload_path):
            upload_path = ftp_host.path.abspath(upload_path)

        if local_path_instance.is_dir():
            return self._upload_dir(
                ftp_host, local_path_instance, upload_path, checks=checks
            )
        else:
            return self._upload_file(
                ftp_host, local_path_instance, upload_path, checks=checks
            )

    def add_ro_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        if isinstance(local_path, pathlib.Path):
            local_path_instance = local_path
        else:
            local_path_instance = pathlib.Path(local_path)
        if local_path_instance.is_file():
            prefix = "file_"
            postfix = ""
        else:
            prefix = "dir_"
            postfix = "/"
        rand_name = prefix + str(uuid.uuid4())
        ftp_path = self.ro_rel_dir + "/" + rand_name
        public_ftp_path = self.public_ro_rel_dir + "/" + rand_name

        with ftputil.FTPHost(
            self.listen_ip,
            self.user_ro,
            self.user_ro_pass,
            session_factory=self.session_factory,
        ) as ftp_host:
            self._upload(ftp_host, local_path_instance, ftp_path)

        public_netloc = self.public_name + ":" + str(self.public_port)
        if self.public_ro_user is not None:
            userpart = urllib.parse.quote(self.public_ro_user)
            if self.public_ro_pass is not None:
                userpart += ":" + urllib.parse.quote(self.public_ro_pass)
            public_netloc = userpart + "@" + public_netloc

        return urllib.parse.urlunparse(
            (
                "ftp",
                public_netloc,
                "/" + public_ftp_path + postfix,
                "",
                "",
                "",
            )
        )

    def add_rw_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        if isinstance(local_path, pathlib.Path):
            local_path_instance = local_path
        else:
            local_path_instance = pathlib.Path(local_path)
        if local_path_instance.is_file():
            prefix = "file_"
            postfix = ""
        else:
            prefix = "dir_"
            postfix = "/"
        rand_name = prefix + str(uuid.uuid4())
        ftp_path = self.rw_rel_dir + "/" + rand_name
        public_ftp_path = self.public_rw_rel_dir + "/" + rand_name

        # Same as read-only case
        with ftputil.FTPHost(
            self.listen_ip,
            self.user_rw,
            self.user_rw_pass,
            session_factory=self.session_factory,
        ) as ftp_host:
            self._upload(ftp_host, local_path_instance, ftp_path)

        netloc = self.listen_ip + ":" + str(self.listen_port)
        if self.user_rw is not None:
            userpart = urllib.parse.quote(self.user_rw)
            if self.user_rw_pass is not None:
                userpart += ":" + urllib.parse.quote(self.user_rw_pass)
            netloc = userpart + "@" + netloc

        ftp_url = urllib.parse.urlunparse(
            (
                "ftp",
                netloc,
                "/" + ftp_path + postfix,
                "",
                "",
                "",
            )
        )

        public_netloc = self.public_name + ":" + str(self.public_port)
        if self.public_rw_user is not None:
            userpart = urllib.parse.quote(self.public_rw_user)
            if self.public_rw_pass is not None:
                userpart += ":" + urllib.parse.quote(self.public_rw_pass)
            public_netloc = userpart + "@" + public_netloc

        public_ftp_url = urllib.parse.urlunparse(
            (
                "ftp",
                public_netloc,
                "/" + public_ftp_path + postfix,
                "",
                "",
                "",
            )
        )

        self.w_mapping[ftp_url] = local_path_instance.resolve()

        return public_ftp_url

    def add_wo_volume(self, local_path: "Union[str, os.PathLike[str]]") -> "str":
        rand_name = str(uuid.uuid4())

        ftp_path = self.wo_rel_dir + "/" + rand_name
        public_ftp_path = self.public_wo_rel_dir + "/" + rand_name

        netloc = self.listen_ip + ":" + str(self.listen_port)
        if self.user_wo is not None:
            userpart = urllib.parse.quote(self.user_wo)
            if self.user_wo_pass is not None:
                userpart += ":" + urllib.parse.quote(self.user_wo_pass)
            netloc = userpart + "@" + netloc

        ftp_url = urllib.parse.urlunparse(
            (
                "ftp",
                netloc,
                "/" + ftp_path,
                "",
                "",
                "",
            )
        )

        public_netloc = self.public_name + ":" + str(self.public_port)
        if self.public_wo_user is not None:
            userpart = urllib.parse.quote(self.public_wo_user)
            if self.public_wo_pass is not None:
                userpart += ":" + urllib.parse.quote(self.public_wo_pass)
            public_netloc = userpart + "@" + public_netloc

        public_ftp_url = urllib.parse.urlunparse(
            (
                "ftp",
                public_netloc,
                "/" + public_ftp_path,
                "",
                "",
                "",
            )
        )

        self.w_mapping[ftp_url] = pathlib.Path(local_path).resolve()

        return public_ftp_url

    def synchronize(self) -> "None":
        # Bring back contents
        for ftp_url, local_path in self.w_mapping.items():
            # First, remove the destination
            if local_path.exists():
                if local_path.is_dir():
                    shutil.rmtree(local_path, ignore_errors=True)
                else:
                    local_path.unlink()

            try:
                self._download(ftp_url, local_path)
            except:
                self.logger.exception(
                    f"URL {ftp_url} could not be downloaded to {local_path} (see stack trace below)"
                )

        # Last, clear it!
        self.w_mapping = dict()

    def daemonize(self, log_file: "str" = "/dev/null") -> "bool":
        return True

    def kill_daemon(self) -> "bool":
        return True
