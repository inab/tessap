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

import inspect
import json
import logging
import urllib.parse

from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        MutableMapping,
        Optional,
        Tuple,
    )

    from typing_extensions import (
        Final,
    )
    from dxf import (
        DXFBase,
    )

    import requests

import dxf


class Credentials(NamedTuple):
    domain: "Optional[str]" = None
    username: "Optional[str]" = None
    password: "Optional[str]" = None


class DockerHelperException(Exception):
    pass


class DockerRegistryHelper:
    """
    This code is based on what it was developed at https://github.com/inab/WfExS-backend/blob/a1c619044db35d34972ba04fb527d71276812790/wfexs_backend/utils/docker.py
    """

    DEFAULT_DOCKER_REGISTRY: "Final[str]" = "docker.io"
    DOCKER_REGISTRY: "Final[str]" = "registry-1.docker.io"

    DEFAULT_ALIAS: "Final[str]" = "latest"

    def __init__(self) -> None:
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        # Default credentials are no credentials
        self.creds: "MutableMapping[Optional[str], Credentials]" = {
            None: Credentials(None, None, None)
        }

        # These credentials are used only when querying
        self.choose_domain()

    def add_creds(
        self, username: "str", password: "str", domain: "Optional[str]" = None
    ) -> None:
        self.creds[domain] = Credentials(
            domain=domain, username=username, password=password
        )

    def choose_domain(self, domain_name: "Optional[str]" = None) -> None:
        if domain_name not in self.creds:
            domain_name = None

        self.domain = self.creds[domain_name]

    def _auth(self, dxf: "DXFBase", response: "requests.Response") -> None:
        """Helper method for DXF machinery"""

        dxf.authenticate(
            self.domain.username,
            self.domain.password,
            actions=["pull"],
            response=response,
        )

    def query_inspect(self, tag: "str") -> "Tuple[str, Mapping[str, Any]]":
        parsedTag = urllib.parse.urlparse(tag)
        if parsedTag.scheme == "":
            docker_tag = "docker://" + tag
            parsedTag = urllib.parse.urlparse(docker_tag)
        elif parsedTag.scheme not in ("http", "https", "ftp", "docker"):
            docker_tag = f"docker://{self.DEFAULT_DOCKER_REGISTRY}/{tag}"
            parsedTag = urllib.parse.urlparse(docker_tag)
        else:
            self.logger.debug(f"Parsed as {parsedTag}")
            docker_tag = tag

        if parsedTag.scheme != "docker":
            raise DockerHelperException(f"Unable to parse {tag} as a Docker tag")

        # Deciding the partial repo and alias
        if parsedTag.path == "":
            pathToParse = parsedTag.netloc
        else:
            pathToParse = parsedTag.netloc + parsedTag.path

        splitSep = "@sha256:"
        splitPos = pathToParse.rfind(splitSep)
        if splitPos == -1:
            splitSep = ":"
            splitPos = pathToParse.rfind(splitSep)
        else:
            # We need to include 'sha256:' prefix in alias
            splitSep = "@"

        if splitPos != -1:
            repo = pathToParse[0:splitPos]
            alias = pathToParse[splitPos + len(splitSep) :]
        else:
            repo = pathToParse
            alias = self.DEFAULT_ALIAS

        # Deciding the registry server and finishing adjustment of repo
        registry = None
        if "." not in repo:
            registry = self.DEFAULT_DOCKER_REGISTRY
        else:
            if repo[0] == "/":
                repo = repo[1:]

            if "/" in repo:
                registry, repo = repo.split("/", 1)
            else:
                # FIXME!!!!
                registry = self.DEFAULT_DOCKER_REGISTRY

        # Last repo adjustment, in case it is a 'library' one
        if "/" not in repo:
            repo = "library/" + repo

        registry_server = registry
        if registry == self.DEFAULT_DOCKER_REGISTRY:
            registry_server = self.DOCKER_REGISTRY

        dxf_obj = dxf.DXF(registry_server, repo, self._auth)

        platform = "linux/amd64"
        _, dcd = dxf_obj._get_alias(alias, None, False, False, False, True, False, platform, True)  # type: ignore[no-untyped-call]

        manifest_str = dxf_obj.get_manifest(alias, platform=platform)
        manifest = json.loads(cast("str", manifest_str))

        blob_iter, blob_size = dxf_obj.pull_blob(
            manifest["config"]["digest"], size=True
        )
        config_blob = b""
        for chunk in blob_iter:
            config_blob += cast("bytes", chunk)

        config = json.loads(config_blob)
        inspect_tag = repo + "@" + dcd
        inspect_res = {
            "Id": manifest["config"]["digest"],
            "RepoTags": [repo + ":" + alias],
            "RepoDigests": [inspect_tag],
            "Parent": "",
            "Comment": "",
            "Created": config["created"],
            "DockerVersion": config["docker_version"],
            "Author": "",
            "Config": config["config"],
            "Architecture": config["architecture"],
            "Os": config["os"],
            "Size": 0,
            "GraphDriver": {
                "Data": None,
                "Name": "overlayfs",
            },
            "RootFS": {
                "Type": config["rootfs"]["type"],
                "Layers": config["rootfs"]["diff_ids"],
            },
            "Metadata": {
                "LastTagTime": "0001-01-01T00:00:00Z",
            },
        }

        return inspect_tag, inspect_res
