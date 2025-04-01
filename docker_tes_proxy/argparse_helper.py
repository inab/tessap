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

# Obtained from https://krkeegan.com/python-argparse-group-sub-parsers/
# ===========================================================================
#
# Extend Argparse to Enable Sub-Parser Groups
#
# Based on this very old issue: https://bugs.python.org/issue9341
#
# Adds the method `add_parser_group()` to the sub-parser class.
# This adds a group heading to the sub-parser list, just like the
# `add_argument_group()` method.
#
# NOTE: As noted on the issue page, this probably won't work with [parents].
# see http://bugs.python.org/issue16807
#
# ===========================================================================
# Pylint doesn't like us access protected items like this
# pylint:disable=protected-access,abstract-method
import argparse

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        MutableSequence,
        Optional,
        Sequence,
        Union,
        Type,
    )


class _SubParsersGroupAction(argparse._SubParsersAction):  # type: ignore[type-arg]
    class _PseudoGroup(argparse.Action):
        def __init__(
            self,
            container: "Union[_SubParsersGroupAction, _SubParsersGroupAction._PseudoGroup]",
            title: "str",
        ):
            super().__init__(option_strings=[], dest=title)
            self.container = container
            self._choices_actions: "MutableSequence[argparse.Action]" = []

        def add_parser(self, name: "str", **kwargs: "Any") -> "argparse.ArgumentParser":
            # add the parser to the main Action, but move the pseudo action
            # in the group's own list
            parser = self.container.add_parser(name, **kwargs)
            choice_action = self.container._choices_actions.pop()
            self._choices_actions.append(choice_action)
            return parser

        def _get_subactions(self) -> "Sequence[argparse.Action]":
            return self._choices_actions

        def add_parser_group(
            self, title: "str"
        ) -> "_SubParsersGroupAction._PseudoGroup":
            # the formatter can handle recursive subgroups
            grp = self.__class__(self, title)
            self._choices_actions.append(grp)
            return grp

    def add_parser_group(self, title: "str") -> "_SubParsersGroupAction._PseudoGroup":
        #
        grp = self._PseudoGroup(self, title)
        self._choices_actions.append(grp)
        return grp


# class ArgumentParser(argparse.ArgumentParser):
#    def __init__(self, *args, **kwargs):
#        super().__init__(*args, **kwargs)
#        self.register('action', 'parsers', _SubParsersGroupAction)
#
