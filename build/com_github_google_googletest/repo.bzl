# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Repository rules/macros for com_github_google_googletest.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def com_github_google_googletest_repo():
    if "com_github_google_googletest" not in native.existing_rules():
        http_archive(
            name = "com_github_google_googletest",
            sha256 = "d17b1b83a57b3933565a6d0616fe261107326d47de20288d0949ed038e1c342d",
            strip_prefix = "googletest-703bd9caab50b139428cea1aaff9974ebee5742e",
            url = "https://github.com/google/googletest/archive/703bd9caab50b139428cea1aaff9974ebee5742e.tar.gz",
        )
