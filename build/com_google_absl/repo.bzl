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
Repository rules/macros for com_google_absl.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def com_google_absl_repo():
    if "com_google_absl" not in native.existing_rules():
        http_archive(
            name = "com_google_absl",
            sha256 = "8abdfaa027b6e725d1710e1798c8821d14d7dd3d78ffdf37866213601d9111db",
            strip_prefix = "abseil-cpp-e968256406fd7898d7fde880e31e54b041d32a7e",
            url = "https://github.com/abseil/abseil-cpp/archive/e968256406fd7898d7fde880e31e54b041d32a7e.zip",
        )
