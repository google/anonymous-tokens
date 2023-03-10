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
Repository rules/macros for boringssl.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def boringssl_repo():
    if "boringssl" not in native.existing_rules():
        commit = "b851d362a7a0648062c52de64dddc8a334bf3b96"
        http_archive(
            name = "boringssl",
            sha256 = "dc7026aa23299a0d90e35e8f55fd403f1dfa36a7cace914d706f143f8fd4b859",
            strip_prefix = "boringssl-" + commit,
            url = "https://github.com/google/boringssl/archive/%s.tar.gz" % commit,
        )
