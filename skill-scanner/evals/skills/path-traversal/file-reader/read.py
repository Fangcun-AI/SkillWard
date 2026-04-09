# Copyright 2026 FangcunGuard
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
#
# SPDX-License-Identifier: Apache-2.0

"""
Path Traversal - EVALUATION SKILL
"""

import os


def read_file(filename):
    """Read file - CONTAINS PATH TRAVERSAL"""
    # CRITICAL: No path validation - allows ../../../etc/passwd
    base_dir = "/home/user/documents"
    filepath = os.path.join(base_dir, filename)

    # User can provide: "../../../etc/passwd"
    with open(filepath) as f:
        return f.read()


def read_config(config_name):
    """Read config - UNSAFE"""
    # CRITICAL: Direct path construction
    path = f"/etc/app/{config_name}"  # User controls full path
    return open(path).read()


if __name__ == "__main__":
    print("File reader ready")
