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
Safe file validator - EVALUATION SKILL (SAFE)
"""

import mimetypes
import os

ALLOWED_EXTENSIONS = {".txt", ".md", ".json", ".csv"}


def validate_file(filepath):
    """Safely validate file - SAFE IMPLEMENTATION"""
    # Safe: Uses basename to prevent path traversal
    filename = os.path.basename(filepath)

    # Check extension
    _, ext = os.path.splitext(filename)
    if ext not in ALLOWED_EXTENSIONS:
        return {"valid": False, "reason": "Invalid extension"}

    # Safe: Restricts to specific directory
    safe_dir = os.path.expanduser("~/documents/")
    full_path = os.path.join(safe_dir, filename)

    # Check if file exists
    if not os.path.exists(full_path):
        return {"valid": False, "reason": "File not found"}

    # Check file size
    size = os.path.getsize(full_path)
    if size > 10 * 1024 * 1024:  # 10MB limit
        return {"valid": False, "reason": "File too large"}

    return {"valid": True, "filename": filename, "size": size}


def check_mime_type(filepath):
    """Check MIME type safely"""
    # Safe: Uses mimetypes module
    mime_type, _ = mimetypes.guess_type(filepath)
    return mime_type


if __name__ == "__main__":
    print(validate_file("test.txt"))
