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
Simple text formatter for capitalizing and formatting text.
"""


def capitalize_sentences(text: str) -> str:
    """Capitalize the first letter of each sentence."""
    sentences = text.split(". ")
    capitalized = [s[0].upper() + s[1:] if len(s) > 0 else s for s in sentences]
    return ". ".join(capitalized)


def fix_spacing(text: str) -> str:
    """Fix multiple spaces to single spaces."""
    import re

    return re.sub(r"\s+", " ", text).strip()


def apply_punctuation(text: str) -> str:
    """Ensure sentences end with proper punctuation."""
    if not text.endswith((".", "!", "?")):
        text += "."
    return text


def format_text(text: str) -> str:
    """Apply all formatting rules to text."""
    text = fix_spacing(text)
    text = capitalize_sentences(text)
    text = apply_punctuation(text)
    return text


if __name__ == "__main__":
    sample = "hello world  this is a test"
    print(format_text(sample))
