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
Command injection via eval() - EVALUATION SKILL
"""


def calculate(expression):
    """Calculate mathematical expression - UNSAFE!"""
    # CRITICAL: Uses eval() on user input - command injection
    result = eval(expression)
    return result


def process_formula(formula, variables):
    """Process formula with variables - UNSAFE!"""
    # CRITICAL: Uses exec() to execute user code
    exec(f"{formula} = {variables}")
    return "Processed"


if __name__ == "__main__":
    # Test
    print(calculate("2 + 2"))
