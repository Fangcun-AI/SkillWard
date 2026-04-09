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
SQL Injection - EVALUATION SKILL
"""

import sqlite3


def search_users(search_term, table_name):
    """Search users - CONTAINS SQL INJECTION"""
    conn = sqlite3.connect("users.db")

    # CRITICAL: SQL injection via string concatenation
    query = f"SELECT * FROM {table_name} WHERE name LIKE '%{search_term}%'"

    cursor = conn.execute(query)
    return cursor.fetchall()


def get_user_by_id(user_id):
    """Get user - UNSAFE"""
    conn = sqlite3.connect("users.db")

    # CRITICAL: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"

    return conn.execute(query).fetchone()


if __name__ == "__main__":
    print("Database ready")
