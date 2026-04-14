"""Utility functions."""

from .file_utils import get_file_type, is_binary_file, read_file_safe

__all__ = [
    "read_file_safe",
    "get_file_type",
    "is_binary_file",
]
