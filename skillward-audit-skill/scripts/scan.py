#!/usr/bin/env python3
"""SkillWard audit client — upload a skill bundle and stream scan results."""
from __future__ import annotations

import argparse
import io
import json
import os
import secrets
import socket
import sys
import threading
import time
import zipfile
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from typing import Iterator
from urllib.error import URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

DEFAULT_API_BASE = "https://skillward.fangcunleap.com"
DEFAULT_TIMEOUTS = {
    "static": 60,
    "sandbox": 900,
    "deep": 1100,
}

EXIT_OK = 0
EXIT_NO_REPORT = 2
EXIT_NO_SKILL_MD = 3
EXIT_UNREACHABLE = 4
EXIT_SERVER_ERROR = 5
EXIT_TIMEOUT = 6

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv"}
SKIP_FILES = {".DS_Store", "Thumbs.db"}
SKIP_SUFFIX = {".pyc"}
LARGE_FILE_WARN = 50 * 1024 * 1024

DEPTH_FLAGS = {
    "static":  {"use_llm": True, "use_runtime": False, "enable_after_tool": False},
    "sandbox": {"use_llm": True, "use_runtime": True,  "enable_after_tool": False},
    "deep":    {"use_llm": True, "use_runtime": True,  "enable_after_tool": True},
}


class UnreachableError(Exception):
    pass


class ServerError(Exception):
    pass


def detect_input(path: Path) -> str:
    if path.is_dir():
        return "folder"
    s = path.name.lower()
    if s.endswith(".zip"):
        return "zip"
    if s.endswith(".tar.gz") or s.endswith(".tgz"):
        return "targz"
    raise ValueError(f"Unsupported input: {path} (expected folder, .zip, .tar.gz, .tgz)")


def has_skill_md(folder: Path) -> bool:
    for _ in folder.rglob("SKILL.md"):
        return True
    return False


def build_zip_from_folder(folder: Path, quiet: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            rel_root = Path(root).relative_to(folder)
            for f in files:
                if f in SKIP_FILES:
                    continue
                if Path(f).suffix in SKIP_SUFFIX:
                    continue
                src = Path(root) / f
                rel = (rel_root / f).as_posix()
                try:
                    sz = src.stat().st_size
                except OSError:
                    continue
                if sz > LARGE_FILE_WARN and not quiet:
                    print(f"[warn] large file {rel} ({sz / 1024 / 1024:.1f} MB)",
                          file=sys.stderr)
                info = zipfile.ZipInfo(rel)
                info.flag_bits |= 0x800
                info.compress_type = zipfile.ZIP_DEFLATED
                with src.open("rb") as src_f:
                    zf.writestr(info, src_f.read())
    return buf.getvalue()


def build_multipart(boundary: str, field: str, filename: str, payload: bytes) -> bytes:
    return b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode("utf-8"),
        b"Content-Type: application/octet-stream\r\n\r\n",
        payload,
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])


def post_upload(api_base: str, payload: bytes, filename: str) -> dict:
    url = urlparse(api_base)
    conn_cls = HTTPSConnection if url.scheme == "https" else HTTPConnection
    boundary = secrets.token_hex(16)
    body = build_multipart(boundary, "files", filename, payload)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
        "Accept": "application/json",
    }
    host = url.hostname or ""
    port = url.port
    try:
        conn = conn_cls(host, port, timeout=120)
        conn.request("POST", "/api/scan/upload-folder", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        if resp.status >= 500:
            raise ServerError(f"HTTP {resp.status}: {data[:500].decode(errors='replace')}")
        if resp.status >= 400:
            raise ServerError(f"HTTP {resp.status}: {data[:500].decode(errors='replace')}")
        return json.loads(data)
    except (socket.gaierror, ConnectionRefusedError) as e:
        raise UnreachableError(str(e))
    except OSError as e:
        raise UnreachableError(str(e))


def stream_scan(
    api_base: str, skill_path: str, depth_flags: dict, lang: str,
    total_timeout: int, quiet: bool = False,
) -> Iterator[dict]:
    params = {
        "skill_path": skill_path,
        "policy": "balanced",
        "use_llm": str(depth_flags["use_llm"]).lower(),
        "use_runtime": str(depth_flags["use_runtime"]).lower(),
        "enable_after_tool": str(depth_flags["enable_after_tool"]).lower(),
        "lang": lang,
    }
    url = f"{api_base.rstrip('/')}/api/scan/stream?{urlencode(params)}"
    req = Request(url, headers={"Accept": "text/event-stream"})
    try:
        resp = urlopen(req, timeout=650)
    except (URLError, socket.gaierror, ConnectionRefusedError) as e:
        raise UnreachableError(str(e))

    start = time.monotonic()
    last_event = [time.monotonic()]
    stopped = threading.Event()

    def heartbeat():
        while not stopped.wait(10):
            silent = time.monotonic() - last_event[0]
            if silent >= 30 and not quiet:
                elapsed = int(time.monotonic() - start)
                print(f"[heartbeat] still scanning... {elapsed}s elapsed",
                      file=sys.stderr, flush=True)
                last_event[0] = time.monotonic()

    threading.Thread(target=heartbeat, daemon=True).start()

    buf = bytearray()
    try:
        while True:
            if time.monotonic() - start > total_timeout:
                raise TimeoutError(f"Exceeded {total_timeout}s timeout")
            try:
                chunk = resp.read(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            while b"\n\n" in buf:
                frame, _, rest = buf.partition(b"\n\n")
                buf = bytearray(rest)
                data_lines = []
                for line in frame.split(b"\n"):
                    line = line.rstrip(b"\r")
                    if line.startswith(b"data:"):
                        data_lines.append(line[5:].lstrip())
                if not data_lines:
                    continue
                raw = b"\n".join(data_lines).decode("utf-8", errors="replace")
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                last_event[0] = time.monotonic()
                yield event
    finally:
        stopped.set()
        resp.close()


def format_progress_line(event: dict) -> str:
    t = event.get("type", "?")
    text = event.get("text", "")
    ts = event.get("timestamp", "")
    stage = event.get("stage")
    stage_tag = f"[stage {stage}] " if stage else ""
    return f"{ts} {stage_tag}{t}: {text}".rstrip()


def format_summary_line(report: dict) -> str:
    verdict = report.get("verdict", "Unknown")
    name = report.get("skill_name", "unknown")
    lat = (report.get("latency") or {}).get("total")
    lat_s = f"{lat:.1f}s" if isinstance(lat, (int, float)) else "?"
    warnings = report.get("warnings") or []
    return f"VERDICT: {verdict} | {name} | {lat_s} | {len(warnings)} warning(s)"


def main() -> int:
    p = argparse.ArgumentParser(description="SkillWard audit client")
    p.add_argument("input_path", type=Path,
                   help="Skill folder (must contain SKILL.md) or .zip / .tar.gz archive")
    p.add_argument("--lang", choices=["zh", "en"], default="en")
    p.add_argument("--depth", choices=list(DEPTH_FLAGS), default="sandbox")
    p.add_argument("--api-base",
                   default=os.environ.get("SKILLWARD_API_BASE", DEFAULT_API_BASE))
    p.add_argument("--out", type=Path, default=None,
                   help="Report path. Default: <input_dir>/skillward-report.json "
                        "(folders) or <archive>.skillward-report.json (archives).")
    p.add_argument("--timeout", type=int, default=None,
                   help="Total scan timeout in seconds. "
                        "Default depends on --depth (static=60, sandbox=900, deep=1100).")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    args.input_path = args.input_path.expanduser()
    if args.timeout is None:
        args.timeout = DEFAULT_TIMEOUTS[args.depth]

    try:
        kind = detect_input(args.input_path)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return EXIT_NO_SKILL_MD

    if args.out is None:
        if kind == "folder":
            args.out = args.input_path / "skillward-report.json"
        else:
            args.out = args.input_path.with_suffix(".skillward-report.json")
    else:
        args.out = args.out.expanduser()

    if kind == "folder":
        if not has_skill_md(args.input_path):
            print(f"No SKILL.md found in {args.input_path} — not a skill bundle",
                  file=sys.stderr)
            return EXIT_NO_SKILL_MD
        if not args.quiet:
            print(f"[upload] zipping folder {args.input_path}...", file=sys.stderr)
        try:
            payload = build_zip_from_folder(args.input_path, quiet=args.quiet)
        except Exception as e:
            print(f"Failed to build zip: {e}", file=sys.stderr)
            return EXIT_SERVER_ERROR
        filename = args.input_path.name + ".zip"
        if not args.quiet:
            print(f"[upload] zip size {len(payload) / 1024:.1f} KB, posting...",
                  file=sys.stderr)
    else:
        try:
            payload = args.input_path.read_bytes()
        except OSError as e:
            print(f"Cannot read {args.input_path}: {e}", file=sys.stderr)
            return EXIT_NO_SKILL_MD
        filename = args.input_path.name

    up = None
    for attempt in (1, 2):
        try:
            up = post_upload(args.api_base, payload, filename)
            break
        except UnreachableError as e:
            print(f"Cannot reach {args.api_base}. Check network or SKILLWARD_API_BASE. ({e})",
                  file=sys.stderr)
            return EXIT_UNREACHABLE
        except ServerError as e:
            if attempt == 1:
                print(f"[warn] server error, retrying in 3s: {e}", file=sys.stderr)
                time.sleep(3)
                continue
            print(f"Server error: {e}", file=sys.stderr)
            return EXIT_SERVER_ERROR
    if up is None:
        return EXIT_SERVER_ERROR

    skill_path = up.get("skill_path")
    skill_name = up.get("skill_name", "unknown")
    if not skill_path:
        print(f"Upload response missing skill_path: {up}", file=sys.stderr)
        return EXIT_SERVER_ERROR
    if not args.quiet:
        print(f"[upload] ok: skill_name={skill_name}, skill_path={skill_path}",
              file=sys.stderr)

    report = None
    try:
        for event in stream_scan(
            args.api_base, skill_path, DEPTH_FLAGS[args.depth],
            args.lang, args.timeout, quiet=args.quiet,
        ):
            t = event.get("type")
            if t == "report":
                data = event.get("data") or {}
                report = data.get("report") if isinstance(data, dict) else None
                if report is None and isinstance(data, dict):
                    report = data
            elif t == "done":
                break
            else:
                if not args.quiet:
                    print(format_progress_line(event), file=sys.stderr, flush=True)
    except UnreachableError as e:
        print(f"Cannot reach {args.api_base}: {e}", file=sys.stderr)
        return EXIT_UNREACHABLE
    except TimeoutError:
        print(f"Scan exceeded {args.timeout}s timeout. Try --depth static for a faster result.",
              file=sys.stderr)
        return EXIT_TIMEOUT

    if not report:
        print("Scan did not complete — no report event received. Check server logs.",
              file=sys.stderr)
        return EXIT_NO_REPORT

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(format_summary_line(report))
    if not args.quiet:
        print(f"[done] report saved to {args.out}", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
