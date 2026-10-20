#!/usr/bin/env python3
"""Web UI that lists and deletes regular files in one directory.

For a trusted LAN, with no login. MECLEAN_ROOT (default /data) is scanned
recursively. Paths are resolved and must stay inside that directory.
Directories, symlinks, and other non-regular files are not deleted.

Environment:
  MECLEAN_ROOT  directory to manage (default /data)
  MECLEAN_HOST  bind address (default 0.0.0.0)
  MECLEAN_PORT  bind port (default 8080)
"""

from __future__ import annotations

import html
import hmac
import os
import posixpath
import secrets
import stat
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

MAX_BODY = 64 * 1024

MESSAGES = {
    "deleted": "File deleted.",
    "rejected": "Not deleted. Only a regular file inside the directory can be removed.",
}


class UnsafePath(Exception):
    """The path is not a regular file inside the root."""


def _within(root: Path, path: Path) -> bool:
    # relative_to, not a string prefix: /data must not match /data-evil.
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def safe_target(root: Path, rel: str) -> Path:
    """Resolve rel to a regular file inside root, or raise UnsafePath.

    Rejects absolute paths, lexical escapes, and symlinks that land outside
    root. An intermediate symlink is followed only when its target is still
    inside root. The final name must be a regular file, so a symlink is never
    the thing removed (unlink would only drop the link, but skipping it keeps
    the rule obvious).
    """
    if not isinstance(rel, str) or rel == "" or "\x00" in rel or len(rel) > 4096:
        raise UnsafePath()
    if posixpath.isabs(rel):
        raise UnsafePath()

    norm = posixpath.normpath(rel)
    if norm in ("", ".") or norm == ".." or norm.startswith("../") or posixpath.isabs(norm):
        raise UnsafePath()

    root_real = root.resolve(strict=True)
    if not root_real.is_dir():
        raise UnsafePath()

    current = root_real
    parts = norm.split("/")
    for index, part in enumerate(parts):
        if part in ("", ".", ".."):
            raise UnsafePath()
        nxt = current / part
        try:
            info = nxt.lstat()
        except OSError as exc:
            raise UnsafePath() from exc
        last = index == len(parts) - 1
        if stat.S_ISLNK(info.st_mode):
            try:
                resolved = nxt.resolve(strict=True)
            except OSError as exc:
                raise UnsafePath() from exc
            if not _within(root_real, resolved):
                raise UnsafePath()
            # Final symlink, or a link that does not point at a directory.
            if last or not resolved.is_dir():
                raise UnsafePath()
            current = resolved
            continue
        if last:
            if not stat.S_ISREG(info.st_mode) or not _within(root_real, nxt):
                raise UnsafePath()
            return nxt
        if not stat.S_ISDIR(info.st_mode):
            raise UnsafePath()
        current = nxt
    raise UnsafePath()


def delete_file(root: Path, rel: str) -> None:
    """Delete one regular file. Raises UnsafePath when the path is refused."""
    path = safe_target(root, rel)
    # O_NOFOLLOW: if the name was swapped for a symlink after the check, skip it.
    # unlink itself does not follow a final symlink.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise UnsafePath() from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise UnsafePath()
    finally:
        os.close(fd)
    try:
        os.unlink(path)
    except OSError as exc:
        raise UnsafePath() from exc


def list_files(root: Path) -> list[dict]:
    """Regular files under root, newest first.

    Each item has path (relative, slash-separated), size (bytes), and mtime.
    Directory symlinks are not followed. Symlinks and other non-files are omitted.
    """
    root_real = root.resolve(strict=True)
    if not root_real.is_dir():
        raise OSError("root is not a directory")

    found: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root_real, followlinks=False):
        kept = []
        for name in dirnames:
            entry = Path(dirpath) / name
            try:
                if entry.is_symlink() or not entry.is_dir():
                    continue
            except OSError:
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in filenames:
            entry = Path(dirpath) / name
            try:
                info = entry.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or not _within(root_real, entry):
                continue
            found.append(
                {
                    "path": entry.relative_to(root_real).as_posix(),
                    "size": info.st_size,
                    "mtime": info.st_mtime,
                }
            )
    found.sort(key=lambda item: (-item["mtime"], item["path"]))
    return found


def format_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def format_time(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))


def token_ok(got: str, expected: str) -> bool:
    if not isinstance(got, str) or len(got) != len(expected):
        return False
    return hmac.compare_digest(got, expected)


def request_allowed(got_token: str, expected: str, host: str, origin: str, fetch_site: str) -> bool:
    """CSRF check: per-process form token, plus browser hints when they are sent.

    Origin, when present, must match Host. Proxies should forward the original
    Host header. Missing Origin is allowed so non-browser clients still work
    when they have the token.
    """
    if not token_ok(got_token, expected):
        return False
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return False
    if origin:
        parsed = urlparse(origin)
        if parsed.scheme not in ("http", "https") or not host or parsed.netloc != host:
            return False
    return True


def _js_quote(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\r", "")
        .replace("\n", "\\n")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def render_page(root: Path, files: list[dict], message: str, error: str, token: str) -> str:
    token_attr = html.escape(token, quote=True)
    rows: list[str] = []
    for item in files:
        path = item["path"]
        confirm = html.escape("return confirm('Delete %s?');" % _js_quote(path), quote=True)
        rows.append(
            "<tr>"
            f"<td class=\"path\">{html.escape(path)}</td>"
            f"<td class=\"num\">{html.escape(format_size(int(item['size'])))}</td>"
            f"<td class=\"num\">{html.escape(format_time(float(item['mtime'])))}</td>"
            "<td class=\"action\">"
            f"<form method=\"post\" action=\"/delete\" onsubmit=\"{confirm}\">"
            f"<input type=\"hidden\" name=\"token\" value=\"{token_attr}\">"
            f"<input type=\"hidden\" name=\"path\" value=\"{html.escape(path, quote=True)}\">"
            "<button type=\"submit\" class=\"delete\">Delete</button>"
            "</form>"
            "</td>"
            "</tr>"
        )

    if error:
        banner = f"<p class=\"banner bad\">{html.escape(error)}</p>"
    elif message:
        banner = f"<p class=\"banner\">{html.escape(message)}</p>"
    else:
        banner = ""

    count = len(files)
    noun = "file" if count == 1 else "files"
    if rows:
        table = (
            "<div class=\"table-wrap\"><table>"
            "<thead><tr><th>File</th><th class=\"num\">Size</th>"
            "<th class=\"num\">Modified</th><th></th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )
    else:
        table = "<p class=\"empty\">No regular files.</p>"

    root_text = html.escape(str(root))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>meclean</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{
    margin: 2rem auto; max-width: 52rem; padding: 0 1rem;
    font: 15px/1.45 system-ui, sans-serif; background: Canvas; color: CanvasText;
  }}
  h1 {{ font-size: 1.35rem; margin: 0 0 0.25rem; }}
  .note, .empty {{ color: color-mix(in srgb, CanvasText 75%, transparent); }}
  .banner {{ padding: 0.5rem 0.7rem; border-radius: 6px; background: color-mix(in srgb, CanvasText 8%, Canvas); }}
  .banner.bad {{ background: color-mix(in srgb, #b00020 16%, Canvas); }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 0.45rem 0.4rem; border-bottom: 1px solid color-mix(in srgb, CanvasText 18%, transparent); vertical-align: middle; }}
  td.path {{ word-break: break-all; font-family: ui-monospace, monospace; font-size: 0.92em; }}
  .num {{ text-align: right; white-space: nowrap; }}
  td.action {{ text-align: right; width: 1%; }}
  form {{ margin: 0; }}
  button.delete {{
    font: inherit; color: white; background: #9b2c2c; border: 0; border-radius: 4px;
    padding: 0.25rem 0.7rem; cursor: pointer;
  }}
  code {{ font-size: 0.92em; }}
</style>
</head>
<body>
  <h1>meclean</h1>
  <p class="note">{count} {noun} under <code>{root_text}</code>, newest first. Delete is permanent.</p>
  {banner}
  {table}
</body>
</html>
"""


def make_handler(root: Path, token: str, *, quiet: bool = False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "meclean"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:
            if not quiet:
                super().log_message(fmt, *args)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._send(200, b"ok\n", "text/plain; charset=utf-8")
                return
            if parsed.path == "/favicon.ico":
                self._send(204, b"", "text/plain; charset=utf-8")
                return
            if parsed.path != "/":
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
                return
            key = (parse_qs(parsed.query).get("msg") or [""])[0]
            message = MESSAGES.get(key, "")
            error = ""
            try:
                files = list_files(root)
            except OSError:
                files = []
                error = "The configured directory is not readable."
            body = render_page(root, files, message, error, token).encode("utf-8", "replace")
            self._send(200, body, "text/html; charset=utf-8")

        def do_POST(self) -> None:
            if urlparse(self.path).path != "/delete":
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._redirect("rejected")
                return
            if length < 1 or length > MAX_BODY:
                self._redirect("rejected")
                return
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
            got_token = (form.get("token") or [""])[0]
            rel = (form.get("path") or [""])[0]
            allowed = request_allowed(
                got_token,
                token,
                self.headers.get("Host", ""),
                self.headers.get("Origin", ""),
                self.headers.get("Sec-Fetch-Site", ""),
            )
            if not allowed:
                self._redirect("rejected")
                return
            try:
                delete_file(root, rel)
            except UnsafePath:
                self._redirect("rejected")
                return
            self._redirect("deleted")

        def _redirect(self, code: str) -> None:
            self.send_response(303)
            self.send_header("Location", "/?msg=" + code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            # same-origin, not no-referrer: no-referrer makes browsers send
            # "Origin: null", which would fail the origin check on every delete.
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; form-action 'self'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )
            self.end_headers()
            if body:
                self.wfile.write(body)

    return Handler


def main() -> None:
    root = Path(os.environ.get("MECLEAN_ROOT", "/data"))
    host = os.environ.get("MECLEAN_HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("MECLEAN_PORT", "8080"))
    except ValueError:
        raise SystemExit("MECLEAN_PORT must be an integer")
    # New token each process. A page loaded before a restart will not delete.
    token = secrets.token_urlsafe(32)
    try:
        httpd = ThreadingHTTPServer((host, port), make_handler(root, token))
    except OSError as exc:
        raise SystemExit(f"cannot bind {host}:{port}: {exc}") from exc
    print(f"meclean root={root} listen={host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping", flush=True)
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
