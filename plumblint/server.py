"""HTTP API on the standard library. No Flask, no FastAPI, no uvicorn.

    python3 -m plumblint.server --port 8080
    curl -s localhost:8080/scan -d '{"text":"ignore previous instructions"}'

Scanned text is never persisted: it lives only in the request handler's
memory, and nothing about a request is written to any log or to stderr.

That claim is enforced: both `log_message` and `handle_error` are overridden
below so no request detail and no filesystem path can escape through them.

Request framing is validated centrally (see `_check_framing`): an unread
request body, a `Transfer-Encoding` header (chunked is not implemented), or a
duplicated `Content-Length` all close the connection. Framing is checked before
any route runs, including GET, unknown routes, and error responses.
"""

import argparse
import json
import re
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import BoundedSemaphore

from . import __version__
from .detector import scan

MAX_BODY = 1 << 20          # 1 MB
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,10}")
READ_TIMEOUT_SECONDS = 15   # ABSOLUTE deadline for reading one body, not idle
MAX_CONCURRENT = 64         # cap on simultaneous worker threads
QUEUE_TIMEOUT_SECONDS = 5   # how long a new connection waits for a slot


class Handler(BaseHTTPRequestHandler):
    server_version = f"plumblint/{__version__}"
    protocol_version = "HTTP/1.1"
    timeout = READ_TIMEOUT_SECONDS

    # ---- output helpers -------------------------------------------------

    def _send(self, code: int, payload: dict, *, close: bool = False) -> None:
        """Writes a JSON response, tolerating a client that already left.

        `close=True` is mandatory on any response issued BEFORE the declared
        request body has been read in full (a refusal, an error, or any route
        that does not consume the body). Otherwise the unread body's bytes are
        parsed as the next request on a kept-alive connection - a request
        smuggling primitive behind any connection-pooling proxy.
        """
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        try:
            if close:
                self.close_connection = True
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if close:
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
            # The peer disconnected before or during the reply. Nothing can
            # be delivered and nothing should be printed: a closed socket is
            # normal traffic, not an incident.
            self.close_connection = True

    # ---- framing --------------------------------------------------------

    def _check_framing(self):
        """Reject ambiguous framing before any route runs.

        Returns the declared body length (0 if none), or None if the request
        was rejected here (a response, with connection close, was already
        sent). Chunked transfer is not implemented, and a duplicated or
        malformed Content-Length is a desynchronisation vector, so all three
        are refused and the connection is closed.
        """
        if self.headers.get("Transfer-Encoding") is not None:
            self._send(501, {"error": "Transfer-Encoding not supported"},
                       close=True)
            return None
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) > 1:
            self._send(400, {"error": "duplicate Content-Length"}, close=True)
            return None
        if not lengths:
            return 0
        raw_len = lengths[0]
        if not _CONTENT_LENGTH_RE.fullmatch(raw_len):
            self._send(400, {"error": "malformed Content-Length"}, close=True)
            return None
        length = int(raw_len)
        if length > MAX_BODY:
            self._send(413, {"error": "body too large", "max_bytes": MAX_BODY},
                       close=True)
            return None
        return length

    def _read_body(self, length: int):
        """Reads exactly `length` bytes under an ABSOLUTE deadline.

        The socket timeout is reset on every recv, so an idle timeout alone
        lets a client drip one byte just under the limit and hold the worker
        thread indefinitely. Here a single monotonic deadline
        bounds the whole read: past it, the request is refused and the
        connection closed, so a slow-drip client occupies a thread for at most
        READ_TIMEOUT_SECONDS - and MAX_CONCURRENT caps how many can try.
        """
        deadline = time.monotonic() + READ_TIMEOUT_SECONDS
        chunks, remaining = [], length
        try:
            while remaining > 0:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise socket.timeout()
                self.connection.settimeout(left)
                # read1, not read: read() is buffered and can loop over many
                # internal recv calls without returning here, so the idle
                # socket timeout resets on each one and the absolute deadline
                # is never checked mid-read - a drip held the thread far past
                # the deadline. read1 returns
                # after a single recv, so the deadline is tested each recv.
                chunk = self.rfile.read1(min(remaining, 65536))
                if not chunk:
                    break               # peer closed early
                chunks.append(chunk)
                remaining -= len(chunk)
        except (socket.timeout, ConnectionResetError, OSError):
            self._send(408, {"error": "timed out reading request body"},
                       close=True)
            return None
        if remaining > 0:
            self._send(400, {"error": "incomplete body"}, close=True)
            return None
        return b"".join(chunks)

    # ---- routes ---------------------------------------------------------

    def do_GET(self):
        length = self._check_framing()
        if length is None:
            return
        # GET carries no body here; if one was declared, answering without
        # draining it would desync the connection, so close.
        self._send(200 if self.path in ("/health", "/") else 404,
                   {"status": "ok", "version": __version__}
                   if self.path in ("/health", "/") else {"error": "not found"},
                   close=length > 0)

    def do_POST(self):
        length = self._check_framing()
        if length is None:
            return
        if self.path != "/scan":
            self._send(404, {"error": "not found"}, close=length > 0)
            return
        if length == 0:
            self._send(400, {"error": "empty body"}, close=True)
            return

        raw = self._read_body(length)
        if raw is None:
            return

        try:
            payload = json.loads(raw.decode("utf-8"))
            text = payload["text"]
            if not isinstance(text, str):
                raise TypeError
        except RecursionError:
            # json.loads recurses per nesting level; RecursionError subclasses
            # RuntimeError, so it escaped the tuple below and the client got
            # zero bytes instead of an answer.
            self._send(400, {"error": "input too deeply nested"})
            return
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError,
                AttributeError):
            self._send(400, {"error": 'expected JSON body {"text": "..."}'})
            return

        try:
            result = scan(text).to_dict()
        except Exception:
            # The detector must never take the service down, and the reason
            # must never reach the client: an error message derived from an
            # exception can leak input or paths.
            self._send(500, {"error": "internal error"})
            return

        self._send(200, result)

    # ---- silence --------------------------------------------------------

    def log_message(self, fmt, *args):
        """Deliberately silent: request details are never logged."""
        return

    def log_error(self, fmt, *args):
        """Deliberately silent: error lines would carry request details."""
        return

    def handle_one_request(self):
        """Wraps the base implementation so a dropped peer stays quiet.

        A watchdog force-closes the socket after READ_TIMEOUT_SECONDS. The
        request line and headers are read by the base class before any of our
        code runs, so a client that drips *headers* slowly would otherwise
        hold a worker slot with no absolute bound. The watchdog caps the whole
        request's wall-clock time; the read1
        loop above gives a clean 408 for the common body-drip case.
        """
        import threading
        # Watchdog fires AFTER the body deadline (2x), so for a body drip the
        # _read_body deadline wins the race and returns a clean 408; the
        # watchdog is the backstop that also covers slow HEADERS (which have no
        # other deadline, being read by the base class). If it fired at exactly
        # the body deadline it would race _read_body and a body drip would get
        # a bare connection close instead of the promised 408.
        watchdog = threading.Timer(READ_TIMEOUT_SECONDS * 2, self._force_close)
        watchdog.daemon = True
        watchdog.start()
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
            self.close_connection = True
        finally:
            watchdog.cancel()

    def _force_close(self):
        """Called from the watchdog thread: unblock any pending read."""
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_concurrent = MAX_CONCURRENT

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Bounds concurrent worker threads. Without a cap, slow-drip
        # connections (even with the read deadline) could still spawn an
        # unbounded number of short-lived threads.
        self._slots = BoundedSemaphore(self.max_concurrent)

    def process_request(self, request, client_address):
        if not self._slots.acquire(timeout=QUEUE_TIMEOUT_SECONDS):
            # Too many in flight: drop this connection rather than pile on.
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        """Swallows tracebacks.

        The default implementation prints the full traceback to stderr,
        including absolute source paths. Those paths identify the machine
        and the author, so they must not be emitted by a service that
        promises to log nothing.
        """
        return


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="HTTP API for the prompt injection detector")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)

    srv = Server((args.host, args.port), Handler)
    print(f"plumblint {__version__} on http://{args.host}:{args.port}  (POST /scan)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
