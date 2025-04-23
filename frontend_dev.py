# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2022 The Home Control Authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import pathlib
import socket
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from typing import Optional, Tuple
import logging

_server: Optional[ThreadingHTTPServer] = None
log = logging.getLogger('frontend-dev')


def start(frontend_dir: pathlib.Path, bind_addr: str, http_port: int, https_port: int,
          ssl_data: Tuple[bool, pathlib.Path, Optional[pathlib.Path]]):
    global _server

    log.info("Starting up")

    class Server(ThreadingHTTPServer):
        def finish_request(self, request, client_address) -> None:
            # There is noqa on the next line as PyCharm doesn't know self.RequestHandlerClass is
            # SimpleHTTPRequestHandler which takes that kwarg
            self.RequestHandlerClass(request, client_address, self, directory=frontend_dir)  # noqa

    listen_port = http_port
    use_ssl, ssl_cert, ssl_key = ssl_data
    ssl_context = None
    listen_extra = ""
    if use_ssl:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            log.info("Enabling SSL")
            ssl_context.load_cert_chain(ssl_cert, ssl_key)
            listen_port = https_port
            listen_extra = " with HTTPS"
        except ssl.SSLError as e:
            log.warning(f"Failed to enable SSL: {e}")
            use_ssl = False

    _server = Server((bind_addr, listen_port), SimpleHTTPRequestHandler)

    if use_ssl:
        _server.socket = ssl_context.wrap_socket(_server.socket, server_side=True)
        _server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    log.info(f"Serving {frontend_dir} on {bind_addr}:{listen_port}{listen_extra}")

    _server_thread = threading.Thread(target=_server.serve_forever)
    _server_thread.daemon = True
    _server_thread.start()


def running():
    return _server is not None


def stop():
    log.info("Shutting down")
    _server.shutdown()
