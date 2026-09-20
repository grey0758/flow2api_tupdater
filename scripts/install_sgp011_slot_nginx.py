#!/usr/bin/env python3
"""Install the reviewed WebSocket include in the existing Updater TLS vhost."""

import pathlib
import sys


path = pathlib.Path(sys.argv[1])
include = "    include /etc/nginx/snippets/flow-updater-login-slots.conf;\n\n"
text = path.read_text()
if include.strip() in text:
    print("nginx websocket include already present")
    raise SystemExit(0)
listen = text.find("listen 443")
if listen < 0:
    raise SystemExit("Updater TLS server was not found")
server_name = text.find("server_name flow-updater.opencodex.uk;", listen)
if server_name < 0:
    raise SystemExit("Updater TLS server name was not found")
location = text.find("    location / {", server_name)
if location < 0:
    raise SystemExit("Updater root location was not found")
text = text[:location] + include + text[location:]
path.write_text(text)
print("nginx websocket include installed")
