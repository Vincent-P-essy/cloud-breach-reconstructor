from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading

from cloud_breach_reconstructor import __version__
from cloud_breach_reconstructor.api import create_server


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        os.chdir(directory)
        server = create_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request("GET", "/api/v1/demo")
            response = connection.getresponse()
            payload = json.loads(response.read())
            connection.close()
            if response.status != 200:
                raise AssertionError(f"packaged demo returned HTTP {response.status}")
            if len(payload["events"]) != 21 or payload["schema_version"] != "1.1":
                raise AssertionError("packaged demo returned an unexpected reconstruction")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print(json.dumps({"installed_version": __version__, "packaged_demo_events": 21}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
