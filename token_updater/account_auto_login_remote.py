"""Container-local stdin bridge for one signed visible login slot.

Invoked with ``docker exec -i``. The only command argument is the Profile ID;
credentials enter on stdin and are never printed or persisted.
"""

import json
import os
import sys
import urllib.request


BASE = "http://127.0.0.1:8002"


def call(method: str, path: str, body: dict | None = None, token: str = "") -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Flow-Updater-Authorization"] = "Bearer " + token
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(BASE + path, data=payload,
                                     headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=420) as response:
        return json.load(response)


def main() -> int:
    try:
        profile_id = int(sys.argv[1])
        if profile_id < 1 or len(sys.argv) != 2:
            raise ValueError
        secret = json.load(sys.stdin)
        if not isinstance(secret, dict) or set(secret) != {"email", "password", "totp_seed"}:
            raise ValueError
        session = call("POST", "/api/login", {"password": os.environ["ADMIN_PASSWORD"]})["token"]
        try:
            result = call("POST", f"/api/login-slots/{profile_id}/auto-login",
                          secret, session)
            secret.clear()
            if result.get("success") is True:
                checked = call("POST", f"/api/profiles/{profile_id}/check-login",
                               token=session)
                success = checked.get("success") is True
                report = {"success": success, "profile_id": profile_id,
                          "stage": "handoff_complete" if success else "review",
                          "error_code": None if success else
                              str(checked.get("error_code") or "project_validation_review")[:64]}
            else:
                report = {"success": False, "profile_id": profile_id,
                          "error_code": str(result.get("error_code") or "login_review")[:64],
                          "requires_manual_action": result.get("requires_manual_action") is True}
            print(json.dumps(report, separators=(",", ":")))
            return 0
        finally:
            try:
                call("POST", "/api/logout", token=session)
            except Exception:
                pass
    except Exception:
        print('{"success":false,"error_code":"auto_login_transport_review"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
