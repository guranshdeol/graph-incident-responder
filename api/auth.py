"""Sign-in for the console: named users with a role, signed session cookies.

Users live in RG_USERS (in .env, never in git) as `name:role:salt:hash,...`, where hash is
PBKDF2-SHA256 (200k rounds) of the password. Roles:
    operator   read everything, approve/reject fixes, simulate incidents, run fault drills
    viewer     read everything
The session cookie is `base64(json).base64(hmac)` signed with SESSION_SECRET, which both the
staging (`/`) and production (`/live/`) APIs share, so one sign-in covers both environments.
The old ADMIN_TOKEN bearer still works for scripts and counts as an operator.

    uv run python -m api.auth add <name> <operator|viewer>   new password -> demo/accounts.txt (600), hash -> .env
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path

ROLES = ("operator", "viewer")
SESSION_HOURS = 12
COOKIE = "rg_session"
ROUNDS = 200_000


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ROUNDS).hex()


def users() -> dict[str, dict]:
    out = {}
    for entry in filter(None, (e.strip() for e in os.environ.get("RG_USERS", "").replace(";", ",").split(","))):
        name, role, salt, digest = entry.split(":")
        if role in ROLES:
            out[name] = {"role": role, "salt": salt, "hash": digest}
    return out


def check_password(name: str, password: str) -> dict | None:
    u = users().get(name)
    # hash even for unknown names so timing doesn't reveal which names exist
    salt = u["salt"] if u else "00" * 16
    _, digest = hash_password(password, salt)
    if u and hmac.compare_digest(digest, u["hash"]):
        return {"name": name, "role": u["role"]}
    return None


def _secret() -> bytes:
    s = os.environ.get("SESSION_SECRET", "")
    if len(s) < 32:
        raise RuntimeError("SESSION_SECRET (32+ chars) is not set")
    return s.encode()


def make_session(user: dict, now: float | None = None) -> str:
    body = _b64(json.dumps({"u": user["name"], "r": user["role"],
                            "exp": int((now or time.time()) + SESSION_HOURS * 3600)}).encode())
    sig = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def read_session(token: str | None, now: float | None = None) -> dict | None:
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    try:
        good = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(good, sig):
            return None
        data = json.loads(_unb64(body))
    except (RuntimeError, ValueError):
        return None
    if data.get("exp", 0) < (now or time.time()):
        return None
    # a user removed from RG_USERS (or whose role changed) loses access at once
    u = users().get(data.get("u"))
    if not u or u["role"] != data.get("r"):
        return None
    return {"name": data["u"], "role": data["r"]}


class LoginLimiter:
    """At most `limit` failed sign-ins per client per `window` seconds."""

    def __init__(self, limit: int = 8, window: int = 300):
        self.limit, self.window, self.fails = limit, window, {}

    def blocked(self, key: str, now: float | None = None) -> bool:
        now = now or time.time()
        recent = [t for t in self.fails.get(key, []) if now - t < self.window]
        self.fails[key] = recent
        return len(recent) >= self.limit

    def failed(self, key: str, now: float | None = None) -> None:
        self.fails.setdefault(key, []).append(now or time.time())


def _add_user(name: str, role: str, env_path: Path, accounts_path: Path) -> None:
    if role not in ROLES or not name.isidentifier():
        sys.exit(f"usage: add <name> <{'|'.join(ROLES)}> (name: letters, digits, _)")
    password = secrets.token_urlsafe(12)
    salt, digest = hash_password(password)
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    current = next((ln.split("=", 1)[1] for ln in lines if ln.startswith("RG_USERS=")), "")
    entries = [e for e in current.replace(";", ",").split(",") if e and not e.startswith(name + ":")] + [f"{name}:{role}:{salt}:{digest}"]
    new = [ln for ln in lines if not ln.startswith("RG_USERS=")] + [f"RG_USERS={','.join(entries)}"]
    if not any(ln.startswith("SESSION_SECRET=") for ln in new):
        new.append(f"SESSION_SECRET={secrets.token_urlsafe(48)}")
    env_path.write_text("\n".join(new) + "\n")
    old = [ln for ln in (accounts_path.read_text().splitlines() if accounts_path.exists() else [])
           if not ln.startswith(name + " ")]
    accounts_path.write_text("\n".join(old + [f"{name} {role} {password}"]) + "\n")
    accounts_path.chmod(0o600)
    print(f"user {name} ({role}) added; password in {accounts_path} (never commit it). Restart api and api-live.")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "add":
        root = Path(__file__).resolve().parents[1]
        _add_user(sys.argv[2], sys.argv[3], root / ".env", root / "demo" / "accounts.txt")
    else:
        sys.exit(__doc__)
