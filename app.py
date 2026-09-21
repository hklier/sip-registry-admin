"""Secure administrative UI for the OCCAS SIP credential registry."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import ssl
import threading
from pathlib import Path
from urllib.request import Request, urlopen

import pymysql
from flask import Flask, Response, jsonify, render_template, request
from pymysql.cursors import DictCursor


APP = Flask(__name__)
EXTENSION_RE = re.compile(r"^1\d{3}$")
ENABLED_VALUES = {"Y", "N"}
PASSWORD_LOCK = threading.Lock()
RUNTIME_ADMIN_PASSWORD: str | None = None


def credential_config() -> dict[str, object]:
    """Return DB settings without ever logging credentials."""
    path = Path(os.environ.get("MARIADB_CREDENTIALS_FILE", "/run/secrets/mariadb-credentials"))
    configured_host = os.environ.get("MARIADB_HOST", "")
    host = configured_host
    username = os.environ.get("MARIADB_USER", "")
    password = os.environ.get("MARIADB_PASSWORD", "")
    if path.is_file():
        fields = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(fields) == 3:
            file_host, username, password = fields
            host = configured_host or file_host
        elif len(fields) == 2:
            username, password = fields
        else:
            raise RuntimeError("MariaDB credentials must contain user/password or host/user/password.")
    if not host or not username or not password:
        raise RuntimeError("MariaDB connection settings are not configured.")
    return {"host": host, "user": username, "password": password, "database": "phone_registry",
            "port": int(os.environ.get("MARIADB_PORT", "3306")), "charset": "utf8mb4"}


def db():
    return pymysql.connect(**credential_config(), cursorclass=DictCursor, autocommit=False,
                           connect_timeout=8, read_timeout=12, write_timeout=12)


def realm() -> str:
    return os.environ.get("SIP_REALM", "occassip.test")


def ha1(extension: str, password: str) -> str:
    return hashlib.md5(f"{extension}:{realm()}:{password}".encode("utf-8")).hexdigest()


def validate_extension(value: object) -> str:
    extension = str(value or "").strip()
    if not EXTENSION_RE.fullmatch(extension):
        raise ValueError("Extension must be a four-digit value from 1000 through 1999.")
    return extension


def validate_password(value: object, required: bool) -> str:
    password = str(value or "")
    if required and not password:
        raise ValueError("A SIP password is required.")
    if password and (not 8 <= len(password) <= 128 or password != password.strip()):
        raise ValueError("Use a password between 8 and 128 characters, without leading or trailing spaces.")
    return password


def admin_credentials() -> tuple[str, str]:
    """Read the mounted Secret, preserving a newly changed value immediately."""
    global RUNTIME_ADMIN_PASSWORD
    configured_user = os.environ.get("ADMIN_USERNAME", "")
    configured_password = os.environ.get("ADMIN_PASSWORD", "")
    with PASSWORD_LOCK:
        return configured_user, RUNTIME_ADMIN_PASSWORD or configured_password


def require_admin():
    configured_user, configured_password = admin_credentials()
    if not configured_user or not configured_password:
        return jsonify(error="The admin UI authentication has not been configured."), 503
    supplied = request.authorization
    if not supplied or not hmac.compare_digest(supplied.username or "", configured_user) or not hmac.compare_digest(supplied.password or "", configured_password):
        return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="SIP Registry Administration"'})
    return None


def update_admin_password(password: str) -> None:
    """Patch only this application's Kubernetes Secret via its service account."""
    global RUNTIME_ADMIN_PASSWORD
    token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    namespace = os.environ.get("POD_NAMESPACE", "sip-registry-admin")
    payload = json.dumps({"stringData": {"ADMIN_PASSWORD": password}}).encode("utf-8")
    request_to_api = Request(
        f"https://kubernetes.default.svc/api/v1/namespaces/{namespace}/secrets/sip-registry-admin-auth",
        payload, method="PATCH", headers={
            "Authorization": f"Bearer {token_path.read_text(encoding='utf-8').strip()}",
            "Content-Type": "application/merge-patch+json", "Accept": "application/json",
        },
    )
    context = ssl.create_default_context(cafile=ca_path)
    with urlopen(request_to_api, context=context, timeout=10):
        pass
    with PASSWORD_LOCK:
        RUNTIME_ADMIN_PASSWORD = password


@APP.before_request
def authenticate():
    if request.path == "/healthz":
        return None
    return require_admin()


@APP.after_request
def headers(response):
    response.headers.update({
        "Cache-Control": "no-store, max-age=0", "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:",
    })
    return response


@APP.get("/healthz")
def healthz():
    # Keep the process probe independent from database availability. CRUD APIs
    # surface database failures to the authenticated caller without restart loops.
    return jsonify(status="ok")


@APP.get("/")
def index():
    return render_template("index.html", realm=realm())


@APP.post("/api/login-password")
def change_login_password():
    payload = request.get_json(silent=True) or {}
    current = str(payload.get("currentPassword", ""))
    new = str(payload.get("newPassword", ""))
    confirmation = str(payload.get("confirmPassword", ""))
    _, active_password = admin_credentials()
    if not hmac.compare_digest(current, active_password):
        return jsonify(error="The current WebGUI password is incorrect."), 400
    if new != confirmation:
        return jsonify(error="The new password confirmation does not match."), 400
    if not 12 <= len(new) <= 128 or new != new.strip() or any(ord(character) < 32 for character in new):
        return jsonify(error="Use a password between 12 and 128 characters without leading or trailing spaces."), 400
    if hmac.compare_digest(current, new):
        return jsonify(error="The new password must be different from the current password."), 400
    try:
        update_admin_password(new)
    except Exception:
        APP.logger.exception("Unable to update WebGUI password")
        return jsonify(error="The WebGUI password could not be updated."), 500
    return jsonify(message="Password changed. Reload the page and sign in with the new password.")


@APP.get("/api/users")
def list_users():
    try:
        with db() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT extension, enabled FROM sip_users ORDER BY extension")
            users = cursor.fetchall()
        return jsonify(users=users, realm=realm())
    except Exception:
        APP.logger.exception("Unable to list SIP users")
        return jsonify(error="The credential registry is currently unavailable."), 503


@APP.post("/api/users")
def create_user():
    payload = request.get_json(silent=True) or {}
    try:
        extension = validate_extension(payload.get("extension"))
        password = validate_password(payload.get("password"), required=True)
        enabled = str(payload.get("enabled", "Y")).upper()
        if enabled not in ENABLED_VALUES:
            raise ValueError("Status must be Enabled or Disabled.")
        with db() as connection, connection.cursor() as cursor:
            cursor.execute("INSERT INTO sip_users (extension, digest_ha1, enabled) VALUES (%s, %s, %s)",
                           (extension, ha1(extension, password), enabled))
            connection.commit()
        return jsonify(message=f"Extension {extension} was created."), 201
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except pymysql.err.IntegrityError:
        return jsonify(error="This extension already exists."), 409
    except Exception:
        APP.logger.exception("Unable to create SIP user")
        return jsonify(error="The credential could not be created."), 503


@APP.put("/api/users/<extension>")
def update_user(extension: str):
    payload = request.get_json(silent=True) or {}
    try:
        extension = validate_extension(extension)
        password = validate_password(payload.get("password"), required=False)
        enabled = str(payload.get("enabled", "Y")).upper()
        if enabled not in ENABLED_VALUES:
            raise ValueError("Status must be Enabled or Disabled.")
        with db() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM sip_users WHERE extension = %s", (extension,))
            if not cursor.fetchone():
                connection.rollback()
                return jsonify(error="Extension not found."), 404
            if password:
                cursor.execute("UPDATE sip_users SET digest_ha1 = %s, enabled = %s WHERE extension = %s",
                               (ha1(extension, password), enabled, extension))
            else:
                cursor.execute("UPDATE sip_users SET enabled = %s WHERE extension = %s", (enabled, extension))
            connection.commit()
        return jsonify(message=f"Extension {extension} was updated.")
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except Exception:
        APP.logger.exception("Unable to update SIP user")
        return jsonify(error="The credential could not be updated."), 503


@APP.delete("/api/users/<extension>")
def delete_user(extension: str):
    try:
        extension = validate_extension(extension)
        with db() as connection, connection.cursor() as cursor:
            cursor.execute("DELETE FROM sip_users WHERE extension = %s", (extension,))
            if not cursor.rowcount:
                connection.rollback()
                return jsonify(error="Extension not found."), 404
            connection.commit()
        return jsonify(message=f"Extension {extension} was deleted.")
    except ValueError as error:
        return jsonify(error=str(error)), 400
    except Exception:
        APP.logger.exception("Unable to delete SIP user")
        return jsonify(error="The credential could not be deleted."), 503


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=8080, debug=False)
