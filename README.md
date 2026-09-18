# SIP Registry Administration

Redwood-styled web administration service for `phone_registry.sip_users`.
It lists extensions, creates and updates SIP Digest credentials, enables or disables registrations, and deletes credentials. The browser never receives `digest_ha1` values and a clear-text password is accepted only in the write request used to calculate the HA1 value.

## Security model

- The service requires HTTP Basic authentication using `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
- Use a dedicated MariaDB account with only `SELECT`, `INSERT`, `UPDATE`, and `DELETE` on `phone_registry.sip_users`.
- Mount database credentials as a runtime secret. Do not copy `data/mariadb.txt` or SSH private keys into the image, a Deployment, or source control.
- Serve the application over HTTPS. The included container expects its certificate and key at `/run/tls`.
- `SIP_REALM` must exactly equal the `-Dsip.realm` value configured in OCCAS (default: `occassip.test`). A password change with a mismatched realm will prevent registrations.

## Runtime configuration

| Variable | Required | Description |
| --- | --- | --- |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Yes | Basic-auth credentials for this admin UI. |
| `MARIADB_CREDENTIALS_FILE` | Yes | Secret file with `host`, `user`, and `password` on separate lines; or user/password if `MARIADB_HOST` is set. |
| `MARIADB_HOST`, `MARIADB_PORT` | Conditional | Database host/port. Port defaults to `3306`. |
| `SIP_REALM` | Yes | SIP Digest realm, normally `occassip.test`. |

For a local SSH tunnel, configure the service with `MARIADB_HOST=127.0.0.1` and `MARIADB_PORT=13306`. Establish the tunnel outside the container with the supplied `hkl` account/key; do not mount the SSH private key in the web application.

## MariaDB privilege

Run once as a MariaDB administrator (replace the password and source host):

```sql
CREATE USER 'phone_registry_admin'@'your-admin-service-host' IDENTIFIED BY 'use-a-unique-strong-password';
GRANT SELECT, INSERT, UPDATE, DELETE ON phone_registry.sip_users TO 'phone_registry_admin'@'your-admin-service-host';
FLUSH PRIVILEGES;
```

## Local start

Create a non-versioned secret file containing the three lines `host`, `user`, and `password`, then run:

```powershell
$env:ADMIN_USERNAME='registry-admin'
$env:ADMIN_PASSWORD='choose-a-long-unique-password'
$env:MARIADB_CREDENTIALS_FILE='C:\secure\mariadb-admin.txt'
$env:SIP_REALM='occassip.test'
python -m pip install -r requirements.txt
python app.py
```

Open `https://localhost:8443` when running the container, or `http://localhost:8080` for the Flask development server.
