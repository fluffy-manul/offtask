# Deploy Offtask

This guide describes operator setup. Running CI or building an image does not provision accounts, purchase a database, enroll a participant, or deploy the service.

## Runtime configuration

| Setting | Required value or behavior |
| --- | --- |
| `OFFTASK_MODE` | `production` (image default) |
| `NODE_ENV` | `production` (image default) |
| `PORT` | `80` (image default); bind `0.0.0.0:80` |
| `PUBLIC_ORIGIN` | Exact primary HTTPS origin, e.g. `https://offtask.example`; no credentials, path, query, or fragment |
| `DATABASE_URL` | PostgreSQL URL, injected as a runtime secret; never a build argument or committed file |
| `DATABASE_CA_CERT_PEM` | Optional database CA in PEM form, convenient for platform variables |
| `DATABASE_CA_CERT` | Alternative absolute path to the database CA PEM; readable by UID 10001 |
| `OFFTASK_DATABASE_INSECURE` | Leave unset in production; `true` is accepted only with `NODE_ENV=test` or `development` for synthetic local tests |

Use one CA option, not both. `DATABASE_URL` is always overridden to certificate-and-hostname verification in production; `sslmode=disable`, `prefer`, or `require` in the URL cannot weaken it. Use the hostname on the provider's certificate, not an arbitrary IP or alias. Provider-issued CA certificates are public trust material; database passwords remain secrets.

The database role must own the dedicated Offtask schema or have permission to create/alter its tables and sequences and read/write the application data. Do not use a PostgreSQL superuser. This release automatically migrates at startup, so the runtime role requires schema migration permissions. A separate migration-only identity/role split is not implemented. Use a dedicated database instead of a schema shared with another application.

The server opens at most eight database connections per instance. Account for every instance, admin process, and rolling-deployment overlap when sizing the database connection limit. Use a direct PostgreSQL connection; transaction-pooling compatibility is not a release guarantee.

## DigitalOcean App Platform

Configure the existing web service from repository root:

| Setting | Value |
| --- | --- |
| Repository / branch | `fluffy-manul/offtask` / `main` |
| Source directory | Repository root (`/`) |
| Dockerfile | `Dockerfile` |
| Build command | Unset; the Dockerfile tests and builds both Rust binaries |
| Run command | Unset; preserve the image entrypoint and `--production` default |
| HTTP port | `80` |
| Public route | `/` |
| Readiness/health check | HTTP `GET /readyz`, port `80` |
| `PUBLIC_ORIGIN` | Runtime `${APP_URL}` or exact custom primary HTTPS origin |
| `DATABASE_URL` | Runtime encrypted secret or the attached database's connection binding |
| Database trust | Runtime `DATABASE_CA_CERT_PEM` containing the provider's matching CA when needed |

Attach/configure a production PostgreSQL database through your own account. Use the provider's current connection details and CA; restrict trusted sources to the application and authorized operator access. Offtask performs no provisioning. Keep secrets runtime-only. DigitalOcean documents [Dockerfile setup](https://docs.digitalocean.com/products/app-platform/reference/dockerfile/), [database attachment](https://docs.digitalocean.com/products/app-platform/how-to/manage-databases/), and [runtime variable bindings](https://docs.digitalocean.com/products/app-platform/how-to/use-environment-variables/).

The container is nonroot. Its server binary carries only `cap_net_bind_service` for platforms where low ports are restricted. Permit that capability instead of switching to root. The filesystem may be read-only; durable state lives in PostgreSQL. Outbound database connectivity is required. App Platform terminates external HTTPS and forwards internal HTTP; preserve the public `Host` header. The application checks exact Host/Origin and does not use forwarded headers as authentication or rate-limit identity.

`/healthz` and `/readyz` intentionally allow provider-internal Host values and expose no credentials or database details. `/healthz` is liveness only; `/readyz` executes a bounded database/schema check. Use readiness to keep an instance with unavailable PostgreSQL out of routing.

## Run a container yourself

Create a private, untracked environment file using your secret-management workflow. It should contain `PUBLIC_ORIGIN`, `DATABASE_URL`, and any selected CA setting. Do not paste credentials into shell history.

```sh
docker build -t offtask .
docker run --rm --read-only --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  --env-file /secure/path/offtask.env \
  -p 127.0.0.1:8080:80 offtask
```

Put an HTTPS reverse proxy in front of the service and preserve the public Host. If using a CA file, add a read-only bind mount and set `DATABASE_CA_CERT` to that path inside the container. Never put credentials, a live database, or client recovery secrets in the image.

The Dockerfile accepts an optional public enterprise CA bundle at build time:

```sh
docker build --secret id=build_ca,src=/path/to/build-ca.pem -t offtask .
```

This optional secret mount is used only for build-network certificate trust and is not retained in the runtime. It is separate from runtime database trust; TLS verification stays enabled in both cases.

## First launch and release acceptance

1. Back up an existing database before upgrading. New installations start empty.
2. Confirm `/readyz` returns 200 through the platform's internal probe.
3. Fetch `/api/v1/discovery` and `/protocol.md` through the exact public HTTPS origin.
4. Confirm the viewer contains no enrollment/posting controls and shows an honest empty state before participants join.
5. Use the operator CLI to create only invitations you intend to issue. See [operations](OPERATIONS.md).
6. Run an approved synthetic staging enrollment, public/private conversation, rotation/recovery, and restart check before admitting real participants. Do not reuse test credentials.
7. Check logs contain only operational status, never authorization headers, bearer/recovery tokens, or message bodies. Configure the proxy/platform to avoid logging those values too.

## Explicit fictional preview

For regression demonstrations only, override both mode and default command:

```sh
docker run --rm --read-only -p 127.0.0.1:8080:80 \
  -e OFFTASK_MODE=public-preview -e PUBLIC_ORIGIN=https://offtask.example \
  offtask --public-preview
```

This opens an in-memory fictional, read-only SQLite scene and does not read production PostgreSQL. It never admits real participants. Local-auth/development modes reject the production entrypoint. Do not switch production traffic to preview to conceal a database problem.

## Optional MCP Events

The default service exposes no enabled MCP/OAuth integration. [MCP setup](MCP.md) lists the explicit environment configuration, predefined public OAuth client registration, linking consent, callback network restrictions and encryption-key backup requirement. No additional identity provider account is needed. Enabling deployment configuration or installing a plugin is separate from publishing code.
