# Deployment Guide

This guide covers running `file-scanner` as a service: the MCP server over HTTP, and the container image.
For one user on one machine, use `mcp-stdio` from the MCP client instead (see [docs/MCP.md](docs/MCP.md)).
It needs no network port.

## What the server does and does not protect

The server reads files and returns what it finds in them. Whoever can call it can read every file
the server's user can read, unless you narrow that with `--allow-root`.

What exists:

- Loopback bind by default (`--host 127.0.0.1`).
- A `Host` header allow-list and an `Origin` allow-list (`--allowed-host`, `--allowed-origin`).
- An optional bearer token (`--auth-token` or `FILE_SCANNER_AUTH_TOKEN`) on every route except `/health`.
- A path scope (`--allow-root`, repeatable, or `FILE_SCANNER_ALLOWED_ROOTS`): every tool path must
  resolve, symlinks and `..` included, to a place under one of the roots.
- A limit of 16 concurrent REST requests and a 120 second REST timeout.

What does not exist, and belongs in the layer in front of the server:

- TLS. The server speaks plain HTTP. Terminate TLS in a reverse proxy or the platform load balancer.
- Rate limiting. Put it in the reverse proxy.
- Per-user accounts or API keys. There is one shared bearer token.
- A configuration file. Everything is a command-line flag or one of the environment variables below.
- `/ready` and `/metrics` routes. Use `/health` for liveness and readiness.

## Command-line reference

`file-scanner mcp-http` (`mcp-sse` is a deprecated alias that starts the same server):

```text
  -p, --port <PORT>              Port to listen on (0 picks a free one) [default: 3000]
      --host <HOST>              Address to bind [default: 127.0.0.1]
      --allowed-host <HOST>      Extra Host header value to accept (`name` or `name:port`); repeatable
      --allowed-origin <ORIGIN>  Extra browser Origin to accept (`scheme://host[:port|:*]`); repeatable
      --auth-token <TOKEN>       Bearer token every request except /health must present
      --allow-root <DIR>         Directory the tools may read; repeatable
      --cache-dir <DIR>          Directory for cached results (private, mode 0700)
      --no-cache                 Turn result caching off
```

`file-scanner mcp-stdio` takes `--allow-root`, `--cache-dir` and `--no-cache`.

Environment variables the binary reads:

| Variable | Effect |
|----------|--------|
| `FILE_SCANNER_AUTH_TOKEN` | Same as `--auth-token`. Prefer it: command lines are visible to other users. |
| `FILE_SCANNER_ALLOWED_ROOTS` | `:`-separated directories; used when no `--allow-root` is given. |
| `FILE_SCANNER_CACHE_DIR` | Same as `--cache-dir`. |
| `FILE_SCANNER_SECTION_CACHE_MB` | In-memory budget of the section cache, in MiB (default 256). |
| `FILE_SCANNER_CACHE_DISK_MB` | On-disk cache budget, in MiB. |
| `XDG_CACHE_HOME`, `HOME` | Choose the default cache directory (below). |

No other variable has an effect. `RUST_LOG` does nothing: the server has no logger. It prints a startup
banner and one line per refused request on stderr.

The default cache directory is `$XDG_CACHE_HOME/file-scanner`, else `~/Library/Caches/file-scanner`
on macOS or `~/.cache/file-scanner` elsewhere, else a per-user directory under the system temp directory.

## Run it on a host

Local use, loopback only:

```bash
file-scanner mcp-http --port 3000 --allow-root /srv/samples
```

Real startup output (shortened):

```text
file-scanner 0.3.9 MCP HTTP server listening on http://127.0.0.1:3000/mcp
  REST helpers on the same address: /health, /api/info, /tools/list, /tools/call, /cache/*, /strings/*, ...
  Host allow-list: localhost, 127.0.0.1, ::1
  Origin check: loopback origins; no CORS wildcard
  Bearer token: not set
  File access: limited to /srv/samples
```

To let other machines connect, bind a non-loopback address and set all three protections:

```bash
export FILE_SCANNER_AUTH_TOKEN="$(openssl rand -hex 32)"
file-scanner mcp-http --host 0.0.0.0 --port 3000 \
  --allow-root /srv/samples \
  --allowed-host scanner.internal:3000
```

If you bind `0.0.0.0` without a token, the server prints a warning and still starts. If you do not
add `--allowed-host`, remote clients get `403` because their `Host` header is not on the list.

How `--allowed-host` matches (checked against a running server): `localhost`, `127.0.0.1` and `::1` are
always accepted on any port. A bare name such as `scanner.example.com` matches that name on any port. A
`name:port` entry matches only that exact name and port. A name that is not listed gets `403`. Repeat the
flag for every name clients use (`file-scanner`, `file-scanner.default.svc`, and so on); a short name does
not match its fully qualified form.

Check it from a second terminal in which the same token is exported. The server holds the first terminal, so
print the token there with `echo "$FILE_SCANNER_AUTH_TOKEN"` before you start it:

```bash
curl -s http://127.0.0.1:3000/health
# {"status":"ok","service":"file-scanner-mcp","version":"0.3.9","transports":["streamable-http"]}

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:3000/tools/list
# 401   (when a token is set and none is sent)

curl -s -X POST http://127.0.0.1:3000/tools/list \
  -H "Authorization: Bearer $FILE_SCANNER_AUTH_TOKEN" |
  python3 -c 'import sys,json; print(len(json.load(sys.stdin)["result"]["tools"]))'
# 17
```

`/tools/list` is one of the REST helper routes. The MCP endpoint itself, `/mcp`, is for MCP clients: it
needs an `Accept: application/json, text/event-stream` header (without it the answer is `406`) and an
initialized session.

A client sends `Authorization: Bearer <token>` on every request. Stop the server with Ctrl-C or SIGTERM.

### systemd

Create the user and the token file first:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin file-scanner
echo "FILE_SCANNER_AUTH_TOKEN=$(openssl rand -hex 32)" | sudo install -m 600 /dev/stdin /etc/file-scanner.env
```

The unit file, `/etc/systemd/system/file-scanner.service`:

```ini
[Unit]
Description=file-scanner MCP server
After=network.target

[Service]
User=file-scanner
EnvironmentFile=/etc/file-scanner.env
ExecStart=/usr/local/bin/file-scanner mcp-http --port 3000 --allow-root /srv/samples
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CacheDirectory=file-scanner
Environment=FILE_SCANNER_CACHE_DIR=/var/cache/file-scanner
ReadOnlyPaths=/srv/samples

[Install]
WantedBy=multi-user.target
```

`/etc/file-scanner.env` holds one line, `FILE_SCANNER_AUTH_TOKEN=...`, readable by root only. This unit
binds loopback; put the reverse proxy on the same host. This unit was not run for this guide.

### Reverse proxy

Put TLS and rate limiting here. Forward the original `Host` header (or add the proxy's public name with
`--allowed-host`) and do not buffer `/mcp`, because responses can be streamed. A minimal nginx
configuration (the `limit_req_zone` line belongs in the `http` block; nginx rejects `limit_req` without it):

```nginx
limit_req_zone $binary_remote_addr zone=scanner:10m rate=5r/s;

location /mcp {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_read_timeout 300s;
    limit_req zone=scanner burst=10;
}
```

Start the server with `--allowed-host scanner.example.com` to match. This snippet was not run.

## Container image

The image is published at `ghcr.io/threatflux/file-scanner`. The runtime stage is Chainguard
`glibc-dynamic` (Wolfi): it runs as uid 65532, with no shell and no package manager. The working directory
is `/data`. The entrypoint is `tini -- file-scanner` and there is no default command, so you always pass
arguments: a file path, a subcommand, or `--help`.

The container sees only what you mount. Tool calls name paths inside the container, so mount the files
and pass the same path in the tool call. Mount read-only (`:ro`).

Scan one file:

```bash
docker run --rm -v "$PWD:/data:ro" ghcr.io/threatflux/file-scanner /data/sample.bin --format json
```

MCP over stdio for a client on the same machine. Keep the host path identical inside the container, so
the client can pass the paths it already has:

```bash
docker run -i --rm -v "$PWD:$PWD:ro" -w "$PWD" ghcr.io/threatflux/file-scanner mcp-stdio --allow-root "$PWD"
```

Claude Code:

```bash
claude mcp add file-scanner -- docker run -i --rm -v "$PWD:$PWD:ro" -w "$PWD" \
  ghcr.io/threatflux/file-scanner mcp-stdio --allow-root "$PWD"
```

MCP over HTTP, published on loopback only, with a token and a read-only mount:

```bash
export FILE_SCANNER_AUTH_TOKEN="$(openssl rand -hex 32)"
docker run -d --name file-scanner --rm -p 127.0.0.1:3000:3000 \
  -e FILE_SCANNER_AUTH_TOKEN \
  -v /srv/samples:/data:ro \
  ghcr.io/threatflux/file-scanner \
  mcp-http --host 0.0.0.0 --port 3000 --allow-root /data
```

`-e FILE_SCANNER_AUTH_TOKEN` with no value passes the variable from your shell, so the container and your
client use the same token. The container runs detached; check it from the same shell, and end it with
`docker stop file-scanner`:

```bash
curl -s http://127.0.0.1:3000/health
curl -s -X POST http://127.0.0.1:3000/tools/list \
  -H "Authorization: Bearer $FILE_SCANNER_AUTH_TOKEN" | head -c 200
```

Inside the container the server must bind `0.0.0.0` so that Docker can forward to it. Publishing the
port on `127.0.0.1` on the host is what keeps it private. Clients that connect as `localhost` or
`127.0.0.1` are always allowed, so this command needs no `--allowed-host`; for any other name, add one
`--allowed-host` for every host name clients use (see the matching rule above). Clients pass `/data/...`
paths. To reach it from other hosts, publish on a non-loopback address and add the proxy in front of it as
above.

Notes:

- The container runs as uid 65532. Files you mount must be readable by that user. If they are not
  world-readable, run as yourself with `--user "$(id -u):$(id -g)"` (add `--cache-dir` under `/tmp`, as
  below, because that user cannot write to the image's own directories).
- The cache directory should be writable. If it is not, the server prints "cache directory ... is not
  usable" on stderr and keeps results in memory only. With `docker run --read-only`, add `--tmpfs /tmp` and
  `--cache-dir /tmp/file-scanner-cache` to keep the on-disk cache.
- The image's `HEALTHCHECK` runs `file-scanner --help`, which only proves that the binary starts. For
  the HTTP server, probe `GET /health`.
- Build it yourself with `docker build -t file-scanner .`.

The untagged image is `latest`. At the time of writing, the published image is the 0.3.9 release, which
does not have `--allow-root`, `--host`, `--allowed-host` or token support: these commands need the image
from the release that follows it, or one you build yourself with `docker build -t file-scanner .` (then
use `file-scanner` in place of `ghcr.io/threatflux/file-scanner`).
The `docker run` commands above are written from the Dockerfile's `ENTRYPOINT` and `WORKDIR`. They were
not run against a built image when this guide was written; the same arguments were run against the
native binary.

## Kubernetes

The image has no default command, so set `args`. A Deployment that serves HTTP with a token from a
Secret, a read-only volume of files, and a writable `/tmp`. The manifest refers to a Secret named
`file-scanner` with the key `token`, a PersistentVolumeClaim named `samples`, and a Service named
`file-scanner`. Create the Secret first:

```bash
kubectl create secret generic file-scanner --from-literal=token="$(openssl rand -hex 32)"
```

To read the token back for a client, run
`kubectl get secret file-scanner -o jsonpath='{.data.token}' | base64 -d`.

The image is `:latest`, which at the time of writing is the 0.3.9 release. It does not have `--allow-root`,
`--host`, `--allowed-host` or token support, so this manifest needs an image from a later release or one you
build yourself.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: file-scanner
spec:
  replicas: 1
  selector:
    matchLabels: { app: file-scanner }
  template:
    metadata:
      labels: { app: file-scanner }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
      containers:
        - name: file-scanner
          image: ghcr.io/threatflux/file-scanner:latest
          args:
            - mcp-http
            - --host=0.0.0.0
            - --port=8080
            - --allow-root=/data
            - --allowed-host=file-scanner
            - --allowed-host=file-scanner.default.svc
            - --cache-dir=/tmp/file-scanner-cache
          env:
            - name: FILE_SCANNER_AUTH_TOKEN
              valueFrom:
                secretKeyRef: { name: file-scanner, key: token }
          ports:
            - containerPort: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
              httpHeaders: [{ name: Host, value: localhost }]
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
              httpHeaders: [{ name: Host, value: localhost }]
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: [ALL] }
          volumeMounts:
            - { name: samples, mountPath: /data, readOnly: true }
            - { name: tmp, mountPath: /tmp }
      volumes:
        - name: samples
          persistentVolumeClaim: { claimName: samples }
        - name: tmp
          emptyDir: {}
```

`/health` is behind the Host allow-list too. A kubelet probe sends the pod IP as `Host`, which is not on
the list and gets `403`, so the probes above set `Host: localhost`, which is always allowed. Without that
header the pod is restarted and never becomes ready. List every name clients use for the Service: the
short name and the `.default.svc.cluster.local` form are different entries.

Expose it with a ClusterIP Service named `file-scanner`, added to the same file after a line containing `---`:

```yaml
---
apiVersion: v1
kind: Service
metadata:
  name: file-scanner
spec:
  selector: { app: file-scanner }
  ports:
    - port: 8080
      targetPort: 8080
```

If you add an Ingress, terminate TLS and rate-limit there, and add its
public name with another `--allowed-host`. Do not expose the Service to the internet without the token.
This manifest was not applied to a cluster for this guide. Use one replica: the cache and the string
index live in the process, and MCP sessions are held by the process that opened them.

## MCP registry file

`server.json` at the repository root describes the server for the MCP registry. It cannot be published as it
stands. These must be true first:

- The three version strings (`version`, the cargo package `version` and the tag in the OCI `identifier`) say
  0.3.9 and nothing in the release automation updates them. Set them by hand to a release that has these
  features, in the same change that bumps `Cargo.toml`. Because 0.3.9 does not accept `--allow-root`, the file
  passes only `mcp-stdio`; add `--allow-root` back to the arguments once the versions name a release that has it.
- `README.md` must contain an `mcp-name: io.github.threatflux/file-scanner` line, which the registry is expected
  to use to check ownership of the cargo package.
- The OCI image must carry the `io.modelcontextprotocol.server.name` label. The Dockerfile now sets it, but the
  0.3.9 image does not have it.
- Not confirmed: whether the registry accepts `registryType` `cargo`, and whether it accepts the lower-case
  `io.github.threatflux` namespace. Check both when publishing.

The file was checked by hand against the registry schema, not validated online.

## Building a custom image

The repository `Dockerfile` is the supported build. It needs the whole repository, because Cargo
patches three crates from `vendor/`, so a Dockerfile that copies only `Cargo.toml`, `Cargo.lock` and
`src/` cannot resolve its dependencies.

## Checking a deployment

`scripts/mcp-smoke.py` runs a real MCP handshake against a local binary: initialize, the initialized
notification, `tools/list`, an overview call and a cached drill-down.

```bash
python3 scripts/mcp-smoke.py target/release/file-scanner
# MCP handshake, tools/list (17 tools), analyze_file overview and cached query_analysis passed
```

It starts the binary itself over stdio, so it does not test a container or the HTTP server. For those,
call `/health` and `POST /tools/list` with your token, as shown above.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `403` from a remote client | The client's `Host` is not allowed. Add `--allowed-host name[:port]`. |
| `401` | A token is set and the request has no `Authorization: Bearer ...` header. |
| Path is outside the directories the server may read | Not under any `--allow-root`. Pass a path under one. |
| Tool says the file does not exist | In a container, the file is not mounted at that path. |
| stderr: cache directory "is not usable" | Not writable; results stay in memory. Fix `--cache-dir`. |
| Port already in use | Pick another port, or `--port 0` and read the port from the startup banner. |
