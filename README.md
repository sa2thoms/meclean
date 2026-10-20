# meclean

Small web page for deleting files in a directory mounted into a container.
It lists regular files (including files in subdirectories) and removes the
ones you confirm.

There is **no authentication**. Run it only on a trusted LAN, or behind your
own reverse proxy on a private network. Do not expose it to the internet:
anyone who can open the page can delete files.

## What it shows

- The root directory is `MECLEAN_ROOT` (default `/data`).
- Subdirectories are scanned recursively. Each row is a path relative to the root.
- Newest modification time comes first. Times use the container's local timezone.
- Only regular files are listed. Directories are not deleted.
- Symbolic links are not deleted. A directory symlink is not followed, so a
  link that points outside the root cannot be used to reach other files.
- Delete is a POST. The button asks for confirmation, and the form includes a
  token generated when the process starts. A request with an `Origin` header
  must match `Host` (forward the original `Host` from your proxy).

Paths are resolved and rejected when they fall outside the root.

## Docker Compose

Example suitable for Dockge. Point the volume at the directory you want to
clean, and set `user` to an account that can write that directory (deleting a
file updates its parent directory). `user:` overrides the image's default
uid/gid of 1000.

```yaml
services:
  meclean:
    image: ghcr.io/sa2thoms/meclean:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - /path/on/host:/data
    user: "1000:1000"
```

The same file is in `docker-compose.yml`. Then open `http://<host>:8080/`.

A `GET /health` endpoint returns `ok` for the image health check.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `MECLEAN_ROOT` | `/data` | Directory to list and delete from |
| `MECLEAN_HOST` | `0.0.0.0` | Address to listen on |
| `MECLEAN_PORT` | `8080` | Port to listen on |

Inside the image these defaults listen on `0.0.0.0:8080` and read `/data`.

## Run locally

```bash
mkdir -p /tmp/meclean-data
echo hello > /tmp/meclean-data/hello.txt
MECLEAN_ROOT=/tmp/meclean-data python3 meclean.py
```

The page is at `http://127.0.0.1:8080/`.

Build and run the image yourself:

```bash
docker build -t meclean .
docker run --rm -p 8080:8080 -v /path/on/host:/data -u "$(id -u):$(id -g)" meclean
```

## Tests

```bash
python3 -m unittest -v test_meclean.py
```

## Image

GitHub Actions builds `linux/amd64` and `linux/arm64` and publishes
`ghcr.io/sa2thoms/meclean`. Pushes to `main` tag the image `latest`. Tags
matching `v*` publish that version (for example `v1.2.3`). Pull requests build
the image and do not push it. A new GHCR package is private until you change
its visibility.

## License

[The Unlicense](LICENSE) — public domain.
