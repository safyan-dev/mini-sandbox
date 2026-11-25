"""Build and verify the sandbox image, over the Engine API.

The image is the template every container is cloned from, so it is the one
place where "what is available to untrusted code" is decided. This module both
builds it and inspects the result, because a build succeeding says nothing
about whether the image is actually minimal or actually unprivileged.
"""

from __future__ import annotations

import io
import json
import tarfile
import urllib.parse

from sandbox import config, engine

# Checks run *inside* the image, as the default user. Emits key=value lines.
_VERIFY = r"""
echo "uid=$(id -u)"
echo "user=$(id -un)"
echo "shell=$(getent passwd "$(id -u)" | cut -d: -f7)"
echo "python=$(python3 -c 'import platform;print(platform.python_version())')"
echo "workdir=$(pwd)"
for t in gcc cc make curl wget git apt-get dpkg perl; do
  command -v "$t" >/dev/null && echo "has_$t=yes" || echo "has_$t=no"
done
echo "setuid_count=$(find / -perm -4000 -type f 2>/dev/null | wc -l)"
"""


def _image_path(name: str) -> str:
    return urllib.parse.quote(name, safe="")


def build(client: engine.Client, no_cache: bool = False) -> str:
    """Build the sandbox image from environment/Dockerfile. Returns the image id."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.add(str(config.DOCKERFILE_DIR / "Dockerfile"), arcname="Dockerfile")
    buffer.seek(0)

    query = {"t": config.SANDBOX_IMAGE, "rm": "1"}
    if no_cache:
        query["nocache"] = "1"
    path = "/build?" + urllib.parse.urlencode(query)

    status, raw = client.request(
        "POST",
        path,
        body=buffer.read(),
        headers={"Content-Type": "application/x-tar"},
        timeout=900,
    )
    if status >= 400:
        raise engine.EngineError("build failed (%d): %s" % (status, raw[:300]))

    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if "error" in event:
            raise engine.EngineError("build error: %s" % event["error"])

    return image_id(client)


def image_id(client: engine.Client) -> str:
    data = client.json("GET", "/images/%s/json" % _image_path(config.SANDBOX_IMAGE))
    return data.get("Id", "")


def info(client: engine.Client) -> dict:
    """Human-facing size and creation time of the sandbox image.

    The per-image endpoint reports compressed layer bytes (`.Size`), which
    understates the on-disk footprint. The image list reports the size a user
    actually sees, so that is what we surface here.
    """
    data = client.json("GET", "/images/%s/json" % _image_path(config.SANDBOX_IMAGE))

    size_bytes = None
    for entry in client.json("GET", "/images/json"):
        if config.SANDBOX_IMAGE in (entry.get("RepoTags") or []):
            size_bytes = entry.get("Size")
            break

    size = "unknown"
    if size_bytes:
        size = "%gMB" % round(size_bytes / 1_000_000, 1)

    return {
        "id": data.get("Id", "")[:19],
        "size": size,
        "created": (data.get("Created") or "")[:19],
    }


def verify(client: engine.Client) -> list:
    """Run the image and confirm it is minimal and unprivileged.

    Returns a list of (name, ok, detail) tuples.
    """
    created = client.json(
        "POST",
        "/containers/create",
        {
            "Image": config.SANDBOX_IMAGE,
            "Cmd": ["-c", _VERIFY],
            "Entrypoint": ["bash"],
            "AttachStdout": True,
            "AttachStderr": True,
        },
    )
    cid = created["Id"]
    try:
        client.request("POST", "/containers/%s/start" % cid)
        client.request("POST", "/containers/%s/wait" % cid, timeout=120)
        _, raw = client.request(
            "GET", "/containers/%s/logs?stdout=1&stderr=1" % cid, timeout=120
        )
        stdout, _ = engine.demux(raw)
    finally:
        client.request("DELETE", "/containers/%s?force=1&v=1" % cid)

    facts = {}
    for line in stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            facts[key.strip()] = value.strip()

    results = []

    uid = facts.get("uid", "?")
    results.append(
        (
            "non-root user",
            uid == str(config.SANDBOX_UID),
            "uid=%s user=%s" % (uid, facts.get("user", "?")),
        )
    )

    results.append(
        (
            "no login shell",
            facts.get("shell", "").endswith("nologin"),
            facts.get("shell", "?"),
        )
    )

    ver = facts.get("python", "")
    results.append(("python 3", ver.startswith("3."), "Python %s" % (ver or "missing")))

    results.append(
        (
            "workdir",
            facts.get("workdir") == config.SANDBOX_WORKDIR,
            facts.get("workdir", "?"),
        )
    )

    forbidden = ["gcc", "cc", "make", "curl", "wget", "git", "apt-get", "dpkg"]
    present = [t for t in forbidden if facts.get("has_%s" % t) == "yes"]
    results.append(
        (
            "no build/download tools",
            not present,
            "absent: %s" % ", ".join(forbidden)
            if not present
            else "present: %s" % ", ".join(present),
        )
    )

    setuid = int(facts.get("setuid_count") or 0)
    results.append(("no setuid binaries", setuid == 0, "%d found" % setuid))

    return results
