# MiniSandbox sandbox image (Stage 2)
#
# A minimal Linux template that can run a Python 3 program as an unprivileged
# user, and nothing more. Design rules:
#   - only the Python 3 interpreter is installed, no recommended packages
#   - the package manager and its perl dependency are removed after install,
#     so untrusted code cannot install anything
#   - no compiler, no curl/wget/git, so nothing can be built or downloaded
#   - setuid bits are cleared, so no binary can raise privileges
#   - nothing is COPYed from the host: no personal files, no credentials
#   - a dedicated non-root user runs the code
#
# The controller never builds this with a shell string; docker.py passes argv
# as a list.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

# Install only the interpreter, then delete every trace of the package manager
# and the per-package metadata it would need. Removing apt/dpkg by file (rather
# than apt purge) is how minimal images shrink: apt refuses to uninstall itself.
# Dropping the setuid bit from the remaining utilities removes the escalation
# path those binaries would otherwise offer.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt/* \
 && rm -rf /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-* \
           /usr/bin/dpkg /usr/bin/dpkg-* /usr/sbin/dpkg* \
           /usr/lib/apt /usr/lib/dpkg /usr/share/dpkg /usr/share/doc/dpkg* /etc/apt \
 && rm -rf /usr/bin/perl /usr/bin/perl5* /usr/lib/*/perl* /usr/lib/perl* /usr/share/perl* \
 && find / -perm -4000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Drop the stock login user and create the unprivileged identity that runs
# untrusted code. The nologin shell leaves no interactive login path.
RUN userdel --remove ubuntu 2>/dev/null || true \
 && useradd --create-home --uid 1000 --shell /usr/sbin/nologin sandbox

WORKDIR /sandbox
RUN chown sandbox:sandbox /sandbox

USER sandbox

ENTRYPOINT ["python3"]
