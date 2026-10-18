#!/bin/sh
set -eu
umask 0007

node /opt/intake/docker/prepare-bw-socket.js "${INTAKE_SOCKET:-/run/intake/writer.sock}" writer
exec "$@"
