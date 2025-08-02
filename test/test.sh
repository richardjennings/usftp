#!/usr/bin/env bash
set +e
set -x
rm ssh_key ssh_key.pub  || true
ssh-keygen -t rsa -b 4096 -f ssh_key -P ""
docker compose down -v || true
docker compose up -d
go test -v ./...
S=$?
docker compose down -v || true
rm ssh_key ssh_key.pub  || true
exit $S