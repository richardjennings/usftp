#!/usr/bin/env bash
set +e
set -x
make test-setup
go test -v ./...
S=$?
make test-setdown
exit $S