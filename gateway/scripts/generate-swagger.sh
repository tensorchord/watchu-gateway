#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v swag >/dev/null 2>&1; then
	GO111MODULE=on GOSUMDB=off go install github.com/swaggo/swag/cmd/swag@latest
fi

SWAG_BIN="$(command -v swag || true)"
if [ -z "$SWAG_BIN" ]; then
	SWAG_BIN="$(go env GOPATH)/bin/swag"
fi

if [ ! -x "$SWAG_BIN" ]; then
	echo "Unable to locate swag binary" >&2
	exit 1
fi

cd "$ROOT_DIR"

"$SWAG_BIN" init \
	-g ./cmd/gateway/main.go \
	--parseDependency \
	--parseInternal \
	--output ./pkg/docs
