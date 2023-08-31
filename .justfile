set dotenv-load := true

export TOOLS_BIN_DIR := join(env_var_or_default("XDG_CACHE_HOME", join(env_var("HOME") , ".cache")), "cerbos-sdk-go/bin")
genpb_dir := join(justfile_directory(), "genpb")
tools_mod_dir := join(justfile_directory(), "tools")

default:
    @ just --list

generate-protos: _buf
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf {{ genpb_dir }}
    cd {{ tools_mod_dir }} # Needed to let Buf read the plugin versions from go.mod
    "${TOOLS_BIN_DIR}/buf" generate --template=buf.gen.yaml --output=.. buf.build/cerbos/cerbos-api

lint: _golangcilint
    @ "${TOOLS_BIN_DIR}/golangci-lint" run --fix

test PKG='./...' TEST='.*': _gotestsum
    @ "${TOOLS_BIN_DIR}/gotestsum" --format=dots-v2 --format-hide-empty-pkg -- -tags=tests,integration -failfast -count=1 -run='{{ TEST }}' '{{ PKG }}'

compile:
    @ go build -o /dev/null ./...

_buf: (_install "buf" "github.com/bufbuild/buf" "cmd/buf")

_gotestsum: (_install "gotestsum" "gotest.tools/gotestsum")

_golangcilint: (_install "golangci-lint" "github.com/golangci/golangci-lint" "cmd/golangci-lint")

_install EXECUTABLE MODULE CMD_PKG="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ tools_mod_dir }}
    TMP_VERSION=$(GOWORK=off go list -m -f "{{{{.Version}}" "{{ MODULE }}")
    VERSION="${TMP_VERSION#v}"
    BINARY="${TOOLS_BIN_DIR}/{{ EXECUTABLE }}"
    SYMLINK="${BINARY}-${VERSION}"
    if [[ ! -e "$SYMLINK" ]]; then
      echo "Installing $SYMLINK"
      mkdir -p "$TOOLS_BIN_DIR"
      find "${TOOLS_BIN_DIR}" -lname "$BINARY" -delete
      if [[ "{{ EXECUTABLE }}" == "golangci-lint" ]]; then
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$TOOLS_BIN_DIR"
      else
        GOBIN="$TOOLS_BIN_DIR" go install {{ if CMD_PKG != "" { MODULE + "/" + CMD_PKG } else { MODULE } }}
      fi
      ln -s "$BINARY" "$SYMLINK"
    fi
