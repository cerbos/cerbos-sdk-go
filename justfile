set dotenv-load := true

export TOOLS_BIN_DIR := join(env_var_or_default("XDG_CACHE_HOME", join(env_var("HOME") , ".cache")), "cerbos-sdk-go/bin")
genpb_dir := join(justfile_directory(), "client", "genpb")
tools_mod_dir := join(justfile_directory(), "tools")

default:
    @ just --list

generate-protos: _buf
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf {{ genpb_dir }}
    cd {{ tools_mod_dir }} # Needed to let Buf read the plugin versions from go.mod
    "${TOOLS_BIN_DIR}/buf" generate --template=buf.gen.yaml --output=.. buf.build/cerbos/cerbos-api

_buf: (_install "buf" "github.com/bufbuild/buf" "cmd/buf")

_gotestsum: (_install "gotestsum" "gotest.tools/gotestsum")

_install EXECUTABLE MODULE CMD_PKG="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ tools_mod_dir }}
    TMP_VERSION=$(GOWORK=off go list -m -f "{{{{.Version}}" "{{ MODULE }}")
    VERSION="${TMP_VERSION#v}"
    SYMLINK="${TOOLS_BIN_DIR}/{{ EXECUTABLE }}-${VERSION}"
    if [[ ! -e "$SYMLINK" ]]; then
      echo "Installing $SYMLINK"
      mkdir -p "$TOOLS_BIN_DIR"
      BINARY="${TOOLS_BIN_DIR}/{{ EXECUTABLE }}"
      find "${TOOLS_BIN_DIR}" -lname "$BINARY" -delete
      GOBIN="$TOOLS_BIN_DIR" go install {{ if CMD_PKG != "" { MODULE + "/" + CMD_PKG } else { MODULE } }}
      ln -s "$BINARY" "$SYMLINK"
    fi
