set dotenv-load := true

export TOOLS_BIN_DIR := join(env_var_or_default("XDG_CACHE_HOME", join(env_var("HOME") , ".cache")), "cerbos-sdk-go/bin")
export CERBOS_TEST_CONTAINER_TAG := "dev"
export CERBOS_TEST_DEBUG := "true"

tools_mod_dir := join(justfile_directory(), "tools")

default:
    @ just --list

lint: lint-modernize _golangcilint
    @ "${TOOLS_BIN_DIR}/golangci-lint" run --fix

lint-modernize: _modernize
    @ GOFLAGS=-tags=tests,integration "${TOOLS_BIN_DIR}/modernize" -fix -test ./...

test PKG='./...' TEST='.*': _gotestsum
    @ "${TOOLS_BIN_DIR}/gotestsum" --format-hide-empty-pkg -- -tags=tests,integration -failfast -v -count=1 -run='{{ TEST }}' '{{ PKG }}'

tests: _gotestsum
    @ "${TOOLS_BIN_DIR}/gotestsum" --format=dots-v2 --format-hide-empty-pkg -- -tags=tests,integration -failfast -count=1 ./...

compile:
    @ go build -o /dev/null ./...

_gotestsum: (_install "gotestsum" "gotest.tools/gotestsum")

_golangcilint: (_install "golangci-lint" "github.com/golangci/golangci-lint" "cmd/golangci-lint")

_modernize: (_install "modernize" "golang.org/x/tools/gopls" "internal/analysis/modernize/cmd/modernize")

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
