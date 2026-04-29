set dotenv-load := true

export CERBOS_TEST_DEBUG := "true"
export TOOLS_BIN_DIR := join(env_var_or_default("XDG_CACHE_HOME", join(env_var("HOME") , ".cache")), "cerbos-sdk-go/bin")
export PATH := TOOLS_BIN_DIR + ":" + env_var("PATH")

tools_mod_dir := join(justfile_directory(), "tools")

default:
    @ just --list

deps:
    @ go mod tidy
    @ go -C tools mod tidy

lint: lint-modernize _golangcilint
    @ "${TOOLS_BIN_DIR}/golangci-lint" run --fix

lint-modernize: _modernize
    @ GOFLAGS=-tags=tests,integration modernize -fix -test ./...

test PKG='./...' TEST='.*': _gotestsum
    @ gotestsum --format-hide-empty-pkg -- -tags=tests,integration -failfast -v -count=1 -run='{{ TEST }}' '{{ PKG }}'

tests: _gotestsum
    @ gotestsum --format=dots-v2 --format-hide-empty-pkg -- -tags=tests,integration -failfast -count=1 ./...

compile:
    @ go build -o /dev/null ./...

_golangcilint: (_install "golangci-lint")

_gotestsum: (_go-install "gotestsum" "gotest.tools/gotestsum")

_install-tools: (_go-install "install-tools" "github.com/cerbos/actions" "cmd/install-tools")

_modernize: (_go-install "modernize" "golang.org/x/tools" "go/analysis/passes/modernize/cmd/modernize")

_go-install EXECUTABLE MODULE CMD_PKG="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ tools_mod_dir }}
    TMP_VERSION=$(GOWORK=off go list -m -f "{{{{.Version}}" "{{ MODULE }}")
    VERSION="${TMP_VERSION#v}"
    BINARY="${TOOLS_BIN_DIR}/{{ EXECUTABLE }}"
    SYMLINK="${BINARY}-${VERSION}"
    if [[ ! -e "$SYMLINK" ]]; then
      echo "Installing $SYMLINK" 1>&2
      mkdir -p "$TOOLS_BIN_DIR"
      find "${TOOLS_BIN_DIR}" -lname "$BINARY" -delete
      PKG={{ if CMD_PKG != "" { MODULE + "/" + CMD_PKG } else { MODULE } }}
      GOBIN="$TOOLS_BIN_DIR" GOWORK=off go install "${PKG}@v${VERSION}"
      ln -s "$BINARY" "$SYMLINK"
    fi

[positional-arguments]
_install *EXECUTABLES:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ "${CI:-}" = "true" ]]; then
    for executable in "$@"; do
      if ! hash "${executable}" 2>/dev/null; then
        printf "\e[31m%s not found\e[0m\nUse cerbos/actions/install-tools to install it\n" "${executable}"
      fi
    done
  else
    just _install-tools
    cd "${TOOLS_BIN_DIR}"
    install-tools "$@"
  fi
