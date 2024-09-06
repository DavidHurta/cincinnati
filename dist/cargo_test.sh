#!/usr/bin/env bash

set -e

declare -A cargo_test_flags
cargo_test_flags["cincinnati"]="--features test-net"
cargo_test_flags["commons"]=""
cargo_test_flags["graph-builder"]="--features test-net"
cargo_test_flags["policy-engine"]=""
cargo_test_flags["prometheus-query"]=""
cargo_test_flags["quay"]="--features test-net"

if [[ -n "${CINCINNATI_TEST_CREDENTIALS_PATH}" && -n "${CINCINNATI_TEST_QUAY_API_TOKEN_PATH}" ]]; then
    echo Secrets available, enabling private tests...
    cargo_test_flags["cincinnati"]+=",test-net-private"
    cargo_test_flags["graph-builder"]+=",test-net-private"
    cargo_test_flags["quay"]+=",test-net-private"

    export CINCINNATI_TEST_QUAY_API_TOKEN="$(cat ${CINCINNATI_TEST_QUAY_API_TOKEN_PATH})"
fi

declare -A executors
executors["cargo"]="execute_native"

function run_tests() {
  set -x
  export CARGO_TARGET_DIR="$PWD/target"

  if [[ $(type -f kcov) ]]; then
    export HAS_KOV="${HAS_KOV:-1}"
    rm -rf "${CARGO_TARGET_DIR}"/cov
  fi

  has_failed=false
  for directory in ${!cargo_test_flags[*]}; do
    if [[ "${HAS_KOV}" -eq "1" ]]; then
      # we want to prevent completely untested functions to be stripped
      export RUSTFLAGS='-C link-dead-code'
    fi

    if ! /usr/bin/env bash -c "\
        set -xe
        cd ${directory}
        cargo test --no-run
        mapfile -t tests < <(
          cargo test --no-run --message-format=json ${cargo_test_flags[${directory}]} | \
            jq -r 'select(.profile.test == true) | .executable'
        )
        for test in \${tests[@]}; do
          if [[ \"${HAS_KOV}\" -eq \"1\" ]]; then
            kcov \
              --exclude-pattern=$HOME/.cargo \
              --verify \
              ${CARGO_TARGET_DIR}/cov \
              \$test
          else
            \$test
          fi
        done
      "; then
      has_failed=true
    fi

  done

  if [[ "${HAS_KOV}" -eq "1" && -n "${ARTIFACTS_DIR}" ]]; then
    mkdir -p "${ARTIFACTS_DIR}"
    [[ ! -e "${ARTIFACTS_DIR}"/cov ]] || rm -rf "${ARTIFACTS_DIR}"/cov
    cp -rf "${CARGO_TARGET_DIR}"/cov "${ARTIFACTS_DIR}"/
  fi

  if [ "${has_failed}" == true ]; then
    echo "at least one error has occurred while running tests; check the output for more information"
    exit 1
  fi

  set +x
}

function execute_native() {
  run_tests
}

for executor in "${!executors[@]}"; do
  if type -f $executor; then
    ${executors[${executor}]}
    exit 0
  fi
done

echo error: could not find any of "${executors[@]}" in PATH
exit 1
