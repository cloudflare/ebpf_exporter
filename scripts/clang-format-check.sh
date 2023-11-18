#!/bin/bash

set -euo pipefail

exit_status=0

for file in "$@"; do
    ret=$(clang-format --dry-run --verbose -Werror "${file}"; echo $?)

    if [ "${ret}" != 0 ]; then
        diff --color=always --unified --show-c-function "${file}" <(clang-format --verbose -Werror "${file}") || true

        exit_status=$ret
    fi
done

exit "${exit_status}"
