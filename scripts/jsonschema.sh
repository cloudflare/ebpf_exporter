#!/bin/bash

set -euo pipefail

exit_status=0

for example in examples/*.yaml; do
    echo "Checking ${example}..."
    ret=$(jsonschema --instance <(yq --output-format=json < $example) <(yq --output-format=json < .vscode/config-schema.yaml); echo $?)
    if [ "${ret}" != 0 ]; then
        exit_status=$ret
    fi
done

exit "${exit_status}"
