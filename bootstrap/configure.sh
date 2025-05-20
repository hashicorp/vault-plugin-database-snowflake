#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

PLUGIN_DIR=$1
PLUGIN_NAME=$2
CONNECTION_URL=$3
PRIVATE_KEY=$4

# validate these are set
[ "${PLUGIN_DIR:?}" ]
[ "${PLUGIN_NAME:?}" ]
[ "${CONNECTION_URL:?}" ]
[ "${PRIVATE_KEY:?}" ]

CONFIG=snowflake
ROLE=test-role

# Try to clean-up previous runs
vault secrets disable database
vault plugin deregister database "${PLUGIN_NAME}"
sleep 1

# Copy the binary so text file is not busy when rebuilding & the plugin is registered
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_DIR"

SHASUM="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')"

if [[ -z "$SHASUM" ]]; then echo "error: shasum not set"; exit 1; fi

# Sets up the binary with local changes
vault plugin register \
    -sha256="${SHASUM}" \
    database "${PLUGIN_NAME}"

vault secrets enable database

vault write database/config/${CONFIG} \
    plugin_name=${PLUGIN_NAME} \
    allowed_roles=${ROLE} \
    connection_url=${CONNECTION_URL} \
    private_key=${PRIVATE_KEY} \
    username='hashicorpvault'

vault write database/roles/${ROLE} \
    db_name=${CONFIG} \
    creation_statements="CREATE USER {{name}} PASSWORD = '{{password}}'
        DAYS_TO_EXPIRY = {{expiration}} DEFAULT_ROLE=public;
        GRANT ROLE public TO USER {{name}};" \
    default_ttl="1h" \
    max_ttl="24h"

vault read database/creds/${ROLE}
