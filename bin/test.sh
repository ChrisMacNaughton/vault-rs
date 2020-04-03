#!/bin/bash

set -eux

for VAULT_VERSION in 1.2.0 1.2.1 1.2.2 1.2.3 1.2.4 1.3.0 1.3.1 1.3.2 1.3.3 1.3.4 1.4.0-rc1 ; do
    curl -o /tmp/vault.zip -sOL https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip
    unzip -o /tmp/vault.zip
    ./vault server -dev  > /dev/null 2>&1 &
    sleep 3
    ./vault token create -id="test12345" -ttl="720h" > /dev/null
    ./vault secrets enable transit > /dev/null
    ./vault write -f transit/keys/test-vault-rs > /dev/null
    echo "About to test the library against Vault ${VAULT_VERSION}"
    cargo test
    killall vault
done
