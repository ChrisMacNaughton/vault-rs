# Vault
[![Build Status](https://travis-ci.org/ChrisMacNaughton/vault-rs.svg?branch=master)](https://travis-ci.org/ChrisMacNaughton/vault-rs)

[HashiCorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) API client for Rust.

You can start a local test server running using:

```bash
vault server -dev

vault version
Vault v1.12.0 (558abfa75702b5dab4c98e86b802fb9aef43b0eb), built 2022-10-10T18:14:33Z
```

Record the `Root Token:` printed at startup time, and use it to create a
test token:

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=<root token from server startup>
vault token create -id="test12345" -ttl="720h"
vault secrets enable transit
```

## High Availability

To use this with a highly available vault, you need to either let consul handle DNS for this crate or handle identifying the Vault leader separately.

## TODO

- Add support for managing Vault
