# Vault
[![Build Status](https://travis-ci.org/ChrisMacNaughton/vault-rs.svg?branch=master)](https://travis-ci.org/ChrisMacNaughton/vault-rs)

[HashiCorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) API client for Rust.


```toml
hashicorp_vault = "0.7"
```

## Local server
You can start a local test server running using:

```bash
# Pre-1.0 versions of Vault w/ kv secrets v1 only
vault server -dev

# v1.0.1+ versions of Vault w/ kv secrets v2 as default dev mode
# See: https://github.com/hashicorp/vault/pull/5919
vault server -dev-kv-v1
```

Record the `Root Token:` printed at startup time, and use it to create a
test token:

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=<root token from server startup>
vault token-create -id="test12345" -ttl="720h"
```

Or you can use the provided `docker-compose.yml` to start a containerized vault.

```bash
docker-compose up -d
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=vault
vault token create -id="test12345" -ttl="720h"

# You need to enable the transit secrets engine for `cargo test`
vault secrets enable transit
```

## High Availability

To use this with a highly available vault, you need to either let consul handle DNS for this crate or handle identifying the Vault leader separately.

## TODO

- Add support for managing Vault

## Features
### Vault 1.3.x support

You can enable the `vault_1_3` feature in your `Cargo.toml`

```toml
hashicorp_vault = { version = "0.7", features = ["vault_1_3"] }
```