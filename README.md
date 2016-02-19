# Vault

[![Build Status](https://travis-ci.org/ChrisMacNaughton/vault-rs.svg?branch=master)](https://travis-ci.org/ChrisMacNaughton/vault-rs)

[HashiCorp](https://hashicorp.com/) [Vault](https://www.vaultproject.io) API client for Rust.

```bash
vault server -dev
```

```bash
vault token-create -id="test12345"
```

## High Availability

To use this with a highly available vault, you need to either let consul handle DNS for this crate or handle identifying the Vault leader separately.

## TODO

- Add support for managing Vault
