# Vault

# [![Build Status](https://git.cmacinfo.com/chris/cault-rs/badges/master/build.svg)](https://git.cmacinfo.com/chris/cault-rs/builds)

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
