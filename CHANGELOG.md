## NEXT

FEATURES

- Update tested Vault releases to include latest versions.
- Migrate CI testing to Github actions.

## 1.1.0

FEATURES

- `escape` now escapes '\"', allowing JSON to be saved into a secret.
- Update gate tests to use released Vault 1.4.0.

## 1.0.0

FEATURES

- `AppRole` auth backend support added: https://www.vaultproject.io/docs/auth/approle.html.
- `VaultResponse`
 - Added `request_id` field. Added in vault 0.6.1: https://github.com/hashicorp/vault/pull/1650.

BREAKING CHANGES

- `VaultClient`
 - `data` is now `Option<VaultResponse<T>>`. The standard function, `VaultClient::new`, for
 constructing a `VaultClient` makes a call to the `auth/token/lookup-self` endpoint to populate
 additional information about the token. However, for limited use tokens, you will not want to
 perform this lookup. As a result, the `VaultClient.data` has now been made an `Option`.
 - `cubbyhole/response` endpoint is deprecated in vault 0.6.2 and has been replaced by
 `sys/wrapping/unwrap`. The function `get_cubbyhole_response()` has been renamed to
 `get_unwrapped_response()`. More details: https://github.com/hashicorp/vault/pull/1927.
