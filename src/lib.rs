
#![deny(missing_docs,
        missing_debug_implementations,
        trivial_casts,
        trivial_numeric_casts,
        unsafe_code,
        unstable_features,
        unused_import_braces,
        unused_qualifications,
        unused_results)]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(feature = "clippy", allow(unstable_features))]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", deny(clippy))]

//! Client API for interacting with [Vault](https://www.vaultproject.io/docs/http/index.html)

#[macro_use]
extern crate hyper;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
#[macro_use]
extern crate quick_error;
pub extern crate chrono;
pub extern crate url;

/// vault client
pub mod client;
pub use client::VaultClient as Client;
pub use client::error::Error;
use url::Url;

/// Waiting to stabilize: https://github.com/rust-lang/rust/issues/33417
///
/// An attempted conversion that consumes `self`, which may or may not be expensive.
///
/// Library authors should not directly implement this trait, but should prefer implementing
/// the [`TryFrom`] trait, which offers greater flexibility and provides an equivalent `TryInto`
/// implementation for free, thanks to a blanket implementation in the standard library.
///
/// [`TryFrom`]: trait.TryFrom.html
pub trait TryInto<T>: Sized {
    /// The type returned in the event of a conversion error.
    type Err;

    /// Performs the conversion.
    fn try_into(self) -> ::std::result::Result<T, Self::Err>;
}

/// Waiting to stabilize: https://github.com/rust-lang/rust/issues/33417
///
/// Attempt to construct `Self` via a conversion.
pub trait TryFrom<T>: Sized {
    /// The type returned in the event of a conversion error.
    type Err;

    /// Performs the conversion.
    fn try_from(T) -> ::std::result::Result<Self, Self::Err>;
}

impl<T, U> TryInto<U> for T
    where U: TryFrom<T>
{
    type Err = U::Err;

    fn try_into(self) -> ::std::result::Result<U, U::Err> {
        U::try_from(self)
    }
}

impl TryFrom<Url> for Url {
    type Err = Error;
    fn try_from(u: Url) -> ::std::result::Result<Self, Self::Err> {
        Ok(u)
    }
}

impl<'a> TryFrom<&'a Url> for Url {
    type Err = Error;
    fn try_from(u: &Url) -> ::std::result::Result<Self, Self::Err> {
        Ok(u.clone())
    }
}

impl<'a> TryFrom<&'a str> for Url {
    type Err = Error;
    fn try_from(s: &str) -> ::std::result::Result<Self, Self::Err> {
        match Url::parse(s) {
            Ok(u) => Ok(u),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use client::VaultClient as Client;
    use std::env;

    #[test]
    fn it_can_create_a_client() {
        let host = env::var("VAULT_ADDR").unwrap_or("http://127.0.0.1:8200".to_string());
        let token = env::var("VAULT_TOKEN").unwrap_or("test12345".to_string());
        let _ = Client::new(&host, &token).unwrap();
    }


    #[test]
    fn it_can_query_secrets() {
        let host = env::var("VAULT_ADDR").unwrap_or("http://127.0.0.1:8200".to_string());
        let token = env::var("VAULT_TOKEN").unwrap_or("test12345".to_string());

        let client = Client::new(&host, &token).unwrap();
        let res = client.set_secret("secret/hello_query", "world");
        assert!(res.is_ok());
        let res = client.get_secret("secret/hello_query").unwrap();
        assert_eq!(res, "world");
    }

    #[test]
    fn it_can_write_secrets_with_newline() {
        let host = env::var("VAULT_ADDR").unwrap_or("http://127.0.0.1:8200".to_string());
        let token = env::var("VAULT_TOKEN").unwrap_or("test12345".to_string());

        let client = Client::new(&host, &token).unwrap();
        let res = client.set_secret("secret/hello_set", "world\n");
        assert!(res.is_ok());
        let res = client.get_secret("secret/hello_set").unwrap();
        assert_eq!(res, "world\n");
    }

    #[test]
    fn it_returns_err_on_forbidden() {
        let host = env::var("VAULT_ADDR").unwrap_or("http://127.0.0.1:8200".to_string());
        let token = "I'ma bad guy";
        let client = Client::new(&host, token);

        // assert_eq!(Err("Forbidden".to_string()), client);
        assert!(client.is_err());
    }

    #[test]
    fn it_can_delete_a_secret() {

        let host = env::var("VAULT_ADDR").unwrap_or("http://127.0.0.1:8200".to_string());
        let token = env::var("VAULT_TOKEN").unwrap_or("test12345".to_string());
        let client = Client::new(&host, &token).unwrap();

        let res = client.set_secret("secret/hello_delete", "world");
        assert!(res.is_ok());
        let res = client.get_secret("secret/hello_delete").unwrap();
        assert_eq!(res, "world");
        let res = client.delete_secret("secret/hello_delete");
        assert!(res.is_ok());
        let res = client.get_secret("secret/hello_delete");
        assert!(res.is_err());
    }
}
