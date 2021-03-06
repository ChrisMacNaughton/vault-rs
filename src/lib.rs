#![deny(
    missing_docs,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(feature = "clippy", allow(unstable_features))]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", deny(clippy))]

//! Client API for interacting with [Vault](https://www.vaultproject.io/docs/http/index.html)

extern crate base64;
extern crate reqwest;
#[macro_use]
extern crate log;
#[macro_use]
extern crate quick_error;
pub extern crate chrono;
extern crate serde;
pub extern crate url;

/// vault client
pub mod client;
pub use crate::client::error::{Error, Result};
pub use crate::client::VaultClient as Client;
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
    fn try_from(_: T) -> ::std::result::Result<Self, Self::Err>;
}

impl<T, U> TryInto<U> for T
where
    U: TryFrom<T>,
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

impl<'a> TryFrom<&'a String> for Url {
    type Err = Error;
    fn try_from(s: &String) -> ::std::result::Result<Self, Self::Err> {
        match Url::parse(s) {
            Ok(u) => Ok(u),
            Err(e) => Err(e.into()),
        }
    }
}

impl TryFrom<String> for Url {
    type Err = Error;
    fn try_from(s: String) -> ::std::result::Result<Self, Self::Err> {
        match Url::parse(&s) {
            Ok(u) => Ok(u),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::client::HttpVerb::*;
    use crate::client::VaultClient as Client;
    use crate::client::{self, EndpointResponse};
    use crate::Error;
    use reqwest::StatusCode;
    use serde::{Deserialize, Serialize};

    /// vault host for testing
    const HOST: &str = "http://127.0.0.1:8200";
    /// root token needed for testing
    const TOKEN: &str = "test12345";

    #[test]
    fn it_can_create_a_client() {
        let _ = Client::new(HOST, TOKEN).unwrap();
    }

    #[test]
    fn it_can_create_a_client_from_a_string_reference() {
        let _ = Client::new(&HOST.to_string(), TOKEN).unwrap();
    }

    #[test]
    fn it_can_create_a_client_from_a_string() {
        let _ = Client::new(HOST.to_string(), TOKEN).unwrap();
    }

    #[test]
    fn it_can_query_secrets() {
        let client = Client::new(HOST, TOKEN).unwrap();
        let res = client.set_secret("hello_query", "world");
        assert!(res.is_ok());
        let res = client.get_secret("hello_query").unwrap();
        assert_eq!(res, "world");
    }

    #[test]
    fn it_can_store_json_secrets() {
        let client = Client::new(HOST, TOKEN).unwrap();
        let json = "{\"foo\": {\"bar\": [\"baz\"]}}";
        let res = client.set_secret("json_secret", json);
        assert!(res.is_ok());
        let res = client.get_secret("json_secret").unwrap();
        assert_eq!(res, json)
    }

    #[test]
    fn it_can_list_secrets() {
        let client = Client::new(HOST, TOKEN).unwrap();

        let _res = client.set_secret("hello/fred", "world").unwrap();
        // assert!(res.is_ok());
        let res = client.set_secret("hello/bob", "world");
        assert!(res.is_ok());

        let res = client.list_secrets("hello");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), ["bob", "fred"]);

        let res = client.list_secrets("hello/");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), ["bob", "fred"]);
    }

    #[test]
    fn it_can_detect_404_status() {
        let client = Client::new(HOST, TOKEN).unwrap();

        let res = client.list_secrets("non/existent/key");
        assert!(res.is_err());

        if let Err(Error::VaultResponse(_, response)) = res {
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        } else {
            panic!("Error should match on VaultResponse with reqwest response.");
        }
    }

    #[test]
    fn it_can_write_secrets_with_newline() {
        let client = Client::new(HOST, TOKEN).unwrap();

        let res = client.set_secret("hello_set", "world\n");
        assert!(res.is_ok());
        let res = client.get_secret("hello_set").unwrap();
        assert_eq!(res, "world\n");
    }

    #[test]
    fn it_returns_err_on_forbidden() {
        let client = Client::new(HOST, "test123456");
        // assert_eq!(Err("Forbidden".to_string()), client);
        assert!(client.is_err());
    }

    #[test]
    fn it_can_delete_a_secret() {
        let client = Client::new(HOST, TOKEN).unwrap();

        let res = client.set_secret("hello_delete", "world");
        assert!(res.is_ok());
        let res = client.get_secret("hello_delete").unwrap();
        assert_eq!(res, "world");
        let res = client.delete_secret("hello_delete");
        assert!(res.is_ok());
        let res = client.get_secret("hello_delete");
        assert!(res.is_err());
    }

    #[test]
    fn it_can_perform_approle_workflow() {
        use std::collections::HashMap;

        let c = Client::new(HOST, TOKEN).unwrap();
        let mut body = "{\"type\":\"approle\"}";
        // Ensure we do not currently have an approle backend enabled.
        // Older vault versions (<1.2.0) seem to have an AppRole backend
        // enabled by default, so calling the POST to create a new one
        // fails with a 400 status
        let _: EndpointResponse<()> = c
            .call_endpoint(DELETE, "sys/auth/approle", None, None)
            .unwrap();
        // enable approle auth backend
        let mut res: EndpointResponse<()> = c
            .call_endpoint(POST, "sys/auth/approle", None, Some(body))
            .unwrap();
        panic_non_empty(&res);
        // make a new approle
        body = "{\"secret_id_ttl\":\"10m\", \"token_ttl\":\"20m\", \"token_max_ttl\":\"30m\", \
                \"secret_id_num_uses\":40}";
        res = c
            .call_endpoint(POST, "auth/approle/role/test_role", None, Some(body))
            .unwrap();
        panic_non_empty(&res);

        // let's test the properties endpoint while we're here
        let _ = c.get_app_role_properties("test_role").unwrap();

        // get approle's role-id
        let res: EndpointResponse<HashMap<String, String>> = c
            .call_endpoint(GET, "auth/approle/role/test_role/role-id", None, None)
            .unwrap();
        let data = match res {
            EndpointResponse::VaultResponse(res) => res.data.unwrap(),
            _ => panic!("expected vault response, got: {:?}", res),
        };
        let role_id = &data["role_id"];
        assert!(!role_id.is_empty());

        // now get a secret id for this approle
        let res: EndpointResponse<HashMap<String, String>> = c
            .call_endpoint(POST, "auth/approle/role/test_role/secret-id", None, None)
            .unwrap();
        let data = match res {
            EndpointResponse::VaultResponse(res) => res.data.unwrap(),
            _ => panic!("expected vault response, got: {:?}", res),
        };
        let secret_id = &data["secret_id"];

        // now finally we can try to actually login!
        let _ = Client::new_app_role(HOST, &role_id[..], Some(&secret_id[..])).unwrap();

        // clean up by disabling approle auth backend
        let res = c
            .call_endpoint(DELETE, "sys/auth/approle", None, None)
            .unwrap();
        panic_non_empty(&res);
    }

    #[test]
    fn it_can_read_a_wrapped_secret() {
        let client = Client::new(HOST, TOKEN).unwrap();
        let res = client.set_secret("hello_delete_2", "second world");
        assert!(res.is_ok());
        // wrap the secret's value in `sys/wrapping/unwrap` with a TTL of 2 minutes
        let res = client.get_secret_wrapped("hello_delete_2", "2m").unwrap();
        let wrapping_token = res.wrap_info.unwrap().token;
        // make a new client with the wrapping token
        let c2 = Client::new_no_lookup(HOST, wrapping_token).unwrap();
        // read the cubbyhole response (can only do this once!)
        let res = c2.get_unwrapped_response().unwrap();
        assert_eq!(res.data.unwrap()["value"], "second world");
    }

    #[test]
    fn it_can_store_policies() {
        // use trailing slash for host to ensure Url processing fixes this later
        let c = Client::new("http://127.0.0.1:8200/", TOKEN).unwrap();
        let body = "{\"policy\":\"{}\"}";
        // enable approle auth backend
        let res: EndpointResponse<()> = c
            .call_endpoint(PUT, "sys/policy/test_policy_1", None, Some(body))
            .unwrap();
        panic_non_empty(&res);
        let res: EndpointResponse<()> = c
            .call_endpoint(PUT, "sys/policy/test_policy_2", None, Some(body))
            .unwrap();
        panic_non_empty(&res);
        let client_policies = c.policies().unwrap();
        let expected_policies = ["default", "test_policy_1", "test_policy_2", "root"];
        let _ = expected_policies
            .iter()
            .map(|p| {
                assert!(client_policies.contains(&(*p).to_string()));
            })
            .last();
        let token_name = "policy_test_token".to_string();
        let token_opts = client::TokenOptions::default()
            .policies(vec!["test_policy_1", "test_policy_2"].into_iter())
            .default_policy(false)
            .id(&token_name[..])
            .ttl(client::VaultDuration::minutes(1));
        let _ = c.create_token(&token_opts).unwrap();
        let body = format!("{{\"token\":\"{}\"}}", &token_name);
        let res: EndpointResponse<client::TokenData> = c
            .call_endpoint(POST, "auth/token/lookup", None, Some(&body))
            .unwrap();
        match res {
            EndpointResponse::VaultResponse(res) => {
                let data = res.data.unwrap();
                let mut policies = data.policies;
                policies.sort();
                assert_eq!(policies, ["test_policy_1", "test_policy_2"]);
            }
            _ => panic!("expected vault response, got: {:?}", res),
        }
        // clean-up
        let res: EndpointResponse<()> = c
            .call_endpoint(DELETE, "sys/policy/test_policy_1", None, None)
            .unwrap();
        panic_non_empty(&res);
        let res: EndpointResponse<()> = c
            .call_endpoint(DELETE, "sys/policy/test_policy_2", None, None)
            .unwrap();
        panic_non_empty(&res);
    }

    #[test]
    fn it_can_list_things() {
        let c = Client::new(HOST, TOKEN).unwrap();
        let _ = c
            .create_token(&client::TokenOptions::default().ttl(client::VaultDuration::minutes(1)))
            .unwrap();
        let res: EndpointResponse<client::ListResponse> = c
            .call_endpoint(LIST, "auth/token/accessors", None, None)
            .unwrap();
        match res {
            EndpointResponse::VaultResponse(res) => {
                let data = res.data.unwrap();
                assert!(data.keys.len() > 2);
            }
            _ => panic!("expected vault response, got: {:?}", res),
        }
    }

    #[test]
    fn it_can_encrypt_decrypt_transit() {
        let key_id = "test-vault-rs";
        let plaintext = b"data\0to\0encrypt";

        let client = Client::new(HOST, TOKEN).unwrap();
        let enc_resp = client.transit_encrypt(None, key_id, plaintext);
        let encrypted = enc_resp.unwrap();
        let dec_resp = client.transit_decrypt(None, key_id, encrypted);
        let payload = dec_resp.unwrap();
        assert_eq!(plaintext, payload.as_slice());
    }

    // helper fn to panic on empty responses
    fn panic_non_empty(res: &EndpointResponse<()>) {
        match *res {
            EndpointResponse::Empty => {}
            _ => panic!("expected empty response, received: {:?}", res),
        }
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct CustomSecretType {
        name: String,
    }

    #[test]
    fn it_can_set_and_get_a_custom_secret_type() {
        let input = CustomSecretType {
            name: "test".into(),
        };

        let client = Client::new(HOST, TOKEN).unwrap();

        let res = client.set_custom_secret("custom_type", &input);
        assert!(res.is_ok());
        let res: CustomSecretType = client.get_custom_secret("custom_type").unwrap();
        assert_eq!(res, input);
    }
}
