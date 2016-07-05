use std::collections::HashMap;
use std::io::Read;

use hyper::{self, header, Client};
use hyper::client::response::Response;

use rustc_serialize::json;

use client::error::{Error, Result};

mod error;

pub struct VaultClient<'a> {
    pub host: &'a str,
    pub token: String,
    client: Client,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct SecretData {
    value: String,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct SecretAuth {
    client_token: String,
    accessor: String,
    policies: Vec<String>,
    metadata: HashMap<String, String>,
    lease_duration: Option<i64>,
    renewable: bool,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct VaultSecret {
    lease_id: Option<String>,
    renewable: Option<bool>,
    lease_duration: Option<i64>,
    data: SecretData,
    warnings: Option<Vec<String>>,
    auth: Option<SecretAuth>,
}


#[derive(RustcDecodable, RustcEncodable, Debug)]
struct AppIdPayload {
    app_id: String,
    user_id: String,
}

header! { (XVaultToken, "X-Vault-Token") => [String] }

impl<'a> VaultClient<'a> {
    /// Make a new `VaultClient` from an existing vault token
    pub fn new(host: &'a str, token: &'a str) -> Result<VaultClient<'a>> {
        let client = Client::new();
        let _ = try!(handle_hyper_response(client.get(&format!("{}/v1/auth/token/lookup-self", host)[..])
                    .header(XVaultToken(token.to_string()))
                    .send()));
        Ok(VaultClient {
            host: host,
            token: token.to_string(),
            client: client,
        })
    }

    /// Retrieve token via the `App ID` auth backend
    pub fn new_app_id(host: &'a str, app_id: &'a str, user_id: &'a str) -> Result<VaultClient<'a>> {
        let client = Client::new();
        let payload = try!(json::encode(&AppIdPayload {
            app_id: app_id.to_string(),
            user_id: user_id.to_string(),
        }));
        let mut res =
            try!(handle_hyper_response(client.post(&format!("{}/v1/auth/app-id/login", host)[..])
                                             .body(&payload)
                                             .send()));
        let mut body = String::new();
        let _ = try!(res.read_to_string(&mut body));
        let decoded: VaultSecret = try!(json::decode(&body));
        let token = match decoded.auth {
            Some(auth) => auth.client_token,
            None => {
                return Err(Error::Vault(format!("No client token found in response: `{}`", body)))
            }
        };
        Ok(VaultClient {
            host: host,
            token: token,
            client: client,
        })
    }

    ///
    /// Saves a secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// # fn main() {
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_set", "world");
    /// assert!(res.is_ok());
    /// # }
    /// ```
    pub fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let _ = try!(self.post(&format!("/v1/secret/{}", key)[..],
                               &format!("{{\"value\": \"{}\"}}", value)[..]));
        Ok(())
    }

    ///
    /// Fetches a saved secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// # fn main() {
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_get", "world");
    /// assert!(res.is_ok());
    /// let res = client.get_secret("hello_get");
    /// assert!(res.is_ok());
    /// assert_eq!(res.unwrap(), "world");
    /// # }
    /// ```
    pub fn get_secret(&self, key: &str) -> Result<String> {
        let mut res = try!(self.get(&format!("/v1/secret/{}", key)[..]));
        let mut body = String::new();
        res.read_to_string(&mut body).unwrap();
        let decoded: VaultSecret = try!(json::decode(&body));
        Ok(decoded.data.value)
    }

    ///
    /// Deletes a saved secret
    ///
    /// ```
    /// # extern crate hashicorp_vault as vault;
    /// # use vault::Client;
    /// # fn main() {
    /// let host = "http://127.0.0.1:8200";
    /// let token = "test12345";
    /// let client = Client::new(host, token).unwrap();
    /// let res = client.set_secret("hello_delete", "world");
    /// assert!(res.is_ok());
    /// let res = client.delete_secret("hello_delete");
    /// assert!(res.is_ok());
    /// # }
    /// ```
    pub fn delete_secret(&self, key: &str) -> Result<()> {
        let _ = try!(self.delete(&format!("/v1/secret/{}", key)[..]));
        Ok(())
    }

    fn get(&self, endpoint: &str) -> Result<Response> {
        Ok(try!(handle_hyper_response(self.client
                                          .get(&format!("{}{}", self.host, endpoint)[..])
                                          .header(XVaultToken(self.token.to_string()))
                                          .header(header::ContentType::json())
                                          .send())))
    }

    fn delete(&self, endpoint: &str) -> Result<Response> {
        Ok(try!(handle_hyper_response(self.client
                                          .delete(&format!("{}{}", self.host, endpoint)[..])
                                          .header(XVaultToken(self.token.to_string()))
                                          .header(header::ContentType::json())
                                          .send())))
    }

    fn post(&self, endpoint: &str, body: &str) -> Result<Response> {
        Ok(try!(handle_hyper_response(self.client
                                          .post(&format!("{}{}", self.host, endpoint)[..])
                                          .header(XVaultToken(self.token.to_string()))
                                          .header(header::ContentType::json())
                                          .body(body)
                                          .send())))
    }
}

/// helper fn to check `Response` for success
fn handle_hyper_response(res: ::std::result::Result<Response, hyper::Error>) -> Result<Response> {
    let res = try!(res);
    if res.status.is_success() {
        Ok(res)
    } else {
        Err(Error::Vault(format!("Vault request failed: {:?}", res)))
    }
}
