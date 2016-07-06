use std::collections::HashMap;
use std::io::Read;

use hyper::{self, header, Client};
use hyper::client::response::Response;

use rustc_serialize::{self, json};

use client::error::{Error, Result};

mod error;

/// Vault client used to make API requests to the vault
#[derive(Debug)]
pub struct VaultClient<'a, T>
    where T: rustc_serialize::Decodable
{
    /// URL to vault instance
    pub host: &'a str,
    /// Token to access vault
    pub token: String,
    /// `hyper::Client`
    client: Client,
    /// Data
    pub data: VaultResponse<T>,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct TokenData {
    pub accessor: String,
    pub creation_time: u64,
    pub creation_ttl: u64,
    pub display_name: String,
    pub explicit_max_ttl: u64,
    pub id: String,
    pub last_renewal_time: u64,
    pub meta: HashMap<String, String>,
    pub num_uses: u64,
    pub orphan: bool,
    pub path: String,
    pub policies: Vec<String>,
    pub renewable: bool,
    pub role: String,
    pub ttl: u64,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct SecretData {
    value: String,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct SecretAuth {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub lease_duration: Option<u64>,
    pub renewable: bool,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct VaultResponse<D>
    where D: rustc_serialize::Decodable
{
    pub lease_id: Option<String>,
    pub renewable: Option<bool>,
    pub lease_duration: Option<u64>,
    pub data: Option<D>,
    pub warnings: Option<Vec<String>>,
    pub auth: Option<SecretAuth>,
    pub wrap_info: Option<WrapInfo>,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct WrapInfo {
    // TODO: change to a `Duration`
    pub ttl: u64,
    pub token: String,
    // TODO: change to `time`
    pub creation_time: u64,
    pub wrapped_accessor: String,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct AppIdPayload {
    app_id: String,
    user_id: String,
}

header! { (XVaultToken, "X-Vault-Token") => [String] }

impl<'a, T> VaultClient<'a, T>
    where T: rustc_serialize::Decodable
{
    /// Construct a `VaultClient` from an existing vault token
    pub fn new(host: &'a str, token: &'a str) -> Result<VaultClient<'a, TokenData>> {
        let client = Client::new();
        let mut res = try!(handle_hyper_response(client.get(&format!("{}/v1/auth/token/lookup-self", host)[..])
                    .header(XVaultToken(token.to_string()))
                    .send()));
        let mut body = String::new();
        let _ = try!(res.read_to_string(&mut body));
        let decoded: VaultResponse<TokenData> = try!(json::decode(&body));
        Ok(VaultClient {
            host: host,
            token: token.to_string(),
            client: client,
            data: decoded,
        })
    }

    /// Construct a `VaultClient` via the `App ID`
    /// [auth backend](https://www.vaultproject.io/docs/auth/app-id.html)
    pub fn new_app_id(host: &'a str,
                      app_id: &'a str,
                      user_id: &'a str)
                      -> Result<VaultClient<'a, ()>> {
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
        let decoded: VaultResponse<()> = try!(json::decode(&body));
        let token = match decoded.auth {
            Some(ref auth) => auth.client_token.clone(),
            None => {
                return Err(Error::Vault(format!("No client token found in response: `{}`", body)))
            }
        };
        Ok(VaultClient {
            host: host,
            token: token,
            client: client,
            data: decoded,
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
        let _ = try!(res.read_to_string(&mut body));
        let decoded: VaultResponse<SecretData> = try!(json::decode(&body));
        match decoded.data {
            Some(data) => Ok(data.value),
            _ => Err(Error::Vault(format!("No secret found in response: `{:#?}`", decoded))),
        }
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
