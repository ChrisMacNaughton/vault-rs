use std::collections::HashMap;
use std::io::Read;
use std::io;

use hyper::Client;
use hyper::client::response::Response;
// use hyper::error::Error;
use hyper::header;
// use hyper::header::Connection;
use hyper::status::StatusCode;

use rustc_serialize::json;
use rustc_serialize::json::DecoderError;

pub struct VaultClient<'a> {
    pub host: &'a str,
    pub token: &'a str,
    client: Client,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct SecretData {
    value: String,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
struct SecretAuth {
    client_token: String,
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
    data: Option<SecretData>,
    warnings: Option<Vec<String>>,
    auth: Option<SecretAuth>,
}

header! { (XVaultToken, "X-Vault-Token") => [String] }

impl<'a> VaultClient<'a> {
    pub fn new(host: &'a str, token: &'a str) -> Result<VaultClient<'a>, String> {

        let client = Client::new();
        match client.get(&format!("{}/v1/auth/token/lookup-self", host)[..])
            .header(XVaultToken(token.to_string()))
            .send() {
            Ok(s) => {
                match s.status {
                    StatusCode::Forbidden | StatusCode::BadRequest => {
                        return Err("Forbidden".to_string())
                    }
                    _ => {}
                }
            }
            // Err(Error { kind: ConnectionRefused }) => continue,
            Err(e) => {
                match e {
                    _ => return Err(format!("{:?}", e)),
                }
            }

        }
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

    pub fn set_secret(&self, key: &str, value: &str) -> Result<&str, io::Error> {
        match self.post(&format!("/v1/secret/{}", key)[..],
                        &format!("{{\"value\": \"{}\"}}", value.replace("\n", "\\n"))[..]) {
            Ok(s) => {
                match s.status {
                    StatusCode::NoContent => Ok(""),
                    _ => Err(io::Error::new(io::ErrorKind::Other, "Error setting secret")),
                }
            }
            Err(e) => {
                println!("{:?}", e);
                Err(io::Error::new(io::ErrorKind::Other, format!("wtf: {:?}", e)))
            }
        }
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

    pub fn get_secret(&self, key: &str) -> Result<String, &str> {
        match self.get(&format!("/v1/secret/{}", key)[..]) {
            Ok(mut s) => {
                let mut body = String::new();
                s.read_to_string(&mut body).unwrap();
                let decoded: Result<VaultSecret, DecoderError> = json::decode(&body);
                match decoded {
                    Ok(decoded) => {
                        if let Some(d) = decoded.data {
                            Ok(d.value)
                        } else {
                            Err("Missing Data Field")
                        }
                    }
                    Err(e) => {
                        println!("Error: {:?} :: Data: {}", e, &body);
                        Err("Got a bad secret back")
                    }
                }
            }
            Err(e) => {
                println!("Error: {:?}", e);
                Err("err")
            }
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
    pub fn delete_secret(&self, key: &str) -> Result<&str, &str> {
        match self.delete(&format!("/v1/secret/{}", key)[..]) {
            Ok(s) => {
                match s.status {
                    StatusCode::NoContent => Ok(""),
                    _ => Err("Error setting secret"),
                }
            }
            Err(e) => {
                println!("{:?}", e);
                Err("err")
            }
        }
    }

    fn get(&self, endpoint: &str) -> Result<Response, String> {
        match self.client
            .get(&format!("{}{}", self.host, endpoint)[..])
            .header(XVaultToken(self.token.to_string()))
            .header(header::ContentType::json())
            .send() {
            Ok(s) => return Ok(s),
            // Err(Error { kind: ConnectionRefused }) => continue,
            Err(e) => {
                match e {
                    _ => return Err(format!("{:?}", e)),
                }
            }
        }

        Err("No working host".to_string())
    }

    fn delete(&self, endpoint: &str) -> Result<Response, String> {
        match self.client
            .delete(&format!("{}{}", self.host, endpoint)[..])
            .header(XVaultToken(self.token.to_string()))
            .header(header::ContentType::json())
            .send() {
            Ok(s) => return Ok(s),
            // Err(Error { kind: ConnectionRefused }) => continue,
            Err(e) => {
                match e {
                    _ => return Err(format!("{:?}", e)),
                }
            }
        }

        Err("No working host".to_string())
    }

    fn post(&self, endpoint: &str, body: &str) -> Result<Response, String> {
        match self.client
            .post(&format!("{}{}", self.host, endpoint)[..])
            .header(XVaultToken(self.token.to_string()))
            .header(header::ContentType::json())
            .body(body)
            .send() {
            Ok(s) => return Ok(s),
            // Err(Error { kind: ConnectionRefused }) => continue,
            Err(e) => {
                match e {
                    _ => return Err(format!("{:?}", e)),
                }
            }
        }
        Err("No working host".to_string())
    }
    // fn get_new_host(&self) -> usize {
    //     let mut rng = thread_rng();
    //     rng.gen_range(0, hosts.len() as u32 - 1)
    // }
}
