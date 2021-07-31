/// `Result` type-alias
pub type Result<T> = ::std::result::Result<T, Error>;

quick_error! {
    /// Error enum for vault-rs
    #[derive(Debug)]
    pub enum Error {
        /// `reqwest::Error` errors
        Reqwest(err: ::reqwest::Error) {
            from()
            display("reqwest error: {}", err)
            source(err)
        }
        /// `serde_json::Error`
        SerdeJson(err: ::serde_json::Error) {
            from()
            display("serde_json Error: {}", err)
            source(err)
        }
        /// Vault errors
        Vault(err: String) {
            display("vault error: {}", err)
        }
        /// Response from Vault errors
        /// This is for when the response is not successful.
        VaultResponse(err: String, response: reqwest::blocking::Response) {
            display("Error in vault response: {}", err)
        }
        /// IO errors
        Io(err: ::std::io::Error) {
            from()
            display("io error: {}", err)
            source(err)
        }
        /// `Url` parsing error
        Url(err: ::url::ParseError) {
            from()
            display("url parse error: {}", err)
            source(err)
        }
        /// `Base64` decode error
        Base64(err: ::base64::DecodeError) {
            from()
            display("base64 decode error: {}", err)
            source(err)
        }
    }
}
