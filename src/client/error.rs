use {reqwest, rustc_serialize, url};

/// `Result` type-alias
pub type Result<T> = ::std::result::Result<T, Error>;

quick_error! {
    /// Error enum for vault-rs
    #[derive(Debug)]
    pub enum Error {
        /// `reqwest::Error` errors
        Reqwest(err: reqwest::Error) {
            from()
            description("reqwest error")
            display("reqwest error: {}", err)
            cause(err)
        }
        /// `rustc_serialize EncoderError`
        Encoder(err: rustc_serialize::json::EncoderError) {
            from()
            description("rustc_serialize EncoderError")
            display("rustc_serialize EncoderError: {}", err)
            cause(err)
        }
        /// `rustc_serialize DecoderError`
        Decoder(err: rustc_serialize::json::DecoderError) {
            from()
            description("rustc_serialize DecoderError")
            display("rustc_serialize DecoderError: {}", err)
            cause(err)
        }
        /// Vault errors
        Vault(err: String) {
            description("vault error")
            display("vault error: {}", err)
        }
        /// IO errors
        Io(err: ::std::io::Error) {
            from()
            description("io error")
            display("io error: {}", err)
            cause(err)
        }
        /// `Url` parsing error
        Url(err: url::ParseError) {
            from()
            description("url parse error")
            display("url parse error: {}", err)
            cause(err)
        }
    }
}
