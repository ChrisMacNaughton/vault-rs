#[macro_use] extern crate hyper;
#[macro_use] extern crate log;
extern crate rustc_serialize;

mod client;

pub use client::{VaultClient as Client};

#[cfg(test)]
mod tests {
    use client::{VaultClient as Client};

    #[test]
    fn it_can_create_a_client() {
        let hosts = vec!["http://127.0.0.1:8201", "http://127.0.0.1:8200"];
        let token = "test12345";
        let _ = Client::new(hosts, token).unwrap();
    }

    #[test]
    fn it_can_query_secrets() {
        let hosts = vec!["http://127.0.0.1:8201", "http://127.0.0.1:8200"];
        let token = "test12345";
        let client = Client::new(hosts, token).unwrap();

        let res = client.set_secret("hello", "world");
        assert!(res.is_ok());
        let res = client.get_secret("hello").unwrap();
        assert_eq!(res, "world");
    }

    #[test]
    fn it_returns_err_on_forbidden() {
        let hosts = vec!["http://127.0.0.1:8201", "http://127.0.0.1:8200"];
        let token = "test123456";
        let client = Client::new(hosts, token);
        // assert_eq!(Err("Forbidden".to_string()), client);
        assert!(client.is_err());
    }

    #[test]
    fn it_can_delete_a_secret() {
        let hosts = vec!["http://127.0.0.1:8201", "http://127.0.0.1:8200"];
        let token = "test12345";
        let client = Client::new(hosts, token).unwrap();

        let res = client.set_secret("hello", "world");
        assert!(res.is_ok());
        let res = client.get_secret("hello").unwrap();
        assert_eq!(res, "world");
        let res = client.delete_secret("hello");
        assert!(res.is_ok());
        let res = client.get_secret("hello");
        assert!(res.is_err());
    }
}

