extern crate hashicorp_vault as vault;

fn main() {
    let host = "http://localhost:8200";
    let token = "test12345";
    let client: vault::Client<()> = vault::Client::new(host).token(token).build().unwrap();

    let _ = client.set_secret("foo", "{\"bar\": \"baz\"}");

    let secret = client.get_secret("foo").unwrap();

    println!("Secret \"foo\" is: {}", secret);
}
