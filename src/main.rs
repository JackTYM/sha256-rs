mod sha256;

fn main() {
    println!("SHA256 - {}", sha256::sha256_string("Hello!"));
}