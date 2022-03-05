fn main() {
    let secret_key = keys::SecretKey::generate(20.0, 10);
    println!("secret key: {:?}", secret_key.val);
    let public_key = secret_key.to_pub_key(2^16, 20.0, 10);
    println!("public key: {:?}", public_key.p_0)
}

mod keys;
mod random_source;
mod plaintext;
mod ciphertext;