fn main() {
    let q = 256;
    let dimension = 10;

    let secret_key = keys::SecretKey::generate(dimension, q);
    println!("secret key: {:?}", secret_key);
    let public_key = secret_key.to_pub_key(q, 3.2, dimension);
    println!("public key: {:?}", public_key.p_0)
}

mod keys;
mod random_source;
mod plaintext;
mod ciphertext;
mod poly;