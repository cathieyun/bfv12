fn main() {
    let msg = vec![0, 1, 2, 3];
    let t = 8;
    let q = 256;
    let std_dev = 3.2;
    let dimension = msg.len();
    let mut rng = rand::thread_rng();

    let secret_key = keys::SecretKey::generate(dimension, q, &mut rng);
    let public_key = secret_key.to_pub_key(q, std_dev, dimension, &mut rng);

    let plaintext = plaintext::Plaintext::new(msg, t, q);
    let ciphertext = plaintext.encrypt(public_key, std_dev, &mut rng);
    let decrypted = ciphertext.decrypt(secret_key, t);

    assert_eq!(decrypted.poly.val, plaintext.poly.val);
}

mod ciphertext;
mod keys;
mod plaintext;
mod poly;
mod random_source;

#[cfg(test)]
mod tests {
    use crate::*;
    use rand::SeedableRng;

    fn encrypt_decrypt_helper(msg: Vec<i64>, t: i64, q: i64, std_dev: f64) {
        let dimension = msg.len();
        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        let secret_key = keys::SecretKey::generate(dimension, q, &mut rng);
        let public_key = secret_key.to_pub_key(q, std_dev, dimension, &mut rng);

        let plaintext = plaintext::Plaintext::new(msg, t, q);
        let ciphertext = plaintext.encrypt(public_key, std_dev, &mut rng);

        let decrypted = ciphertext.decrypt(secret_key, t);

        assert_eq!(decrypted.poly.val, plaintext.poly.val);
    }

    #[test]
    fn test_encrypt_decrypt_t8_dim4() {
        encrypt_decrypt_helper(vec![0, 1, 2, 3], 8, 256, 3.2);
    }
}
