#[cfg(test)]
mod tests {
    use crate::*;
    use rand::SeedableRng;

    fn encrypt_decrypt_helper(msg: Vec<i64>, t: i64, q: i64, std_dev: f64) {
        let dimension = msg.len();
        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        let secret_key = keys::SecretKey::generate(dimension, q, &mut rng);
        let public_key = secret_key.public_key_gen(q, std_dev, dimension, &mut rng);

        let plaintext = plaintext::Plaintext::new(msg, t, q);
        let ciphertext = plaintext.encrypt(public_key, std_dev, &mut rng);

        let decrypted = ciphertext.decrypt(secret_key);

        assert_eq!(decrypted.poly.val, plaintext.poly.val);
    }

    // t = 2
    #[test]
    fn encrypt_decrypt_t2_dim2() {
        encrypt_decrypt_helper(vec![0, 1], 2, 65536, 3.2);
    }

    #[test]
    fn encrypt_decrypt_t2_dim4() {
        encrypt_decrypt_helper(vec![0, 1, 1, 0], 2, 65536, 3.2);
    }

    #[test]
    fn encrypt_decrypt_t2_dim8() {
        encrypt_decrypt_helper(vec![0, 1, 1, 0, 0, 0, 1, 0], 2, 65536, 3.2);
    }

    // t = 4
    #[test]
    fn encrypt_decrypt_t4_dim2() {
        encrypt_decrypt_helper(vec![0, 3], 4, 65536, 3.2);
    }

    #[test]
    fn encrypt_decrypt_t4_dim4() {
        encrypt_decrypt_helper(vec![0, 1, 2, 3], 4, 65536, 3.2);
    }

    #[test]
    fn encrypt_decrypt_t4_dim8() {
        encrypt_decrypt_helper(vec![0, 1, 2, 3, 3, 2, 1, 0], 4, 65536, 3.2);
    }

    // t = 8
    #[test]
    fn encrypt_decrypt_t8_dim4() {
        encrypt_decrypt_helper(vec![0, 1, 2, 3], 8, 65536, 3.2);
    }

    #[test]
    fn encrypt_decrypt_t8_dim8() {
        encrypt_decrypt_helper(vec![0, 1, 2, 3, 4, 5, 6, 7], 8, 65536, 3.2);
    }

    // t = 16
    #[test]
    fn encrypt_decrypt_t16_dim2() {
        encrypt_decrypt_helper(vec![0, 3], 16, 65536, 3.2);
    }

    #[test]
    fn encrypt_decrypt_t16_dim4() {
        encrypt_decrypt_helper(vec![0, 1, 2, 3], 16, 65536, 3.2);
    }

    #[test]
    fn t32_dim2() {
        encrypt_decrypt_helper(vec![0, 1], 32, 65536, 3.2);
    }

    fn encrypt_add_decrypt_helper(msg_1: Vec<i64>, msg_2: Vec<i64>, t: i64, q: i64, std_dev: f64) {
        let mut rng = rand::thread_rng();
        let dimension = msg_1.len();

        let secret_key = keys::SecretKey::generate(dimension, q, &mut rng);
        let public_key = secret_key.public_key_gen(q, std_dev, dimension, &mut rng);

        let plaintext_1 = plaintext::Plaintext::new(msg_1, t, q);
        let ciphertext_1 = plaintext_1.encrypt(public_key.clone(), std_dev, &mut rng);
        let decrypted_1 = ciphertext_1.decrypt(secret_key.clone());
        assert_eq!(decrypted_1.poly.val, plaintext_1.poly.val);

        let plaintext_2 = plaintext::Plaintext::new(msg_2, t, q);
        let ciphertext_2 = plaintext_2.encrypt(public_key, std_dev, &mut rng);
        let decrypted_2 = ciphertext_2.decrypt(secret_key.clone());
        assert_eq!(decrypted_2.poly.val, plaintext_2.poly.val);

        let added_ciphertext = ciphertext_1 + ciphertext_2;
        let decrypted_add = added_ciphertext.decrypt(secret_key.clone());
        let expected_add = (plaintext_1.poly + plaintext_2.poly).unsigned_modulo(t).val;
        assert_eq!(decrypted_add.poly.val, expected_add);
    }

    // t = 4
    #[test]
    fn encrypt_add_decrypt_t4_dim4() {
        encrypt_add_decrypt_helper(vec![0, 1, 2, 3], vec![2, 3, 1, 0], 4, 65536, 3.2)
    }

    #[test]
    fn encrypt_add_decrypt_t4_dim8() {
        encrypt_add_decrypt_helper(
            vec![0, 1, 2, 3, 0, 1, 2, 3],
            vec![3, 2, 1, 0, 3, 2, 1, 0],
            4,
            65536,
            3.2,
        )
    }

    // t = 8
    #[test]
    fn encrypt_add_decrypt_t8_dim4() {
        encrypt_add_decrypt_helper(vec![0, 1, 2, 3], vec![2, 3, 1, 0], 8, 65536, 3.2)
    }

    #[test]
    fn encrypt_add_decrypt_t8_dim8() {
        encrypt_add_decrypt_helper(
            vec![0, 1, 2, 3, 4, 5, 6, 7],
            vec![7, 6, 5, 4, 3, 2, 1, 0],
            8,
            65536,
            3.2,
        )
    }

    //TODO(cathie): write tests for Ciphertext Neg, Sub
}
