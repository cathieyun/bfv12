fn main() {
    let t = 4;
    let q = 256;
    let std_dev = 3.2;
    let dimension = 4;
    let mut rng = rand::thread_rng();

    let secret_key = keys::SecretKey::generate(dimension, q, &mut rng);
    let public_key = secret_key.to_pub_key(q, std_dev, dimension, &mut rng);

    let msg_1 = vec![0, 1, 2, 3];
    let plaintext_1 = plaintext::Plaintext::new(msg_1, t, q);
    let ciphertext_1 = plaintext_1.encrypt(public_key.clone(), std_dev, &mut rng);
    let decrypted_1 = ciphertext_1.decrypt(secret_key.clone(), t);
    assert_eq!(decrypted_1.poly.val, plaintext_1.poly.val);

    let msg_2 = vec![2, 3, 1, 0];
    let plaintext_2 = plaintext::Plaintext::new(msg_2, t, q);
    let ciphertext_2 = plaintext_2.encrypt(public_key, std_dev, &mut rng);
    let decrypted_2 = ciphertext_2.decrypt(secret_key.clone(), t);
    assert_eq!(decrypted_2.poly.val, plaintext_2.poly.val);

    let added_ciphertext = ciphertext_1 + ciphertext_2;
    let decrypted_add = added_ciphertext.decrypt(secret_key.clone(), t);
    println!("decrypted addition: {:?}", decrypted_add.poly.val);
    assert_eq!(decrypted_add.poly.val, vec![2, 0, 3, 3]);
}

mod ciphertext;
mod keys;
mod plaintext;
mod poly;
mod random_source;
mod tests;
