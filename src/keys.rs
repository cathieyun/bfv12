use super::random_source;

pub struct SecretKey {
    pub val: Vec<i64>,
    pub dimension: usize,
    pub std_dev: f64 
}

pub struct PublicKey {  
    // TODO(cathie): add a struct to hold vectors
    pub p_0: Vec<i64>,
    pub p_1: Vec<i64>,
    pub dimension: usize,
    pub std_dev,
    pub q: u64,
}

impl SecretKey {
    // TODO(cathie): add error management
    pub fn generate(std_dev: f64, dimension: usize) -> SecretKey {
        SecretKey {
            val: random_source::get_gaussian(std_dev, dimension),
            dimension,
            std_dev,
        }
    }

    // TODO(cathie): are the dimensions for a, s, e all the same?
    pub fn to_pub_key(&self, q: u64, std_dev: f64, dimension: usize) -> PublicKey {
        let s = &self.val;
        let a = random_source::get_uniform(q, dimension);
        let e = random_source::get_gaussian(std_dev, dimension);

        let p_0 = s.iter().zip(a.iter().zip(e.iter()))
                   .map(|(s_i, (a_i, e_i))| -(a_i * s_i + e_i) % (q as i64))
                   .collect();

        PublicKey {
            p_0,
            p_1: a,
            dimension,
            std_dev,
            q,
        }
    }
}