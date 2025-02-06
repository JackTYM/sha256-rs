const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone, Debug)]
struct HashValues {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,
}

pub fn sha256_string(message: &str) -> String {
    sha256(message.as_bytes())
}
pub fn sha256(message: &[u8]) -> String {
    let p = 512 * (((message.len() * 8 + 64) / 512) + 1) - (message.len() * 8 + 64);

    let block: String = format!(
        "{}1{}{:064b}",
        message
            .iter()
            .map(|byte| format!("{:08b}", byte))
            .collect::<Vec<_>>()
            .join(""),
        vec!["0";p-1].join(""),
        message.len() * 8
    );

    let mut inputs = HashValues {
        a: 0x6a09e667,
        b: 0xbb67ae85,
        c: 0x3c6ef372,
        d: 0xa54ff53a,
        e: 0x510e527f,
        f: 0x9b05688c,
        g: 0x1f83d9ab,
        h: 0x5be0cd19,
    };

    for i in 0..(block.len() / 512) {
        let inputs = & mut inputs;
        let chunk = &block[512 * i..512 * (i + 1)];

        let words: [u32; 16] = core::array::from_fn(|n| {
            u32::from_str_radix(&chunk[32 * n..32 * (n+1)], 2).unwrap()
        });

        let mut w: [u32; 64] = [0; 64];

        for r in 0..64 {
            let w = & mut w;
            if r < 16 {
                w[r] = words[r];
                continue;
            }

            let sigma0 = rotr(7, w[r-15]) ^ rotr(18, w[r-15]) ^ shr(3, w[r-15]);
            let sigma1 = rotr(17, w[r-2]) ^ rotr(19, w[r-2]) ^ shr(10, w[r-2]);

            w[r] = (w[r-16].wrapping_add(sigma0).wrapping_add(w[r-7]).wrapping_add(sigma1)) & 0xFFFFFFFF;
        }

        let outputs = compress(inputs.clone(), w);

        inputs.a = outputs.a.wrapping_add(inputs.a);
        inputs.b = outputs.b.wrapping_add(inputs.b);
        inputs.c = outputs.c.wrapping_add(inputs.c);
        inputs.d = outputs.d.wrapping_add(inputs.d);
        inputs.e = outputs.e.wrapping_add(inputs.e);
        inputs.f = outputs.f.wrapping_add(inputs.f);
        inputs.g = outputs.g.wrapping_add(inputs.g);
        inputs.h = outputs.h.wrapping_add(inputs.h);
    }

    format!("{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}", inputs.a, inputs.b, inputs.c, inputs.d, inputs.e, inputs.f, inputs.g, inputs.h)
}

fn compress(mut inputs: HashValues, w: [u32; 64]) -> HashValues {
    for r in 0..64 {
        let t1: u32 = (inputs.h.wrapping_add(rotr(6, inputs.e) ^ rotr(11, inputs.e) ^ rotr(25, inputs.e)).wrapping_add((inputs.e & inputs.f) ^ (!inputs.e & inputs.g)).wrapping_add(K[r]).wrapping_add(w[r])) & 0xFFFFFFFF;
        let t2: u32 = (((inputs.a & inputs.b) ^ (inputs.a & inputs.c) ^ (inputs.b & inputs.c)).wrapping_add(rotr(2, inputs.a) ^ rotr(13, inputs.a) ^ rotr(22, inputs.a))) & 0xFFFFFFFF;

        inputs.h = inputs.g;
        inputs.g = inputs.f;
        inputs.f = inputs.e;
        inputs.e = (inputs.d.wrapping_add(t1)) & 0xFFFFFFFF;
        inputs.d = inputs.c;
        inputs.c = inputs.b;
        inputs.b = inputs.a;
        inputs.a = (t1.wrapping_add(t2)) & 0xFFFFFFFF;

    }

    inputs
}

fn rotr(n: u8, x: u32) -> u32 {
    ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
}

fn shr(n: u8, x: u32) -> u32 {
    (x >> n) & 0xFFFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha256() {
        let result = sha256_string("");
        assert_eq!(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}