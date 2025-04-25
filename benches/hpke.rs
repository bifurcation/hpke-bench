use criterion::{criterion_group, criterion_main, Criterion};
use hpke_bench::*;

fn bench_hpke<K, KS, A>(c: &mut Criterion, label: &str)
where
    K: Kem,
    KS: KeySchedule,
    A: Aead,
{
    let mut rng = rand::thread_rng();

    let info = b"info";
    let (dk, ek) = K::generate_key_pair(&mut rng);
    let (ct, _) = Instance::<K, KS, A>::setup_base_s(&mut rng, &ek, info);

    let encap_label = format!("{}_encap", label);
    c.bench_function(&encap_label, |b| {
        b.iter(|| {
            Instance::<K, KS, A>::setup_base_s(&mut rng, &ek, info);
        })
    });

    let decap_label = format!("{}_decap", label);
    c.bench_function(&decap_label, |b| {
        b.iter(|| {
            Instance::<K, KS, A>::setup_base_r(&ct, &dk, info);
        })
    });
}

pub fn criterion_benchmark(c: &mut Criterion) {
    bench_hpke::<DhkemP256HkdfSha256, Rfc9180<HkdfSha256>, Aes128Gcm>(c, "p256");
    bench_hpke::<DhkemP384HkdfSha384, Rfc9180<HkdfSha384>, Aes256Gcm>(c, "p384");
    bench_hpke::<DhkemP521HkdfSha512, Rfc9180<HkdfSha512>, Aes256Gcm>(c, "p521");
    bench_hpke::<DhkemX25519HkdfSha256, Rfc9180<HkdfSha256>, ChaCha20Poly1305>(c, "x25519");
    bench_hpke::<DhkemX448HkdfSha512, Rfc9180<HkdfSha512>, ChaCha20Poly1305>(c, "x448");

    bench_hpke::<DhkemX25519HkdfSha256, Rfc9180<HkdfSha3_256>, ChaCha20Poly1305>(c, "x25519_sha3");
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
