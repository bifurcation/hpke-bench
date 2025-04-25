use criterion::{criterion_group, criterion_main, Criterion};
use hpke_bench::*;

fn bench_key_schedule<KS>(c: &mut Criterion, label: &str)
where
    KS: KeySchedule,
{
    let suite_id = *b"HPKE\x00\x01\x02\x03\x04\x05";
    let mode = Mode::Base;
    let shared_secret = [0xa0; 64];
    let info = [0xb0; 1024];
    let psk = [0xc0; 64];
    let psk_id = [0xd0; 1024];
    let key_size = 32;
    let nonce_size = 12;

    c.bench_function(&label, |b| {
        b.iter(|| {
            KS::key_schedule(
                suite_id,
                mode,
                &shared_secret,
                &info,
                &psk,
                &psk_id,
                key_size,
                nonce_size,
            );
        })
    });
}

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
    // Benchmark the raw key schedule
    bench_key_schedule::<Rfc9180<HkdfSha256>>(c, "rfc_sha2");
    bench_key_schedule::<Rfc9180<HkdfSha3_256>>(c, "rfc_sha3");
    bench_key_schedule::<XofWithLabel<Shake128>>(c, "shake_label");
    bench_key_schedule::<XofWithLabel<TurboShake128>>(c, "turboshake_label");
    bench_key_schedule::<XofFlat<Shake128>>(c, "shake_flat");
    bench_key_schedule::<XofFlat<TurboShake128>>(c, "turboshake_flat");

    // Benchmark the key schedule functions in context
    bench_hpke::<DhkemP256HkdfSha256, Rfc9180<HkdfSha256>, Aes128Gcm>(c, "p256");
    bench_hpke::<DhkemP384HkdfSha384, Rfc9180<HkdfSha384>, Aes256Gcm>(c, "p384");
    bench_hpke::<DhkemP521HkdfSha512, Rfc9180<HkdfSha512>, Aes256Gcm>(c, "p521");
    bench_hpke::<DhkemX25519HkdfSha256, Rfc9180<HkdfSha256>, ChaCha20Poly1305>(c, "x25519");
    bench_hpke::<DhkemX448HkdfSha512, Rfc9180<HkdfSha512>, ChaCha20Poly1305>(c, "x448");

    bench_hpke::<DhkemX25519HkdfSha256, Rfc9180<HkdfSha3_256>, ChaCha20Poly1305>(c, "x25519_sha3");

    bench_hpke::<DhkemX25519HkdfSha256, XofWithLabel<Shake128>, ChaCha20Poly1305>(
        c,
        "x25519_shake_label",
    );
    bench_hpke::<DhkemX25519HkdfSha256, XofWithLabel<TurboShake128>, ChaCha20Poly1305>(
        c,
        "x25519_turboshake_label",
    );

    bench_hpke::<DhkemX25519HkdfSha256, XofFlat<Shake128>, ChaCha20Poly1305>(
        c,
        "x25519_shake_flat",
    );
    bench_hpke::<DhkemX25519HkdfSha256, XofFlat<TurboShake128>, ChaCha20Poly1305>(
        c,
        "x25519_turboshake_flat",
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
