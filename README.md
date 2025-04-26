Benchmarking HPKE with SHA-3
============================

This repository contains a small reference implementation of HPKE, structured to
allow us to measure the performance impact of changes to HPKE.  Specifically,
proposed mechanisms to integrate SHA3 / SHAKE / XOFs in the "KDF" slot, as
[discussed] on the HPKE mailing list.

The core change involved is in the `KeySchedule` function, and in particular,
the way that the `key`, `base_nonce`, and `exporter_secret` values are derived
from the inputs.  In this experiment, we compare three variations:

* Integrating SHA-3 via HPKE (as [suggested by Dierdre])
* An XOF-based approach with derivation labels (as [suggested by Sophie])
* An XOF-based approach with length-separated outputs (my own invention)

These are benchmarked separately and in the context of HPKE.  For the latter
measurement, we use DHKEM(X25519, HKDF-SHA256) as the KEM, because this is
empirically the fastest of the registered KEMs, and thus will show any key
schedule differences to their greatest advantage.  Also looked at ML-KEM-768
because [Dierdre asked].

# Local Measurement Results

```
> cargo bench
```

Environment:

* MacBook M1 Pro, vintage 2021
* Rust 1.85.1
* Rust Crypto and X25519-Dalek used for underlying primitives
* ☁️  Weather: 25C and cloudy 
* 🌘 Moon phase: Waning crescent, 7% illumination

Measurements reflect the mean value measured by Criterion.

| Key schedule variant | KDF / XOF      | Time per iteration | X225519 Encap | ML-KEM-768 Encap | ML-KEM-768 Decap |
|----------------------|----------------|--------------------|---------------|------------------|------------------|
| RFC                  | HKDF-SHA256    | 13.018 µs          | 56.667 µs     | 37.105 µs        | 44.695 µs        |
| RFC                  | HKDF-SHA3\_256 | 10.621 µs          | 57.520 µs     | 38.055 µs        | 45.664 µs        |
| XOF with label       | SHAKE128       | 4.3673 µs          | 51.536 µs     | 32.161 µs        | 39.674 µs        |
| XOF with label       | TurboSHAKE128  | 2.3762 µs          | 50.927 µs     | 31.276 µs        | 38.878 µs        |
| XOF with length      | SHAKE128       | 3.4692 µs          | 50.662 µs     | 31.134 µs        | 38.734 µs        |
| XOF with length      | TurboSHAKE128  | 1.8673 µs          | 50.337 µs     | 31.418 µs        | 39.069 µs        |

[discussed]: https://mailarchive.ietf.org/arch/msg/cfrg/zwpQRXtlqnPC0QzJ1-pNbz5ohcM/
[suggested by Dierdre]: https://datatracker.ietf.org/doc/draft-connolly-cfrg-sha3-hpke
[suggested by Sophie]: https://mailarchive.ietf.org/arch/msg/cfrg/3RzIoQs0u5aw-uywoQQoY2gJtbM/
[Dierdre asked]: https://mailarchive.ietf.org/arch/msg/cfrg/hUUdjQYZt0ZRwGTAAhlt7UkK25Q/
