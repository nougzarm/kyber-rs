use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use kyber_nz::constants::{KyberParams, PolyParams};
use kyber_nz::kem_scheme::MlKem;
use kyber_nz::params::{Kyber1024Params, Kyber512Params, Kyber768Params, SecurityLevel};
use kyber_nz::traits::KemScheme;
use rand::rngs::OsRng;

fn bench_kem<const K: usize, S, P>(c: &mut Criterion, name: &str)
where
    S: SecurityLevel,
    P: PolyParams,
    MlKem<K, S, P>: KemScheme,
{
    let mut group = c.benchmark_group(name);
    let kem = MlKem::<K, S, P>::new();
    let mut rng = OsRng;

    group.bench_function("KeyGen", |b| {
        b.iter(|| kem.key_gen(black_box(&mut rng)).unwrap())
    });

    let (ek, dk) = kem.key_gen(&mut rng).unwrap();

    group.bench_function("Encaps", |b| {
        b.iter(|| kem.encaps(black_box(&ek), black_box(&mut rng)).unwrap())
    });

    let (_ss, ct) = kem.encaps(&ek, &mut rng).unwrap();

    group.bench_function("Decaps", |b| {
        b.iter(|| kem.decaps(black_box(&dk), black_box(&ct)).unwrap())
    });

    group.finish();
}

fn bench_kyber512(c: &mut Criterion) {
    bench_kem::<2, Kyber512Params, KyberParams>(c, "ML-KEM-512");
}

fn bench_kyber768(c: &mut Criterion) {
    bench_kem::<3, Kyber768Params, KyberParams>(c, "ML-KEM-768");
}

fn bench_kyber1024(c: &mut Criterion) {
    bench_kem::<4, Kyber1024Params, KyberParams>(c, "ML-KEM-1024");
}

criterion_group!(benches, bench_kyber512, bench_kyber768, bench_kyber1024);
criterion_main!(benches);
