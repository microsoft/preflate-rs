#[cfg(feature = "simd")]
use cabac::perf::fpaq_parallel_simd_get_pattern;

use cabac::perf::{
    fpaq_get_pattern, fpaq_parallel_get_pattern, fpaq_parallel_put_pattern, fpaq_put_pattern,
    rans32_get_pattern, rans32_get_pattern_bypass, rans32_put_pattern, rans32_put_pattern_bypass,
    vp8_get_pattern, vp8_get_pattern_bypass, vp8_put_pattern, vp8_put_pattern_bypass,
};

use criterion::{Criterion, criterion_group, criterion_main};

fn criterion_benchmark(c: &mut Criterion) {
    let mut pattern = Vec::<bool>::new();
    rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Standard)
        .take(65535)
        .for_each(|x| pattern.push(x));

    let rans_pattern = rans32_put_pattern(&pattern);
    let vp8_pattern = vp8_put_pattern(&pattern);
    let fpaq_pattern = fpaq_put_pattern(&pattern);
    let fpaq_parallel_pattern = fpaq_parallel_put_pattern(&pattern);

    let rans_pattern_bypass = rans32_put_pattern_bypass(&pattern);
    let vp8_pattern_bypass = vp8_put_pattern_bypass(&pattern);

    c.bench_function("VP8 read", |b| {
        b.iter(|| {
            vp8_get_pattern(&pattern, &vp8_pattern);
        })
    });

    c.bench_function("VP8 read bypass", |b| {
        b.iter(|| {
            vp8_get_pattern_bypass(&pattern, &vp8_pattern_bypass);
        })
    });

    c.bench_function("VP8 write", |b| {
        b.iter(|| {
            vp8_put_pattern(&pattern);
        })
    });

    c.bench_function("Rans32 read", |b| {
        b.iter(|| {
            rans32_get_pattern(&pattern, &rans_pattern);
        });
    });

    c.bench_function("Rans32 read bypass", |b| {
        b.iter(|| {
            rans32_get_pattern_bypass(&pattern, &rans_pattern_bypass);
        });
    });

    c.bench_function("Rans32 write", |b| {
        b.iter(|| {
            rans32_put_pattern(&pattern);
        })
    });

    c.bench_function("Fpaq write", |b| {
        b.iter(|| {
            fpaq_put_pattern(&pattern);
        })
    });

    c.bench_function("Fpaq read", |b| {
        b.iter(|| {
            fpaq_get_pattern(&pattern, &fpaq_pattern);
        })
    });

    c.bench_function("Fpaq0 parallel write", |b| {
        b.iter(|| {
            fpaq_parallel_put_pattern(&pattern);
        })
    });

    c.bench_function("Fpaq0 parallel read", |b| {
        b.iter(|| {
            fpaq_parallel_get_pattern(&pattern, &fpaq_parallel_pattern);
        })
    });

    #[cfg(feature = "simd")]
    c.bench_function("Fpaq0 parallel simd read", |b| {
        b.iter(|| {
            fpaq_parallel_simd_get_pattern(&pattern, &fpaq_parallel_pattern);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
