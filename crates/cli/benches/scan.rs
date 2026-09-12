//! Performance regression benchmarks for the detector engines.
//!
//! `cargo bench -p truent-cli --bench scan` measures a full detector pass
//! over the general and EVM regression corpora. Criterion keeps a baseline
//! under `target/criterion`; CI runs with `--save-baseline main` on the
//! default branch and `--baseline main` on pull requests so a slowdown in a
//! hot path is visible before it ships.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::path::Path;

fn corpus(rel: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let mut out = Vec::new();
    fn walk(d: &Path, out: &mut Vec<(String, String)>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if let Ok(s) = std::fs::read_to_string(&p) {
                    out.push((p.to_string_lossy().to_string(), s));
                }
            }
        }
    }
    walk(&root, &mut out);
    out
}

fn bench_general(c: &mut Criterion) {
    let files = corpus("crates/analyzer/general/tests/corpus");
    let bytes: usize = files.iter().map(|(_, s)| s.len()).sum();
    let mut g = c.benchmark_group("general");
    g.throughput(Throughput::Bytes(bytes as u64));
    g.bench_function("run_all_detectors over corpus", |b| {
        b.iter(|| {
            for (p, s) in &files {
                black_box(truent_analyzer_general::run_all_detectors(s, p));
            }
            black_box(truent_analyzer_general::run_repo_detectors(&files));
        })
    });
    g.finish();
}

fn bench_evm(c: &mut Criterion) {
    let files = corpus("crates/analyzer/evm/tests/corpus");
    let bytes: usize = files.iter().map(|(_, s)| s.len()).sum();
    let mut g = c.benchmark_group("evm");
    g.throughput(Throughput::Bytes(bytes as u64));
    g.bench_function("run_all_detectors over corpus", |b| {
        b.iter(|| {
            for (p, s) in &files {
                black_box(truent_analyzer_evm::detectors::run_all_detectors(s, p));
            }
        })
    });
    g.finish();
}

fn bench_taxonomy(c: &mut Criterion) {
    c.bench_function("taxonomy lookup", |b| {
        b.iter(|| {
            for t in truent_core::taxonomy::all() {
                black_box(truent_core::taxonomy::taxonomy_for(t.invariant_id));
                black_box(truent_core::exposure::exposure_for(t.invariant_id));
            }
        })
    });
}

criterion_group!(benches, bench_general, bench_evm, bench_taxonomy);
criterion_main!(benches);
