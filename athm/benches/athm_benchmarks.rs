use athm::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_core::OsRng;

fn benchmark_key_gen(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_gen");

    [4, 6].iter().for_each(|&n_buckets| {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_buckets),
            &n_buckets,
            |b, &n_buckets| {
                let params = Params::new(n_buckets).unwrap();
                b.iter(|| {
                    let (_private_key, _public_key, _proof) = key_gen(black_box(&params));
                });
            },
        );
    });

    group.finish();
}

fn benchmark_token_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_request");
    let mut rng = OsRng;

    [4, 6].iter().for_each(|&n_buckets| {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_buckets),
            &n_buckets,
            |b, &n_buckets| {
                let params = Params::new(n_buckets).unwrap();
                let (_server_private_key, server_public_key, proof) = key_gen(&params);

                b.iter(|| {
                    let (_context, _request) = token_request(
                        black_box(&server_public_key),
                        black_box(&proof),
                        black_box(&params),
                        &mut rng,
                    )
                    .unwrap();
                });
            },
        );
    });

    group.finish();
}

fn benchmark_token_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_response");
    let mut rng = OsRng;

    [4, 6].iter().for_each(|&n_buckets| {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_buckets),
            &n_buckets,
            |b, &n_buckets| {
                let params = Params::new(n_buckets).unwrap();
                let (server_private_key, server_public_key, proof) = key_gen(&params);
                let (_context, request) =
                    token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
                let hidden_metadata = 2;

                b.iter(|| {
                    let _response = token_response(
                        black_box(&server_private_key),
                        black_box(&server_public_key),
                        black_box(&request),
                        black_box(hidden_metadata),
                        black_box(&params),
                        &mut rng,
                    )
                    .unwrap();
                });
            },
        );
    });

    group.finish();
}

fn benchmark_finalize_token(c: &mut Criterion) {
    let mut group = c.benchmark_group("finalize_token");
    let mut rng = OsRng;

    [4, 6].iter().for_each(|&n_buckets| {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_buckets),
            &n_buckets,
            |b, &n_buckets| {
                let params = Params::new(n_buckets).unwrap();
                let (server_private_key, server_public_key, proof) = key_gen(&params);
                let (context, request) =
                    token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
                let hidden_metadata = 2;
                let response = token_response(
                    &server_private_key,
                    &server_public_key,
                    &request,
                    hidden_metadata,
                    &params,
                    &mut rng,
                )
                .unwrap();

                b.iter(|| {
                    let _token = finalize_token(
                        black_box(&context),
                        black_box(&server_public_key),
                        black_box(&request),
                        black_box(&response),
                        black_box(&params),
                        &mut rng,
                    )
                    .unwrap();
                });
            },
        );
    });

    group.finish();
}

fn benchmark_verify_token(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_token");
    let mut rng = OsRng;

    [4, 6].iter().for_each(|&n_buckets| {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_buckets),
            &n_buckets,
            |b, &n_buckets| {
                let params = Params::new(n_buckets).unwrap();
                let (server_private_key, server_public_key, proof) = key_gen(&params);
                let (context, request) =
                    token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
                let hidden_metadata = 2;
                let response = token_response(
                    &server_private_key,
                    &server_public_key,
                    &request,
                    hidden_metadata,
                    &params,
                    &mut rng,
                )
                .unwrap();
                let token = finalize_token(
                    &context,
                    &server_public_key,
                    &request,
                    &response,
                    &params,
                    &mut rng,
                )
                .unwrap();

                b.iter(|| {
                    let _metadata = verify_token(
                        black_box(&server_private_key),
                        black_box(&token),
                        black_box(&params),
                    )
                    .unwrap();
                });
            },
        );
    });

    group.finish();
}

fn benchmark_verify_public_key_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_public_key_proof");

    [4, 6].iter().for_each(|&n_buckets| {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_buckets),
            &n_buckets,
            |b, &n_buckets| {
                let params = Params::new(n_buckets).unwrap();
                let (_server_private_key, server_public_key, proof) = key_gen(&params);

                b.iter(|| {
                    let _result = verify_public_key_proof(
                        black_box(&server_public_key),
                        black_box(&proof),
                        black_box(&params),
                    );
                });
            },
        );
    });

    group.finish();
}

fn benchmark_verify_issuance_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_issuance_proof");
    let mut rng = OsRng;

    [4, 6].iter().for_each(|&n_buckets| {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_buckets),
            &n_buckets,
            |b, &n_buckets| {
                let params = Params::new(n_buckets).unwrap();
                let (server_private_key, server_public_key, proof) = key_gen(&params);
                let (_context, request) =
                    token_request(&server_public_key, &proof, &params, &mut rng).unwrap();
                let hidden_metadata = 2;
                let response = token_response(
                    &server_private_key,
                    &server_public_key,
                    &request,
                    hidden_metadata,
                    &params,
                    &mut rng,
                )
                .unwrap();

                b.iter(|| {
                    let _result = verify_issuance_proof(
                        black_box(&server_public_key),
                        black_box(&request.big_t),
                        black_box(&response),
                        black_box(&params),
                    );
                });
            },
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_key_gen,
    benchmark_token_request,
    benchmark_token_response,
    benchmark_finalize_token,
    benchmark_verify_token,
    benchmark_verify_public_key_proof,
    benchmark_verify_issuance_proof
);

criterion_main!(benches);
