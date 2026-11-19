// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Statistical timing tests for the constant-time properties ATHM depends on.
//!
//! # Overview
//!
//! The ATHM server issues and redeems tokens over secret `hidden_metadata`.
//! While the protocol logic in `lib.rs` is branch-free (`conditional_select`),
//! end-to-end constant-time execution also depends on the cryptographic backend.
//!
//! Expected behavior is declared per backend via [`TimingProfile`]:
//! - `rustcrypto` uses complete projective formulas and is constant-time everywhere.
//! - `boringssl` is constant-time except that point addition and subtraction are faster when the
//!   operands cancel (see `boringssl.rs`).
//!
//! Tests assert the declared [`TimingProfile`] expectation rather than skipping
//! known leaks, so both regressions and fixes surface immediately.
//!
//! # Methodology
//!
//! - Each test compares input [`Class`]es that run the exact same operation and differ only in
//!   secret operand values.
//! - Classes are timed in calibrated batches (exceeding `Instant::now()` overhead) and sampled in
//!   shuffled round-robin order to neutralize CPU/cache drift.
//! - Spread is evaluated at the **10th percentile** (`p10`), since preemption and frequency scaling
//!   skew timings strictly upward.
//!
//! # Running
//!
//! ```shell
//! # RustCrypto backend:
//! cargo test --release --lib --features timing-tests timing_test -- --test-threads=1 --nocapture
//! # BoringSSL backend:
//! cargo test --release --lib --no-default-features --features boringssl,timing-tests timing_test -- --test-threads=1 --nocapture
//! ```

use super::AthmBackend;
use std::hint::black_box;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ===========================================================================
// Per-backend expectations
// ===========================================================================

/// Expected timing properties for a backend.
///
/// When a backend leak is fixed, flip the corresponding flag to `true`.
trait TimingProfile: AthmBackend + Clone {
    const NAME: &'static str;

    /// Whether point arithmetic is independent of operand values (identity,
    /// doubling, and scalar multiplication).
    const CT_POINT_ARITHMETIC: bool;

    /// Whether point addition and subtraction take the same time when the
    /// operands cancel (`P + (-P)`, `P - P`) as otherwise.
    const CT_POINT_CANCELLATION: bool;

    /// Whether `token_response` is independent of `hidden_metadata`.
    const CT_ISSUANCE: bool;
}

#[cfg(feature = "rustcrypto")]
impl TimingProfile for crate::backend::rustcrypto::RustCryptoBackend {
    const NAME: &'static str = "rustcrypto";
    const CT_POINT_ARITHMETIC: bool = true;
    const CT_POINT_CANCELLATION: bool = true;
    const CT_ISSUANCE: bool = true;
}

#[cfg(feature = "boringssl")]
impl TimingProfile for crate::backend::boringssl::BoringSslBackend {
    const NAME: &'static str = "boringssl";
    const CT_POINT_ARITHMETIC: bool = true;
    // `EC_POINT_add` short-circuits when the result is the identity (~1.7x
    // faster on x86-64).
    const CT_POINT_CANCELLATION: bool = false;
    const CT_ISSUANCE: bool = true;
}

// ===========================================================================
// Thresholds
// ===========================================================================

/// Percentile at which classes are compared.
const COMPARISON_PERCENTILE: f64 = 0.10;

/// Decision thresholds for a test. Ratios between `constant_time_max_ratio` and
/// `leak_min_ratio` are treated as inconclusive and fail either way.
#[derive(Clone, Copy)]
struct Thresholds {
    /// Max slowest/fastest ratio considered constant-time.
    constant_time_max_ratio: f64,
    /// Min slowest/fastest ratio confirming a leak.
    leak_min_ratio: f64,
    /// Samples per class.
    samples: usize,
}

/// Thresholds for backend primitives (large leaks on BoringSSL: 1.74x on point
/// add, 182x on neg; loose constant-time bound for nanosecond-scale scalar ops).
const PRIMITIVE: Thresholds =
    Thresholds { constant_time_max_ratio: 1.10, leak_min_ratio: 1.25, samples: 300 };

/// Thresholds for ~1ms protocol ops (idle workstation spread: <=1.002x on
/// rustcrypto, ~1.020x for the ~25us BoringSSL issuance leak).
const PROTOCOL: Thresholds =
    Thresholds { constant_time_max_ratio: 1.006, leak_min_ratio: 1.012, samples: 200 };

/// Retries before failing, filtering transient machine noise.
const MAX_ATTEMPTS: usize = 3;

/// Target duration of one batched sample (well above `Instant::now()` overhead).
const TARGET_SAMPLE_TIME: Duration = Duration::from_micros(20);

/// Upper bound on batch size during calibration.
const MAX_BATCH: usize = 1 << 20;

// ===========================================================================
// Harness
// ===========================================================================

/// Serializes timing measurements when the test harness runs tests in parallel
/// (e.g., `cargo test --features timing-tests` without `--test-threads=1`).
static TIMING_LOCK: Mutex<()> = Mutex::new(());

/// An input class whose timing must be indistinguishable from others in a test.
struct Class<'a> {
    label: String,
    op: Box<dyn FnMut() + 'a>,
}

impl<'a> Class<'a> {
    fn new(label: impl Into<String>, op: impl FnMut() + 'a) -> Self {
        Class { label: label.into(), op: Box::new(op) }
    }
}

/// Per-operation timing samples (ns, sorted ascending) for a single class.
struct Measurement {
    label: String,
    batch: usize,
    sorted_ns: Vec<f64>,
}

impl Measurement {
    fn percentile(&self, q: f64) -> f64 {
        if self.sorted_ns.is_empty() {
            return f64::NAN;
        }
        let idx = ((self.sorted_ns.len() - 1) as f64 * q).round() as usize;
        self.sorted_ns[idx]
    }

    fn p10(&self) -> f64 {
        self.percentile(COMPARISON_PERCENTILE)
    }
}

/// Picks a batch size large enough that one sample dominates clock overhead.
/// Uses the median of 3 trials per doubling step so a one-off OS preemption
/// does not stop calibration early at a tiny batch size.
fn calibrate(op: &mut dyn FnMut()) -> usize {
    let mut batch = 1;
    loop {
        let mut trials = [Duration::ZERO; 3];
        for t in &mut trials {
            let start = Instant::now();
            for _ in 0..batch {
                op();
            }
            *t = start.elapsed();
        }
        trials.sort_unstable();
        if trials[1] >= TARGET_SAMPLE_TIME || batch >= MAX_BATCH {
            return batch;
        }
        batch *= 2;
    }
}

/// Xorshift64* PRNG seeded from the clock to shuffle per-round sampling order.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let seed = Instant::now().elapsed().as_nanos() as u64
            ^ std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9e37_79b9_7f4a_7c15);
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Samples every class in shuffled round-robin order and returns per-class timings.
fn measure(classes: &mut [Class<'_>], samples: usize) -> Vec<Measurement> {
    // Warm up caches and lazy statics (e.g. BoringSSL contexts), then share
    // the minimum calibrated batch size so all classes execute the exact same
    // loop count and timer overhead without blowing up runtime on large leaks.
    let batch = classes
        .iter_mut()
        .map(|class| {
            for _ in 0..16 {
                (class.op)();
            }
            calibrate(&mut class.op)
        })
        .min()
        .unwrap_or(1);

    let mut rng = Rng::new();
    let mut order: Vec<usize> = (0..classes.len()).collect();
    let mut raw: Vec<Vec<f64>> = classes.iter().map(|_| Vec::with_capacity(samples)).collect();
    for _ in 0..samples {
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i + 1));
        }

        for &i in &order {
            let op = &mut classes[i].op;
            let start = Instant::now();
            for _ in 0..batch {
                op();
            }
            let elapsed = start.elapsed().as_nanos() as f64;
            raw[i].push(elapsed / batch as f64);
        }
    }

    classes
        .iter()
        .zip(raw)
        .map(|(class, mut times)| {
            times.sort_by(|a, b| a.partial_cmp(b).expect("timings are never NaN"));
            Measurement { label: class.label.clone(), batch, sorted_ns: times }
        })
        .collect()
}

/// Ratio between the slowest and fastest class at `COMPARISON_PERCENTILE`.
fn spread(measurements: &[Measurement]) -> f64 {
    let fastest = measurements.iter().map(|m| m.p10()).fold(f64::INFINITY, f64::min);
    let slowest = measurements.iter().map(|m| m.p10()).fold(f64::NEG_INFINITY, f64::max);
    slowest / fastest
}

fn report(measurements: &[Measurement]) -> String {
    let fastest = measurements.iter().map(|m| m.p10()).fold(f64::INFINITY, f64::min);
    let width = measurements.iter().map(|m| m.label.len()).max().unwrap_or(0);
    let mut out = format!(
        "\n  {:<width$}  {:>12}  {:>12}  {:>8}  {:>7}\n",
        "class", "p10 (ns)", "p50 (ns)", "vs min", "batch"
    );
    for m in measurements {
        out.push_str(&format!(
            "  {:<width$}  {:>12.1}  {:>12.1}  {:>7.3}x  {:>7}\n",
            m.label,
            m.p10(),
            m.percentile(0.5),
            m.p10() / fastest,
            m.batch
        ));
    }
    out
}

/// Runs `build` up to `MAX_ATTEMPTS` times and asserts that the timing spread
/// matches `expect_constant_time`.
fn check<'a>(
    test: &str,
    backend: &str,
    expect_constant_time: bool,
    limits: Thresholds,
    mut build: impl FnMut() -> Vec<Class<'a>>,
) {
    let _guard = TIMING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Thresholds { constant_time_max_ratio, leak_min_ratio, samples } = limits;
    let mut last = Vec::new();
    let mut ratio = f64::NAN;

    for attempt in 1..=MAX_ATTEMPTS {
        let mut classes = build();
        assert!(classes.len() >= 2, "{test}: need at least two classes to compare");
        let measurements = measure(&mut classes, samples);
        ratio = spread(&measurements);

        let expectation = if expect_constant_time {
            format!("constant-time, at most {constant_time_max_ratio:.3}x")
        } else {
            format!("leaking, at least {leak_min_ratio:.3}x")
        };
        println!(
            "[{backend}] {test} (attempt {attempt}/{MAX_ATTEMPTS}): spread {ratio:.4}x, \
             expected {expectation}{}",
            report(&measurements)
        );

        let ok = if expect_constant_time {
            ratio <= constant_time_max_ratio
        } else {
            ratio >= leak_min_ratio
        };
        if ok {
            return;
        }
        last = measurements;
    }

    let table = report(&last);
    if expect_constant_time {
        panic!(
            "{test}: {backend} is expected to be constant-time here, but the \
             slowest input class was {ratio:.4}x the fastest (limit \
             {constant_time_max_ratio:.3}x), on all {MAX_ATTEMPTS} attempts.\n\
             \n\
             If this is a real regression, an attacker who can time this \
             operation can distinguish these input classes.\n\
             If the machine is simply too noisy, that should show up as an \
             unstable ratio across the attempts above rather than a consistent \
             one -- re-run, and prefer an optimized/release build on an idle machine.\n{table}"
        );
    }
    panic!(
        "{test}: {backend} is expected to LEAK here, but the spread was only \
         {ratio:.4}x (need {leak_min_ratio:.3}x to confirm), on all \
         {MAX_ATTEMPTS} attempts.\n\
         \n\
         If the backend was just fixed, that is good news: flip the \
         corresponding flag in `TimingProfile for {backend}` to `true` so this \
         test starts enforcing constant time instead of expecting a leak.\n\
         Otherwise the measurement is inconclusive -- values between \
         {constant_time_max_ratio:.3}x and {leak_min_ratio:.3}x are treated as \
         neither constant-time nor leaking.\n{table}"
    );
}

// ===========================================================================
// Backend primitive tests
// ===========================================================================

fn random_point<B: AthmBackend>() -> B::Point {
    B::point_generator() * B::random_scalar()
}

/// Point addition must not leak equal or identity operands (hit by
/// `create_issuance_proof` when `i == 0` or `i == hidden_metadata`).
fn point_add_is_constant_time<B: TimingProfile>() {
    check("point_add_is_constant_time", B::NAME, B::CT_POINT_ARITHMETIC, PRIMITIVE, || {
        let p = random_point::<B>();
        let q = random_point::<B>();
        let id = B::point_identity();
        vec![
            {
                let p = p.clone();
                Class::new("P + Q", move || {
                    black_box(black_box(p.clone()) + black_box(&q));
                })
            },
            {
                let p = p.clone();
                Class::new("P + P", move || {
                    black_box(black_box(p.clone()) + black_box(&p));
                })
            },
            {
                let id = id.clone();
                let p = p.clone();
                Class::new("O + P", move || {
                    black_box(black_box(id.clone()) + black_box(&p));
                })
            },
            Class::new("P + O", move || {
                black_box(black_box(p.clone()) + black_box(&id));
            }),
        ]
    });
}

/// Point addition must not leak whether the operands cancel.
fn point_add_is_constant_time_when_operands_cancel<B: TimingProfile>() {
    check(
        "point_add_is_constant_time_when_operands_cancel",
        B::NAME,
        B::CT_POINT_CANCELLATION,
        PRIMITIVE,
        || {
            let p = random_point::<B>();
            let q = random_point::<B>();
            let neg_p = -p.clone();
            vec![
                {
                    let p = p.clone();
                    Class::new("P + Q", move || {
                        black_box(black_box(p.clone()) + black_box(&q));
                    })
                },
                Class::new("P + (-P)", move || {
                    black_box(black_box(p.clone()) + black_box(&neg_p));
                }),
            ]
        },
    );
}

/// Point subtraction must not leak equal, inverse, or identity operands.
fn point_sub_is_constant_time<B: TimingProfile>() {
    check("point_sub_is_constant_time", B::NAME, B::CT_POINT_ARITHMETIC, PRIMITIVE, || {
        let p = random_point::<B>();
        let q = random_point::<B>();
        let neg_p = -p.clone();
        let id = B::point_identity();
        vec![
            {
                let p = p.clone();
                Class::new("P - Q", move || {
                    black_box(black_box(p.clone()) - black_box(&q));
                })
            },
            {
                let p = p.clone();
                Class::new("P - (-P)", move || {
                    black_box(black_box(p.clone()) - black_box(&neg_p));
                })
            },
            {
                let p = p.clone();
                let id = id.clone();
                Class::new("P - O", move || {
                    black_box(black_box(p.clone()) - black_box(&id));
                })
            },
            Class::new("O - P", move || {
                black_box(black_box(id.clone()) - black_box(&p));
            }),
        ]
    });
}

/// Point subtraction must not leak whether the operands cancel.
fn point_sub_is_constant_time_when_operands_cancel<B: TimingProfile>() {
    check(
        "point_sub_is_constant_time_when_operands_cancel",
        B::NAME,
        B::CT_POINT_CANCELLATION,
        PRIMITIVE,
        || {
            let p = random_point::<B>();
            let q = random_point::<B>();
            vec![
                {
                    let p = p.clone();
                    Class::new("P - Q", move || {
                        black_box(black_box(p.clone()) - black_box(&q));
                    })
                },
                Class::new("P - P", move || {
                    black_box(black_box(p.clone()) - black_box(&p));
                }),
            ]
        },
    );
}

/// Scalar multiplication of a non-identity point must not leak a non-zero
/// scalar (constant-time control: BoringSSL uses constant-time 5-bit windowed
/// multiplication here).
fn point_mul_is_constant_time_in_the_scalar<B: TimingProfile>() {
    check(
        "point_mul_is_constant_time_in_the_scalar",
        B::NAME,
        /* expect_constant_time= */ true,
        PRIMITIVE,
        || {
            let p = random_point::<B>();
            let one = B::scalar_one();
            let two = B::Scalar::from(2u64);
            let small = B::Scalar::from(3u64);
            let large = B::Scalar::from(u64::MAX);
            let random = B::random_non_zero_scalar();
            vec![
                {
                    let p = p.clone();
                    Class::new("P * 1", move || {
                        black_box(black_box(p.clone()) * black_box(one));
                    })
                },
                {
                    let p = p.clone();
                    Class::new("P * 2", move || {
                        black_box(black_box(p.clone()) * black_box(two));
                    })
                },
                {
                    let p = p.clone();
                    Class::new("P * 3", move || {
                        black_box(black_box(p.clone()) * black_box(small));
                    })
                },
                {
                    let p = p.clone();
                    Class::new("P * (2^64 - 1)", move || {
                        black_box(black_box(p.clone()) * black_box(large));
                    })
                },
                Class::new("P * random", move || {
                    black_box(black_box(p.clone()) * black_box(random));
                }),
            ]
        },
    );
}

/// Scalar multiplication must not leak identity inputs or outputs (`P * 0` is
/// hit by `token_response` when `hidden_metadata == 0`).
fn point_mul_is_constant_time_in_the_point<B: TimingProfile>() {
    check(
        "point_mul_is_constant_time_in_the_point",
        B::NAME,
        B::CT_POINT_ARITHMETIC,
        PRIMITIVE,
        || {
            let p = random_point::<B>();
            let id = B::point_identity();
            let zero = B::scalar_zero();
            let random = B::random_non_zero_scalar();
            vec![
                {
                    let p = p.clone();
                    Class::new("P * random", move || {
                        black_box(black_box(p.clone()) * black_box(random));
                    })
                },
                Class::new("P * 0", move || {
                    black_box(black_box(p.clone()) * black_box(zero));
                }),
                Class::new("O * random", move || {
                    black_box(black_box(id.clone()) * black_box(random));
                }),
            ]
        },
    );
}

/// Point negation must not leak whether its operand is the identity.
fn point_neg_is_constant_time<B: TimingProfile>() {
    check("point_neg_is_constant_time", B::NAME, B::CT_POINT_ARITHMETIC, PRIMITIVE, || {
        let p = random_point::<B>();
        let id = B::point_identity();
        vec![
            Class::new("-P", move || {
                black_box(-black_box(p.clone()));
            }),
            Class::new("-O", move || {
                black_box(-black_box(id.clone()));
            }),
        ]
    });
}

/// Scalar addition must not leak its operands (constant-time control).
fn scalar_add_is_constant_time<B: TimingProfile>() {
    check(
        "scalar_add_is_constant_time",
        B::NAME,
        /* expect_constant_time= */ true,
        PRIMITIVE,
        || {
            let zero = B::scalar_zero();
            let a = B::random_non_zero_scalar();
            let b = B::random_non_zero_scalar();
            vec![
                Class::new("0 + 0", move || {
                    black_box(black_box(zero) + black_box(zero));
                }),
                Class::new("0 + a", move || {
                    black_box(black_box(zero) + black_box(a));
                }),
                Class::new("a + b", move || {
                    black_box(black_box(a) + black_box(b));
                }),
                Class::new("a + a", move || {
                    black_box(black_box(a) + black_box(a));
                }),
            ]
        },
    );
}

/// Scalar subtraction must not leak its operands, including `a - a = 0`
/// (constant-time control).
fn scalar_sub_is_constant_time<B: TimingProfile>() {
    check(
        "scalar_sub_is_constant_time",
        B::NAME,
        /* expect_constant_time= */ true,
        PRIMITIVE,
        || {
            let zero = B::scalar_zero();
            let a = B::random_non_zero_scalar();
            let b = B::random_non_zero_scalar();
            vec![
                Class::new("a - b", move || {
                    black_box(black_box(a) - black_box(b));
                }),
                Class::new("a - a", move || {
                    black_box(black_box(a) - black_box(a));
                }),
                Class::new("a - 0", move || {
                    black_box(black_box(a) - black_box(zero));
                }),
                Class::new("0 - a", move || {
                    black_box(black_box(zero) - black_box(a));
                }),
            ]
        },
    );
}

/// Scalar multiplication must not leak its operands, including 0 and 1
/// (constant-time control).
fn scalar_mul_is_constant_time<B: TimingProfile>() {
    check(
        "scalar_mul_is_constant_time",
        B::NAME,
        /* expect_constant_time= */ true,
        PRIMITIVE,
        || {
            let zero = B::scalar_zero();
            let one = B::scalar_one();
            let a = B::random_non_zero_scalar();
            let b = B::random_non_zero_scalar();
            vec![
                Class::new("0 * a", move || {
                    black_box(black_box(zero) * black_box(a));
                }),
                Class::new("1 * a", move || {
                    black_box(black_box(one) * black_box(a));
                }),
                Class::new("a * b", move || {
                    black_box(black_box(a) * black_box(b));
                }),
                Class::new("a * a", move || {
                    black_box(black_box(a) * black_box(a));
                }),
            ]
        },
    );
}

/// Scalar inversion must not leak its operand, including 0 (constant-time control).
fn scalar_invert_is_constant_time<B: TimingProfile>() {
    check(
        "scalar_invert_is_constant_time",
        B::NAME,
        /* expect_constant_time= */ true,
        PRIMITIVE,
        || {
            let zero = B::scalar_zero();
            let one = B::scalar_one();
            let a = B::random_non_zero_scalar();
            vec![
                Class::new("invert(0)", move || {
                    black_box(B::scalar_invert(black_box(&zero)));
                }),
                Class::new("invert(1)", move || {
                    black_box(B::scalar_invert(black_box(&one)));
                }),
                Class::new("invert(random)", move || {
                    black_box(B::scalar_invert(black_box(&a)));
                }),
            ]
        },
    );
}

// ===========================================================================
// Whole-protocol tests
// ===========================================================================

/// Small bucket count to maximize the relative signal of fixed-cost leaks.
const TIMING_N_BUCKETS: u8 = 2;

/// Token issuance must take the same time regardless of `hidden_metadata`.
fn token_response_is_constant_time_in_hidden_metadata<B: TimingProfile>() {
    use crate::{key_gen_generic, token_request_generic, token_response_generic, GenericParams};

    check(
        "token_response_is_constant_time_in_hidden_metadata",
        B::NAME,
        B::CT_ISSUANCE,
        PROTOCOL,
        || {
            let params = GenericParams::<B>::new_generic(TIMING_N_BUCKETS, b"timing_test".to_vec())
                .expect("params");
            let (sk, pk, proof) = key_gen_generic::<B>(&params);
            let (_ctx, request) =
                token_request_generic::<B>(&pk, &proof, &params).expect("token request");

            (0..TIMING_N_BUCKETS)
                .map(|metadata| {
                    let label = format!("hidden_metadata = {metadata}");
                    let params = params.clone();
                    let sk = sk.clone();
                    let pk = pk.clone();
                    let request = request.clone();
                    Class::new(label, move || {
                        black_box(
                            token_response_generic::<B>(
                                black_box(&sk),
                                black_box(&pk),
                                black_box(&request),
                                black_box(metadata),
                                black_box(&params),
                            )
                            .expect("token response"),
                        );
                    })
                })
                .collect()
        },
    );
}

/// Token redemption (`verify_token`) must take the same time regardless of the
/// token's embedded metadata (constant-time control: both backends pass).
fn verify_token_is_constant_time_in_metadata<B: TimingProfile>() {
    use crate::{
        finalize_token_generic, key_gen_generic, token_request_generic, token_response_generic,
        verify_token_generic, GenericParams,
    };

    check(
        "verify_token_is_constant_time_in_metadata",
        B::NAME,
        /* expect_constant_time= */ true,
        PROTOCOL,
        || {
            let params = GenericParams::<B>::new_generic(TIMING_N_BUCKETS, b"timing_test".to_vec())
                .expect("params");
            let (sk, pk, proof) = key_gen_generic::<B>(&params);

            (0..TIMING_N_BUCKETS)
                .map(|metadata| {
                    let (ctx, request) =
                        token_request_generic::<B>(&pk, &proof, &params).expect("token request");
                    let response =
                        token_response_generic::<B>(&sk, &pk, &request, metadata, &params)
                            .expect("token response");
                    let token =
                        finalize_token_generic::<B>(&ctx, &pk, &request, &response, &params)
                            .expect("finalize");

                    // Ensure we time the success path rather than early rejection.
                    let recovered = verify_token_generic::<B>(&sk, &token, &params);
                    assert_eq!(
                        recovered.unwrap_or(u8::MAX),
                        metadata,
                        "token did not round-trip; the timing measurement would be meaningless"
                    );

                    let label = format!("token carries metadata {metadata}");
                    let params = params.clone();
                    let sk = sk.clone();
                    Class::new(label, move || {
                        black_box(verify_token_generic::<B>(
                            black_box(&sk),
                            black_box(&token),
                            black_box(&params),
                        ));
                    })
                })
                .collect()
        },
    );
}

/// Synthetic self-check verifying the harness flags a known ~2x timing difference.
#[test]
fn harness_detects_synthetic_leak() {
    #[inline(never)]
    fn spin(mut x: u64, rounds: usize) -> u64 {
        for _ in 0..rounds {
            x = black_box(x).wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        }
        x
    }

    check(
        "harness_detects_synthetic_leak",
        "self-test",
        /* expect_constant_time= */ false,
        PRIMITIVE,
        || {
            vec![
                Class::new("64 rounds", || {
                    black_box(spin(black_box(1), 64));
                }),
                Class::new("128 rounds", || {
                    black_box(spin(black_box(1), 128));
                }),
            ]
        },
    );
}

// ===========================================================================
// Test instantiation, one module per backend
// ===========================================================================

macro_rules! timing_suite {
    ($mod_name:ident, $backend:ty) => {
        mod $mod_name {
            #[test]
            fn point_add_is_constant_time() {
                super::point_add_is_constant_time::<$backend>();
            }

            #[test]
            fn point_add_is_constant_time_when_operands_cancel() {
                super::point_add_is_constant_time_when_operands_cancel::<$backend>();
            }

            #[test]
            fn point_sub_is_constant_time() {
                super::point_sub_is_constant_time::<$backend>();
            }

            #[test]
            fn point_sub_is_constant_time_when_operands_cancel() {
                super::point_sub_is_constant_time_when_operands_cancel::<$backend>();
            }

            #[test]
            fn point_mul_is_constant_time_in_the_scalar() {
                super::point_mul_is_constant_time_in_the_scalar::<$backend>();
            }

            #[test]
            fn point_mul_is_constant_time_in_the_point() {
                super::point_mul_is_constant_time_in_the_point::<$backend>();
            }

            #[test]
            fn point_neg_is_constant_time() {
                super::point_neg_is_constant_time::<$backend>();
            }

            #[test]
            fn scalar_add_is_constant_time() {
                super::scalar_add_is_constant_time::<$backend>();
            }

            #[test]
            fn scalar_sub_is_constant_time() {
                super::scalar_sub_is_constant_time::<$backend>();
            }

            #[test]
            fn scalar_mul_is_constant_time() {
                super::scalar_mul_is_constant_time::<$backend>();
            }

            #[test]
            fn scalar_invert_is_constant_time() {
                super::scalar_invert_is_constant_time::<$backend>();
            }

            #[test]
            fn token_response_is_constant_time_in_hidden_metadata() {
                super::token_response_is_constant_time_in_hidden_metadata::<$backend>();
            }

            #[test]
            fn verify_token_is_constant_time_in_metadata() {
                super::verify_token_is_constant_time_in_metadata::<$backend>();
            }
        }
    };
}

#[cfg(feature = "rustcrypto")]
timing_suite!(rustcrypto, crate::backend::rustcrypto::RustCryptoBackend);

#[cfg(feature = "boringssl")]
timing_suite!(boringssl, crate::backend::boringssl::BoringSslBackend);
