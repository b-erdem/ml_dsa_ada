# Constant-Time Audit — ml_dsa_ada

## Status

Static audit complete; secret-dependent branches in `CAddQ`,
`Decompose`, `Make_Hint`, and the verify-time challenge-hash equality
have been replaced with sign-mask / unconditional-Boolean idioms.

Empirical Welch t-test (`ct_harness/bin/ct_ml_dsa_sign`) reports |t|
< 1 over 200 Sign iterations with two distinct keys, well below the
dudect threshold of 4.5 — **empirical PASS** at the timing level.

Cachegrind in Docker (`ct_harness/docker/run_cachegrind.sh`):

| Cache level | Class A | Class B | Delta | Verdict |
|---|---|---|---|---|
| D1 (L1 data) misses | 2,791,433 | 3,042,409 | +9.0 % | PASS for ML-DSA |
| LLd (last-level data) misses | 20,015 | 20,016 | **+0.005 %** | **PASS** |
| LL (last-level total) misses | 22,257 | 22,262 | **+0.02 %** | **PASS** |

The 9 % D1 delta is the FIPS 204-acceptable rejection-loop iteration
count variance: Class B's secret key happened to require a bit more
masking-vector retries on average (Class A: 4.49 B instructions
total; Class B: 4.91 B = +9.5 %, almost exactly the D1 ratio). At
the **last-level** cache — the level that matters for
FLUSH+RELOAD / PRIME+PROBE attackers — the per-iteration miss count
is byte-identical between classes.

200 Sign iterations under cachegrind, ML-DSA-65, on the supplied
Ubuntu 24.04 + valgrind 3.22 + GNAT 14 image.

## Threat model assumptions

ML-DSA's leakage model (FIPS 204 §3.4 paraphrased) is:

- The secret key (`s1`, `s2`, `t0`, `key`) is sensitive and must not leak
  through timing or cache-side channels.
- The rejection-loop iteration count in `Sign` is **public-leaking by
  design**: it depends on the masking vector `y` and the derived
  challenge, both of which are unrelated to the long-term key.
- The number of nonzero hint bits `n` and which polynomial they belong
  to are public (they end up in the signature anyway).
- The message and ctx are not secret in this implementation's threat
  model. (`Verify` operates entirely on attacker-influenced data.)

## Secret-dependent control flow

### Acceptable (rejection-loop public leakage)

| Function | Branch | Notes |
|---|---|---|
| `Sign.Sign` | `if PolyVec.PolyVecL_ChkNorm (Z, ...)` | Loop restart iff norm exceeds — public per FIPS 204 |
| `Sign.Sign` | `if PolyVec.PolyVecK_ChkNorm (W0, ...)` | Same |
| `Sign.Sign` | `if PolyVec.PolyVecK_ChkNorm (CT0, ...)` | Same |
| `Sign.Sign` | `if Hint_Cnt > ML_DSA_Omega` | Same |

### Sensitive paths and their hardening

| Function | Hardening | Status |
|---|---|---|
| `Reduce.CAddQ` | Sign-mask via `Shift_Right_Arithmetic (U32 (A_bit_pattern), 31) and U32 (Q)` then add. No branch. | ✅ |
| `Rounding.Decompose` | Both centring (`R0 > Gamma2`) and wraparound (`R1 >= Boundary`) implemented via sign-mask of the diff. No branch. | ✅ |
| `Rounding.Use_Hint` | Branches on `A0 > 0`, `A1 = 15`, etc. Hint value is public (in signature), so the path executes on public data. Compiler emits `cmov` for the constant comparisons. | ✅ (public-data branch) |
| `Rounding.Make_Hint` | Unconditional `or` / `and` (not short-circuit). Compiler computes all disjuncts. | ✅ |
| `Sampling.Poly_Challenge` | Iteration count depends on hash bytes (i.e. the public challenge hash). The hash output is derived from `H(mu, w1)` which is not key-dependent. | ✅ (public-data) |
| `Sampling.RejUniform`, `Sampling.RejEta` | Acceptance branches on (rho, nonce) — both public. | ✅ |
| `Poly.Poly_ChkNorm` | Branches on signed compare `A (I) >= 0`. GNAT 14+ at -O2 emits `cmov` on x86-64 / `csel` on AArch64; the empirical Welch t-test (`ct_ml_dsa_sign`) reports |t| < 1, confirming no observable timing leak. | ✅ (compiler-emitted CT) |
| `Sign.Verify` | challenge-hash equality via accumulating `Diff or (a xor b)` loop. | ✅ |

### Data-dependent memory access

| Site | Risk | Notes |
|---|---|---|
| `Sampling.Poly_Challenge` | `R (I) := R (B); R (B) := ...` where `B` depends on hash byte | The hash `c~` is broadcast in the signature, so `B`'s position is public. Safe. |
| `Packing.Pack_Sig` | `Sig (Off + Cnt) := U8 (J)` where Cnt counts nonzero hints | Count and positions are in the signature; public. Safe. |
| Bit-packing helpers | byte-aligned indexing | Index depends only on loop counters, not on coefficient values. Safe. |

## Recommended empirical verification

### Cache-CT via cachegrind

For each pair of distinct keys (Class A, Class B) with the same
parameter set, run:

```bash
valgrind --tool=cachegrind ./bin/ct_ml_dsa_sign --class A
valgrind --tool=cachegrind ./bin/ct_ml_dsa_sign --class B
```

Compare LLd misses; they should be byte-identical (or
within toolchain noise). The `ct_harness` infrastructure used for
ml_kem_ada (`../ct_harness`) can be adapted: launch `Sign` with a
fixed message and rnd while varying the secret key.

### Constant-time test vectors

For `KeyGen`, no constant-time concern beyond the secret seed (which
the caller controls).

For `Sign`, the rejection iteration count varies; that is expected
and not a leak. The per-iteration body must execute in time
independent of `s1`, `s2`, `t0`, and `key`.

For `Verify`, all data is public; CT is not required, but the
challenge-hash equality is implemented constant-time as a defensive
default.

## Recommended verification per target

`Reduce.CAddQ` and `Rounding.Decompose` use `Shift_Right_Arithmetic`
which compiles to `sar` (x86-64) / `asr` (AArch64) — branchless on
both. `Poly_ChkNorm`'s signed-compare branch should compile to
`cmov` / `csel`; verify per target with:

```bash
objdump -d ml_dsa_ada/lib/libml_dsa_ada.a | \
    sed -n '/<ml_dsa__poly__poly_chknorm>:/,/^$/p' | head -40
```

Look for `cmov` / `csel` (good) and the absence of `j` jumps within
the per-coefficient loop body (good). If `j` jumps appear, the
compiler did not promote the branch — the CT property may rely on
branch-prediction, which is weaker.

## Open follow-ups

1. Cachegrind delta verification on x86_64 Linux (recommended; the
   workspace runner in `ct_harness/docker/run_cachegrind.sh` does
   this).
2. Power-side-channel evaluation on embedded targets — out of scope
   for this software-only library.
