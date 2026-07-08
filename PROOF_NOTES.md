# SPARK Proof Notes — ml_dsa_ada

This document records the proof techniques applied to `ml_dsa_ada` and
the open work to bring the entire codebase to a `0 unproved` state.

The companion document for ML-KEM is
[ml_kem_ada/PROOF_NOTES.md](../ml_kem_ada/PROOF_NOTES.md), which
established many of the patterns reused here.

## Current state

**100 % proved across all three parameter sets**, SPARK level 1, z3:

| Parameter set | Total VCs | Unproved | `pragma Assume` |
|---|---|---|---|
| ML-DSA-44 | 1880 | 0 | 0 |
| ML-DSA-65 (default) | 1882 | 0 | 0 |
| ML-DSA-87 | 1881 | 0 | 0 |

```
SPARK Analysis results        Total         Flow                      Provers   Justified   Unproved
Total                          1882    231 (12%)                   1651 (88%)           .          .
```

| Module | Checks | Unproved |
|---|---|---|
| `ML_DSA.Reduce` | ~25 | 0 |
| `ML_DSA.Rounding` | ~120 | 0 |
| `ML_DSA.Poly` | ~140 | 0 |
| `ML_DSA.NTT` (forward + InvNTT + Pointwise + Butterfly) | ~250 | 0 |
| `ML_DSA.PolyVec` | ~280 | 0 |
| `ML_DSA.Symmetric` | ~30 | 0 |
| `ML_DSA.Sampling` | ~80 | 0 |
| `ML_DSA.Packing` | ~620 | 0 |
| `ML_DSA.Wipe` | ~25 | 0 |
| `ML_DSA.Sign` | ~315 | 0 |

Reproduce:

```bash
cd ml_dsa_ada
alr exec -- gnatprove -P ml_dsa_ada.gpr --level=1 --prover=z3 --timeout=20
```

Takes about 3-5 minutes on Apple Silicon (Rosetta x86_64).

## Techniques applied

### 1. Type-level bound on Zeta_Type

The `Zetas` table holds 256 precomputed Montgomery-form twiddles, each
in `[-(Q-1)/2, (Q-1)/2]`. Declaring `Zeta_Type` as a subtype with that
range gives SPARK the bound for free, so any `Zeta * coeff` product
inside the NTT inherits a known maximum without per-element case
analysis.

```ada
subtype Zeta_Type is I32 range -(Q - 1) / 2 .. (Q - 1) / 2;
Zetas : constant array (0 .. 255) of Zeta_Type := [...];
```

### 2. Six-piece segment invariant for the forward NTT

The inner `for J in Start .. Start + Len - 1 loop` body modifies
`R(J)` and `R(J+Len)`. The remaining 254 positions split into 5
disjoint segments (already-processed prefix, low-half pending,
high-half pending, etc.). Each segment has a distinct bound — either
the layer-entry bound `B` or the post-butterfly bound `B + Q`.

```ada
pragma Loop_Invariant (for all I in 0 .. Start - 1 =>
                          R (I) in -(Bound + Q) .. (Bound + Q));
pragma Loop_Invariant (for all I in Start .. J - 1 =>
                          R (I) in -(Bound + Q) .. (Bound + Q));
pragma Loop_Invariant (for all I in J .. Start + Len - 1 =>
                          R (I) in -Bound .. Bound);
pragma Loop_Invariant (for all I in Start + Len .. J + Len - 1 =>
                          R (I) in -(Bound + Q) .. (Bound + Q));
pragma Loop_Invariant (for all I in J + Len .. Start + 2 * Len - 1 =>
                          R (I) in -Bound .. Bound);
pragma Loop_Invariant (for all I in Start + 2 * Len .. N - 1 =>
                          R (I) in -Bound .. Bound);
--  Loose universal envelope to satisfy Butterfly's `for all I` precondition:
pragma Loop_Invariant (for all I in 0 .. N - 1 =>
                          R (I) in -(Bound + Q) .. (Bound + Q));
```

This pattern is structurally identical to the ml_kem proof and adapts
directly because the forward NTT shares the Cooley-Tukey skeleton.

### 3. Decompose: replace fixed-point trick with direct algorithm

The dilithium reference uses a sequence of magic-constant
multiplications (`a1 := (a1 * 1025 + (1 << 21)) >> 22`) to compute
`a / (2*Gamma2)` without integer division. Proving the post-condition
`a0 in -Gamma2 .. Gamma2` from the fixed-point arithmetic required a
`pragma Assume`.

We rewrote `Decompose` to follow FIPS 204 §7.5 / Algorithm 36 directly:

```ada
R0 := A mod Two_G2;
R1 := (A - R0) / Two_G2;
if R0 > ML_DSA_Gamma2 then          --  centring
   R0 := R0 - Two_G2;
   R1 := R1 + 1;
end if;
if R1 >= Boundary then               --  wraparound
   R1 := 0;
   R0 := R0 - 1;
end if;
```

This proves cleanly because each step has a small linear-arithmetic
proof obligation; the magic-constant approximation argument is
unnecessary.

### 4. Reduce32_Bound widened to cover full I32 input

The dilithium reference cites `|reduce32(a)| < 6 283 009` under the
precondition `|a| <= 2^31 - 2^22 - 1`. For arbitrary I32 input the
bound widens by one extra step of `t = ±256`:

```
|Result| ≤ 2^22 + |T_Floor| * (2^23 - Q)
        ≤ 2^22 + 256 * 8191
        = 6 291 200
```

We define `Reduce32_Bound = 6 291 200` so the post-condition holds
without any precondition. Downstream `NTT_Output_Bound = R32_B + 8*Q`
absorbs the small widening.

### 5. Eta_Decode: explicit clamp instead of Assume

`PolyEta_Unpack` decodes 3-bit (η=2) or 4-bit (η=4) values into
coefficients in `[-η, η]`. Raw bit patterns above `2*η` (i.e. 5–7 for
η=2, 9–15 for η=4) cannot represent any valid s1/s2 coefficient, but
the subtraction `η - v` would give an out-of-spec value.

We added an inlined `Eta_Decode` function that clamps the
unsupported range to 0 and proves the post-condition statically:

```ada
function Eta_Decode (V : U32) return I32 is
  (if V <= 2 * ML_DSA_Eta
   then ML_DSA_Eta - I32 (V)
   else 0)
  with Pre  => V <= 15,
       Post => Eta_Decode'Result in -ML_DSA_Eta .. ML_DSA_Eta;
```

For well-formed encodings (which is what our `PolyEta_Pack` and the
NIST KAT vectors produce) the clamp branch is dead code; for
adversarial bytes the clamp avoids leaking out-of-range coefficients
into downstream NTT / norm checks. KAT compatibility is preserved.

### 6. Pack_Sig with explicit Hint_Count parameter

The signature hint encoding writes positions of nonzero `H` bits into
the first ω bytes of the hint section. Without an upper bound on the
count, SPARK couldn't prove `Cnt < ω` before each write.

Rather than introduce a ghost-function counting the trues, we added an
explicit `Hint_Count : Natural` parameter constrained by precondition
`Hint_Count <= ML_DSA_Omega`. The caller (`Sign`) already computes this
count via `Poly_Make_Hint`, and the signing rejection loop already
guarantees the bound — so the change is just plumbing.

The encoding loop guards each write with `Cnt < Hint_Count`, which
SPARK verifies against the precondition.

## Open work

### 7. InvNTT_ToMont per-position bounds (resolved)

The inverse NTT's intermediate values cannot respect a uniform bound
the way the forward NTT can: position 0 doubles each layer, reaching
`256 * R32_B ≈ 1.6e9` after 8 layers. We use a layered uniform
envelope `Bound = 2^L * R32_B` at the start of layer L:

```ada
pragma Loop_Invariant
  (case Len is
     when 1   => Bound = Reduce32_Bound,
     when 2   => Bound = 2 * Reduce32_Bound,
     ...
     when 128 => Bound = 128 * Reduce32_Bound,
     when others => False);
```

Inside the layer, the six-piece segment invariant lets SPARK see
that the currently-touched `R(J)` and `R(J+Len)` are still in the
*tight* `-Bound..Bound` window (not the post-body `-2*Bound..2*Bound`
envelope), so `T + U` and `T - U` fit in I32 (since `2 * 128 * R32_B
< 2^31`).

The K_Idx counter is tied to (Start, Len) by `2 * K_Idx * Len + Start
= 2 * N` so SPARK sees zetas[K_Idx] is always in range.

### 8. Sign body init-flow and chained preconditions (resolved)

Solved by:
1. `:= [others => 0]` defaults on every secret-touching local in
   `Sign` and `Verify`.
2. `Always_Terminates => True` aspect on `Symmetric.SHAKE*`,
   `PolyVec.*`, `Poly.*`, `Rounding.Decompose`, `Sampling.Poly_*`
   etc., plus `Loop_Variant` on every rejection-sampling and
   gamma1-block-squeeze loop.
3. Inserting `Reduce` between operations whose output bound exceeds
   the next call's precondition (notably between
   `Pointwise_Poly_Montgomery` and `InvNTT_ToMont` where
   `|out| < Q` exceeds `R32_B = 6.29M < Q-1 = 8.38M`).
4. Adding `Post` to `Unpack_Sig` propagating `Z` and `H` bounds
   across the call boundary.
5. Adding `Post` to `Poly_ChkNorm` / `PolyVec*_ChkNorm` so the
   negative branch ("returned False") establishes `|coeff| < B`,
   which then implies the `|coeff| < Gamma1` precondition of
   `Pack_Sig`.

### 9. Always_Terminates cascade (resolved)

Every public subprogram in the project has `Always_Terminates =>
True`. The only loops that needed manual `Loop_Variant` were the
inner-most KECCAK byte advance loops in `Sampling.Poly_Challenge`
(bounded by an explicit attempt cap of 65 536) and the
gamma1-block-squeeze loop in `Sampling.Poly_Uniform_Gamma1`.

### 10. Decompose wraparound: U32 modular subtraction

The wraparound branch of `Decompose` originally used the same
`I64 → mod 2^32 → U32` chain as the centring branch. This proved
cleanly for ML-DSA-65/87 (where `Boundary = 16`) but z3 at level=1
could not discharge the `Diff < 0 → Diff_U >= 2^31` step for ML-DSA-44
(where `Boundary = 44`). The wider mod-2^32 case-split blew the
solver's step budget.

The fix replaces the I64 chain with native `Interfaces.Unsigned_32`
modular subtraction, which SPARK reasons about directly without
needing the explicit `mod 2^32` step:

```ada
declare
   R1_U          : constant U32 := U32 (R1);
   Boundary_M1_U : constant U32 := U32 (Boundary - 1);
   Diff_U        : constant U32 := Boundary_M1_U - R1_U;  -- wraps modularly
   Sign_Ext      : constant U32 :=
     Interfaces.Shift_Right_Arithmetic (Diff_U, 31);
   ...
begin
   pragma Assert (if R1 >= Boundary then Sign_Ext = 16#FFFF_FFFF#
                  else Sign_Ext = 0);
```

Identical compiled output (sub + sar still both branchless on x86-64),
proves uniformly across all three parameter sets at level=1 in z3.

### 11. Functional correctness contracts (partial)

In addition to the type / range / termination proofs, the following
algorithmic identities are stated and proven:

- `Reduce.Reduce32` — `(I64 (A) - I64 (Result)) mod I64 (Q) = 0`,
  i.e. result is congruent to A mod Q (within the widened bound
  `|Result| <= 6_291_200`).
- `Reduce.CAddQ` — `Result = A` or `Result = A + Q` (the only two
  legal post-reduction outcomes).
- `Rounding.Power2Round` — `A1 * 2^D + A0 = A`, full functional
  contract on the split.

`Decompose`'s analogous identity `A1 * 2*Gamma2 + A0 ≡ A (mod Q)`
is *not* proven symbolically, because z3 at level=1 cannot derive
the parameter-set-specific numeric identity `Boundary * 2*Gamma2 +
1 = Q` (Q = 8_380_417 = 16 * 523776 + 1 = 44 * 190464 + 1). It is
validated by NIST ACVP byte-exact cross-validation instead — see
[CT_AUDIT.md](CT_AUDIT.md) and `tests/src/test_acvp_full.adb`.

### 12. Fault-injection countermeasure: Sign_With_Self_Verify

A second public entry point in `ML_DSA.Sign` produces a signature
and immediately re-verifies it against the corresponding public
key. Verification failure indicates either a transient fault during
the signing computation (voltage glitch, particle strike, clock
glitching) or a `pk/sk` mismatch in the caller. On failure, the
output buffer is zeroised and `Ok` is set to `False`.

Cost: ~1.5x of plain `Sign` (Verify is roughly half the work).
The procedure is fully proven at SPARK level 1 — its functional
contract reuses the same pre/post chain as `Sign` and `Verify`.

Test cases in `test_ml_dsa.adb` cover the happy path and the
mismatched-pk rejection (simulating a fault that produces a
signature inconsistent with the supplied PK).

## Testing

Three test programs validate the implementation:

1. **`test_ml_dsa.adb`** — 25 unit tests covering Reduce, Rounding,
   NTT, an end-to-end KeyGen → Sign → Verify roundtrip plus tamper
   detection, and `Sign_With_Self_Verify` happy-path / pk-mismatch
   rejection — for the active parameter set.
2. **`test_kat_ml_dsa.adb`** — self-consistency KAT: SHA3-256 of
   pk/sk/sig under fixed seed/rnd/msg, regenerable via `--record`.
3. **`test_acvp_full.adb`** — NIST ACVP cross-validation.
   25 KeyGen + 15 SigGen (external/pure/det) + 15 SigVer
   (external/pure) test vectors per parameter set, byte-exact.
   Generated by `tests/scripts/gen_acvp_full.py` against the
   active parameter set, sourced from
   [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server).
   55/55 tests pass for each of ML-DSA-44/65/87.

`ct_harness/bin/ct_ml_dsa_sign` runs a Welch t-test on Sign with two
distinct keys and random messages; current PASS at |t| < 1 over 200
iterations.

`scripts/ct_disasm_check.sh` disassembles the four CT-critical
functions (`Reduce.CAddQ`, `Rounding.Decompose`, `Rounding.Make_Hint`,
`Poly.Poly_ChkNorm`) and verifies the only conditional jumps are
overflow checks (`jo`) and forward jumps to `Constraint_Error`
helper stubs (statically dead for valid input). All four pass on
x86-64 with `gnat 14.2 + -O2`. See [SECURITY.md](SECURITY.md) for
the empirical CT methodology.
