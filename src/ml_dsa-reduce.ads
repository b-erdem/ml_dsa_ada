--  Field arithmetic over Z_q with q = 8 380 417.
--
--  Three reductions:
--   * Montgomery_Reduce — for Montgomery-form multiplication. Input
--     is a 64-bit value bounded by Q*2^31 in magnitude, output lies
--     in (-Q, Q).
--   * Reduce32 — Barrett-like reduction of a 32-bit signed value.
--     The pq-crystals implementation computes
--       t := (a + (1 << 22)) >> 23;
--       return a - t * Q;
--     which yields a result in roughly [-(Q+1)/2, (Q+1)/2].
--   * CAddQ — conditional add Q to bring a centered representative
--     into [0, Q-1] (used before bit packing).
package ML_DSA.Reduce is

   pragma Pure;
   pragma SPARK_Mode;

   --  Montgomery reduction.
   --
   --    t := A_low (mod 2^32) * Q_Inv (mod 2^32);
   --    R := (A - t * Q) / 2^32;
   --
   --  yields R such that `R * 2^32 ≡ A (mod Q)`, equivalently
   --  `R ≡ A * 2^{-32} (mod Q)`. The functional identity is true
   --  by construction (Q * Q_Inv ≡ 1 mod 2^32 is a numeric fact
   --  about the chosen constants, see the body comment), but SPARK
   --  cannot derive it without bit-vector reasoning. The
   --  post-condition therefore only states the I32 range; the
   --  modular identity is documented in the body and validated
   --  via the NIST ACVP byte-exact tests in tests/.
   function Montgomery_Reduce (A : I64) return I32
     with
       Pre  => A in -(I64 (Q) * 2 ** 31) .. (I64 (Q) * 2 ** 31 - 1),
       Post => Montgomery_Reduce'Result in -(Q - 1) .. (Q - 1);

   --  Barrett-style reduction. The reference implementation guarantees
   --  the output magnitude is at most ~(Q+1)/2 + 2^22 < 6_283_009; we
   --  expose a slightly looser bound that's still tight enough for all
   --  downstream chknorm / NTT precondition reasoning.
   --
   --  Functional contract: `Result ≡ A (mod Q)` — the value is
   --  congruent to A modulo Q (i.e., `A - Result` is a multiple of Q).
   function Reduce32 (A : I32) return I32
     with
       Post => Reduce32'Result in -Reduce32_Bound .. Reduce32_Bound
               and then ((I64 (A) - I64 (Reduce32'Result))
                          mod I64 (Q) = 0);

   --  Conditional add Q: maps centered representative into [0, Q-1].
   --  Precondition: A is a centered representative output of
   --  Reduce32 or a difference within (-Q, Q).
   --
   --  Functional contract: `Result = A` if A >= 0, else `Result = A + Q`
   --  — equivalently, `Result ≡ A (mod Q)` and `Result >= 0`.
   function CAddQ (A : I32) return Coeff_Standard
     with
       Pre  => A in -(Q - 1) .. (Q - 1),
       Post => (CAddQ'Result = A) or (CAddQ'Result = A + Q);

end ML_DSA.Reduce;
