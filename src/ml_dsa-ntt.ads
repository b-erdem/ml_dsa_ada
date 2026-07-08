--  Number-Theoretic Transform over Z_q[X] / (X^256 + 1) with q = 8 380 417.
--  256-point NTT (8 layers, in-place Cooley-Tukey).
--
--  Bound analysis (matching pq-crystals/dilithium):
--   * NTT input  : |coeffs| <= Reduce32_Bound  (after a Reduce32 pass)
--     NTT output : |coeffs| <= Reduce32_Bound + 8*Q (each butterfly
--                  layer contributes |t| <= Q via Montgomery_Reduce).
--   * InvNTT input  : |coeffs| <= Reduce32_Bound
--     InvNTT output : |coeffs| <= Q-1  (after the final f-multiply
--                     and Montgomery_Reduce, every coeff fits in (-Q, Q)).
--
--  The InvNTT intermediate (after L layers) at position 0 grows as
--  2^L * input_bound. With input_bound <= Reduce32_Bound = 6_283_009,
--  after L=8 the worst-case is 256 * 6_283_009 = 1_608_450_304 < 2^31,
--  so all intermediate values fit in I32 and SPARK's overflow checks
--  hold throughout.
package ML_DSA.NTT is

   pragma Pure;
   pragma SPARK_Mode;

   --  Forward NTT input bound: typically the output of Reduce32, or any
   --  coefficient strictly bounded by 6_283_009 in absolute value.
   NTT_Input_Bound  : constant := Reduce32_Bound;

   --  Forward NTT output bound: 8 layers, each adding Q.
   NTT_Output_Bound : constant := Reduce32_Bound + 8 * Q;

   --  Inverse NTT input bound (must be reduce32'd first).
   InvNTT_Input_Bound : constant := Reduce32_Bound;

   procedure NTT (R : in out Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 =>
                     R (I) in -NTT_Input_Bound .. NTT_Input_Bound),
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -NTT_Output_Bound .. NTT_Output_Bound);

   --  Inverse NTT, multiplied by Montgomery factor 2^32 mod q.
   --  After the final per-coefficient f-multiply, each coefficient is
   --  the output of Montgomery_Reduce and lies in (-Q, Q).
   procedure InvNTT_ToMont (R : in out Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 =>
                     R (I) in -InvNTT_Input_Bound .. InvNTT_Input_Bound),
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -(Q - 1) .. (Q - 1));

   --  Pointwise multiply in NTT domain. Both operands must be
   --  Montgomery-form coefficients with magnitude bounded by NTT_Output_Bound;
   --  the output is bounded by Q-1 (from Montgomery_Reduce).
   procedure Pointwise_Montgomery
     (R    : out Polynomial;
      A, B : Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 =>
                     A (I) in -NTT_Output_Bound .. NTT_Output_Bound)
                  and then (for all I in 0 .. N - 1 =>
                     B (I) in -NTT_Output_Bound .. NTT_Output_Bound),
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -(Q - 1) .. (Q - 1));

end ML_DSA.NTT;
