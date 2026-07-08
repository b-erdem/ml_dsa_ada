--  ML-DSA rounding primitives (FIPS 204 §7.4 — §7.7).
--
--  Power2Round splits an integer modulo q into a pair (a1, a0) with
--  a = a1 * 2^D + a0 and -2^{D-1} < a0 <= 2^{D-1}.  D = 13.
--
--  Decompose is the analogous operation with arbitrary "step size"
--  2*Gamma2 instead of 2^D.  It produces (a1, a0) with
--      a = a1 * (2*Gamma2) + a0   (mod q)
--  and -Gamma2 < a0 <= Gamma2 (centered).
--
--  MakeHint computes a single hint bit indicating whether the high
--  part of (a + a0) differs from the high part of a.  UseHint applies
--  that hint to recover the perturbed high part.
package ML_DSA.Rounding is

   pragma Pure;
   pragma SPARK_Mode;

   --  Power2Round bound on the low part: a0 in (-2^{D-1}, 2^{D-1}].
   --  We expose two-sided closed bounds for SPARK postconditions.
   Power2Round_Low_Bound : constant := 2 ** (D - 1);  -- 2^12 = 4096

   --  Power2Round high part: a1 has D-bit complement = 23 - 13 = 10
   --  bits, so a1 in [0, 2^10 - 1] = [0, 1023]. Negative inputs are
   --  expected to be in [0, Q-1] (i.e., the caller has applied caddq).
   Power2Round_High_Max : constant := 2 ** (23 - D) - 1;  -- 1023

   --  Decompose: a1 in [0, Decompose_High_Max] when input in [0, Q-1].
   --  Decompose_High_Max = (Q-1)/(2*Gamma2) - 1 (the special boundary
   --  case wraps a1 from (Q-1)/(2*Gamma2) back to 0).
   --   * Gamma2 = (Q-1)/88 (ML-DSA-44): a1 in [0, 43].
   --   * Gamma2 = (Q-1)/32 (ML-DSA-65/87): a1 in [0, 15].
   Decompose_High_Max : constant := (Q - 1) / (2 * ML_DSA_Gamma2) - 1;

   --  Decompose low part: -Gamma2 < a0 <= Gamma2 (centered).
   --  Wider bound used in postconditions: |a0| <= Gamma2.
   --  After the conditional Q-subtraction, a0 may temporarily
   --  reach -(Gamma2-1)..Gamma2 (excluding +Gamma2 in the special-case
   --  border), but conservatively we say |a0| <= Gamma2.

   --  Power2Round: split a in [0, Q-1] into a1 * 2^D + a0.
   procedure Power2Round
     (A0 : out I32;
      A1 : out I32;
      A  : I32)
     with Always_Terminates => True,
          Pre  => A in 0 .. Q - 1,
          Post => A0 in -(Power2Round_Low_Bound - 1) .. Power2Round_Low_Bound
                  and then A1 in 0 .. Power2Round_High_Max
                  and then A1 * (2 ** D) + A0 = A;

   --  Decompose: split a in [0, Q-1] into a1 * (2*Gamma2) + a0 (mod q).
   --  a0 is centred around 0; |a0| <= Gamma2.
   --
   --  The reconstruction congruence `a1 * 2*Gamma2 + a0 = a (mod Q)`
   --  is machine-proved: the sum is tracked exactly through the two
   --  constant-time mask branches (centring preserves it; the
   --  boundary fixup shifts it by exactly -Q because
   --  Boundary * 2*Gamma2 + 1 = Q), mirroring Power2Round's exact
   --  identity one level up.
   procedure Decompose
     (A0 : out I32;
      A1 : out I32;
      A  : I32)
     with Always_Terminates => True,
          Pre  => A in 0 .. Q - 1,
          Post => A0 in -ML_DSA_Gamma2 .. ML_DSA_Gamma2
                  and then A1 in 0 .. Decompose_High_Max
                  and then (A1 * (2 * ML_DSA_Gamma2) + A0) mod Q = A;

   --  HighBits: top half of Decompose. (Convenience wrapper.)
   function HighBits (A : I32) return I32
     with Pre  => A in 0 .. Q - 1,
          Post => HighBits'Result in 0 .. Decompose_High_Max;

   --  MakeHint: returns 1 iff a single hint bit is needed at this
   --  coefficient, i.e., the low part has rolled over the boundary.
   --  Inputs come from a Decompose-style split, with a0 in (-Gamma2..
   --  Gamma2] being the "low" portion of (a + ct0) and a1 the
   --  "expected" high portion.
   function Make_Hint (A0, A1 : I32) return U8
     with Post => Make_Hint'Result in 0 .. 1;

   --  UseHint: apply the hint bit to recover the corrected high part.
   --  Result is in [0, Decompose_High_Max].
   function Use_Hint (Hint : U8; A : I32) return I32
     with Pre  => A in 0 .. Q - 1
                  and then Hint <= 1,
          Post => Use_Hint'Result in 0 .. Decompose_High_Max;

end ML_DSA.Rounding;
