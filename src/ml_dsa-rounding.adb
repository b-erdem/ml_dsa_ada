with Interfaces;

package body ML_DSA.Rounding is
   pragma SPARK_Mode (On);

   --  Several if-conditions in this body are parameter-set-dependent
   --  static selectors (eta=2 vs 4, gamma1=2^17 vs 2^19, gamma2 variants).
   --  GNAT correctly folds them to constants at compile time and warns
   --  about the dead branch; that's intentional.
   pragma Warnings (Off, "condition is always*",
                    Reason => "Parameter-set static selector.");
   pragma Warnings (Off, "this statement is never reached*",
                    Reason => "Parameter-set static selector.");
   pragma Warnings (Off, "statement has no effect",
                    Reason => "Parameter-set static selector.");

   ----------------------------------------------------------------------
   --  Power2Round (FIPS 204 §7.4)
   --
   --    a1 = (a + 2^{D-1} - 1) >> D
   --    a0 = a - a1 * 2^D
   --
   --  For a in [0, Q-1]:
   --    a1 in [0, 1023]  (10-bit value)
   --    a0 in [-(2^{D-1}-1), 2^{D-1}] = [-4095, 4096]
   --  and a = a1 * 2^D + a0.
   ----------------------------------------------------------------------
   procedure Power2Round (A0 : out I32; A1 : out I32; A : I32) is
      --  A + 2^{D-1} - 1 = A + 4095 fits in I32 since A <= Q-1 < 2^{23}.
      T : constant I32 := A + (2 ** (D - 1) - 1);
   begin
      pragma Assert (T in 4095 .. Q + 4094);
      A1 := T / (2 ** D);
      pragma Assert (A1 in 0 .. Power2Round_High_Max);
      A0 := A - A1 * (2 ** D);
      pragma Assert (A0 in -(2 ** (D - 1) - 1) .. 2 ** (D - 1));
   end Power2Round;

   ----------------------------------------------------------------------
   --  Decompose (FIPS 204 §7.5)
   --
   --  Splits a (mod q) into a high part a1 and low part a0 such that
   --      a = a1 * (2 * Gamma2) + a0   (mod q)
   --      -Gamma2 < a0 <= Gamma2
   --      0 <= a1 <= (q-1)/(2*Gamma2)
   --
   --  Two parameter-set variants depending on whether 2*Gamma2 divides
   --  q-1 (Gamma2 = (q-1)/32) or 88 | q-1 (Gamma2 = (q-1)/88).
   --
   --  The fixed-point sequence
   --      a1 := (a + 127) >> 7
   --      a1 := (a1 * 1025 + (1 << 21)) >> 22       -- (Q-1)/32 variant
   --      a1 &= 15
   --  approximates a / (2*Gamma2), and similarly for the (Q-1)/88
   --  variant with multipliers (11275, 1<<23, >>24, XOR with 43-mask).
   ----------------------------------------------------------------------
   procedure Decompose (A0 : out I32; A1 : out I32; A : I32) is
      --  Direct FIPS 204 §7.5 / Algorithm 36:
      --    r0 := A mod (2*Gamma2)        in [0, 2*Gamma2 - 1]
      --    r1 := (A - r0) / (2*Gamma2)   in [0, Boundary]
      --    centre:    if r0 > Gamma2 then r0 -= 2*Gamma2; r1 += 1.
      --    wraparound: if r1 >= Boundary then r1 := 0; r0 -= 1.
      --
      --  Both branches are CT-hardened via sign-mask arithmetic so the
      --  selection of the centring / wraparound paths leaks no info
      --  about the secret-derived input. See CT_AUDIT.md.
      Two_G2     : constant I32 := 2 * ML_DSA_Gamma2;
      Boundary   : constant I32 := (Q - 1) / Two_G2;
      R0_Initial : constant I32 := A mod Two_G2;
      R0         : I32 := R0_Initial;
      R1         : I32 := (A - R0_Initial) / Two_G2;
   begin
      pragma Assert (R0 in 0 .. Two_G2 - 1);
      pragma Assert (R1 in 0 .. Boundary);

      --  Centring branch: condition is `R0 > Gamma2`, equivalent to
      --  `Gamma2 - R0 < 0`, which has the high bit set in two's
      --  complement. ASR by 31 gives 0 (R0 <= Gamma2) or -1 (R0 > Gamma2).
      declare
         Diff      : constant I64 := I64 (ML_DSA_Gamma2) - I64 (R0);
         Diff_Mod  : constant I64 := (Diff + 2 ** 32) mod 2 ** 32;
         Diff_U    : constant U32 := U32 (Diff_Mod);
         Sign_Ext  : constant U32 :=
           Interfaces.Shift_Right_Arithmetic (Diff_U, 31);
         M_Two_G2  : constant U32 := Sign_Ext and U32 (Two_G2);
         M_One     : constant U32 := Sign_Ext and 1;
      begin
         --  Sign_Ext = -1 iff R0 > Gamma2, else 0.
         pragma Assert (if R0 > ML_DSA_Gamma2 then Sign_Ext = 16#FFFF_FFFF#
                        else Sign_Ext = 0);
         pragma Assert (if R0 > ML_DSA_Gamma2 then M_Two_G2 = U32 (Two_G2)
                        else M_Two_G2 = 0);
         pragma Assert (if R0 > ML_DSA_Gamma2 then M_One = 1 else M_One = 0);
         R0 := R0 - I32 (M_Two_G2);
         R1 := R1 + I32 (M_One);
      end;
      pragma Assert (R0 in -(ML_DSA_Gamma2 - 1) .. ML_DSA_Gamma2);
      pragma Assert (R1 in 0 .. Boundary + 1);
      --  Centring moved (-2*Gamma2, +1) in lockstep: sum is exact.
      pragma Assert (R1 * Two_G2 + R0 = A);

      --  Wraparound: condition is `R1 >= Boundary`, equivalent to
      --  `Boundary - 1 - R1 < 0`. Compute the difference as U32
      --  modular subtraction (Interfaces.Unsigned_32 wraps on
      --  underflow), giving a value with the high bit set iff
      --  R1 >= Boundary.
      declare
         R1_U          : constant U32 := U32 (R1);
         Boundary_M1_U : constant U32 := U32 (Boundary - 1);
         Diff_U        : constant U32 := Boundary_M1_U - R1_U;
         Sign_Ext      : constant U32 :=
           Interfaces.Shift_Right_Arithmetic (Diff_U, 31);
         R1_Cleared    : constant U32 := R1_U and (not Sign_Ext);
         M_One         : constant U32 := Sign_Ext and 1;
      begin
         --  Sign_Ext = -1 iff R1 >= Boundary, else 0.
         pragma Assert (if R1 >= Boundary then Sign_Ext = 16#FFFF_FFFF#
                        else Sign_Ext = 0);
         --  R1_Cleared = 0 iff R1 >= Boundary, else R1.
         pragma Assert (if R1 >= Boundary then R1_Cleared = 0
                        else R1_Cleared = U32 (R1));
         R1 := I32 (R1_Cleared);
         R0 := R0 - I32 (M_One);
      end;

      --  Either no wraparound happened (sum still exact) or R1 was
      --  exactly Boundary (R1 = Boundary + 1 is impossible: it would
      --  force R0 <= -2*Gamma2, outside the centred range) and the
      --  fixup shifted the sum by Boundary * 2*Gamma2 + 1 = Q.
      pragma Assert
        (R1 * Two_G2 + R0 = A or else R1 * Two_G2 + R0 = A - Q);
      pragma Assert ((R1 * Two_G2 + R0) mod Q = A);

      A0 := R0;
      A1 := R1;
   end Decompose;

   function HighBits (A : I32) return I32 is
      A0, A1 : I32;
   begin
      Decompose (A0, A1, A);
      return A1;
   end HighBits;

   ----------------------------------------------------------------------
   --  MakeHint (FIPS 204 §7.6)
   --
   --  Returns 1 iff the low part a0 has rolled across the boundary,
   --  i.e., the high part of (a + something) differs from a1.
   ----------------------------------------------------------------------
   function Make_Hint (A0, A1 : I32) return U8 is
      --  Use unconditional `or` / `and` (not the short-circuit forms) so
      --  every branch is evaluated regardless of input — the hint bit
      --  is observable in the signature anyway, but the timing of the
      --  evaluation should not depend on a0/a1 values.
   begin
      if A0 > ML_DSA_Gamma2
        or A0 < -ML_DSA_Gamma2
        or (A0 = -ML_DSA_Gamma2 and A1 /= 0)
      then
         return 1;
      else
         return 0;
      end if;
   end Make_Hint;

   ----------------------------------------------------------------------
   --  UseHint (FIPS 204 §7.7)
   --
   --  Apply the hint bit to recover the perturbed high part a1.
   ----------------------------------------------------------------------
   function Use_Hint (Hint : U8; A : I32) return I32 is
      A0, A1 : I32;
   begin
      Decompose (A0, A1, A);
      if Hint = 0 then
         return A1;
      end if;

      if ML_DSA_Gamma2 = (Q - 1) / 32 then
         if A0 > 0 then
            return (if A1 = 15 then 0 else A1 + 1);
         else
            return (if A1 = 0 then 15 else A1 - 1);
         end if;
      else
         if A0 > 0 then
            return (if A1 = 43 then 0 else A1 + 1);
         else
            return (if A1 = 0 then 43 else A1 - 1);
         end if;
      end if;
   end Use_Hint;

end ML_DSA.Rounding;
