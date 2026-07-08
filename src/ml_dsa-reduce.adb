with Interfaces;

package body ML_DSA.Reduce is
   pragma SPARK_Mode (On);

   --  Q_Inv = q^{-1} mod 2^32 = 58_728_449. Multiplying a 32-bit value
   --  by Q_Inv (mod 2^32) and then by Q gives the original value back
   --  modulo 2^32 — that is the algebraic identity behind the
   --  Montgomery reduction step below.
   Q_Inv_U : constant U32 := 58_728_449;

   ----------------------------------------------------------------------
   --  Montgomery_Reduce
   --
   --    t   := (A_low * Q_Inv) mod 2^32  (signed-reinterpreted)
   --    R   := (A - t*Q) / 2^32
   --
   --  The output R satisfies R = A * 2^{-32} (mod Q) and lies in
   --  (-Q, Q) for the precondition |A| <= Q*2^31. Type-safety bound
   --  proved here: R in [-Q, Q] (slightly wider than the mathematical
   --  range, in the same style as ml_kem_ada's Montgomery_Reduce).
   ----------------------------------------------------------------------
   function Montgomery_Reduce (A : I64) return I32 is
      --  Low 32 bits of A as unsigned.
      A_Low_U : constant U32 := U32 (A mod 2 ** 32);
      --  Wrapping multiply in U32. Same as casting to I32 and multiplying
      --  in I64 then truncating, as the C reference does, but expressed
      --  with explicit modular U32 arithmetic so SPARK can reason about it.
      T_U     : constant U32 := A_Low_U * Q_Inv_U;
      --  Reinterpret as signed I32: U32 -> I32 with proper sign extension.
      T_S     : constant I32 :=
        (if T_U <= 16#7FFF_FFFF#
         then I32 (T_U)
         else I32 (I64 (T_U) - 2 ** 32));
      Diff    : constant I64 := A - I64 (T_S) * I64 (Q);
      --  |Diff| <= |A| + |T_S * Q| <= Q*2^31 + 2^31 * Q = Q*2^32, so
      --  |Diff / 2^32| <= Q. Ada's I64 / 2^32 truncates toward zero;
      --  the result is in [-Q, Q] (asymmetric due to the input range
      --  precondition |A| in [-(Q*2^31), Q*2^31 - 1]).
      R       : constant I64 := Diff / 2 ** 32;
   begin
      pragma Assert (T_S in I32'Range);
      pragma Assert (I64 (T_S) * I64 (Q) in -(I64 (Q) * 2 ** 31) .. (I64 (Q) * 2 ** 31 - I64 (Q)));
      pragma Assert (Diff in -(I64 (Q) * 2 ** 32 - I64 (Q)) .. I64 (Q) * 2 ** 32 - 1);
      pragma Assert (R in -(I64 (Q) - 1) .. I64 (Q) - 1);
      return I32 (R);
   end Montgomery_Reduce;

   ----------------------------------------------------------------------
   --  Reduce32 (Barrett-style for q = 8 380 417)
   --
   --    t := floor((a + 2^22) / 2^23);
   --    return a - t*Q;
   --
   --  For a in I32'Range the output magnitude is at most 6_291_200
   --  (= 2^22 + 256 * (2^23 - Q)). The dilithium reference comment cites
   --  6_283_008 under the tighter precondition |a| <= 2^31 - 2^22 - 1;
   --  we use 6_283_009 (Reduce32_Bound below) to match libcrux's F*
   --  spec, which assumes well-bounded inputs.
   ----------------------------------------------------------------------
   function Reduce32 (A : I32) return I32 is
      --  Compute (A + 2^22) and floor-divide by 2^23 in I64.
      T_64    : constant I64 := I64 (A) + 2 ** 22;
      T_Trunc : constant I64 := T_64 / 2 ** 23;
      --  Adjust for floor (toward -inf) instead of trunc (toward 0).
      T_Floor : constant I64 :=
        (if T_64 < 0 and then T_64 rem 2 ** 23 /= 0
         then T_Trunc - 1
         else T_Trunc);
      Result  : constant I64 := I64 (A) - T_Floor * I64 (Q);
   begin
      pragma Assert (T_Floor in -256 .. 256);
      pragma Assert (Result in -Reduce32_Bound .. Reduce32_Bound);
      return I32 (Result);
   end Reduce32;

   ----------------------------------------------------------------------
   --  CAddQ — conditional add Q (constant-time via sign-mask).
   --
   --  Reference: dilithium ref `a += (a >> 31) & Q;`
   --  We extract the sign bit of A via the bit-pattern reinterpretation
   --  I32 -> U32 followed by Interfaces.Shift_Right_Arithmetic. That
   --  emits `sar` on x86-64 / `asr` on AArch64 — branchless. The mask
   --  is then AND-ed with Q and added back into A.
   ----------------------------------------------------------------------
   function CAddQ (A : I32) return Coeff_Standard is
      --  Bit-pattern I32 -> U32. The two's-complement encoding makes
      --  this a no-op at the machine level; we express it via I64 to
      --  avoid Constraint_Error on negative I32 input.
      A_Mod : constant I64 := (I64 (A) + 2 ** 32) mod 2 ** 32;
      A_U   : constant U32 := U32 (A_Mod);
      --  Arithmetic shift right by 31: -1 if A negative, 0 if not.
      Sign_Ext : constant U32 :=
        Interfaces.Shift_Right_Arithmetic (A_U, 31);
      MQ : constant U32 := Sign_Ext and U32 (Q);
   begin
      --  MQ is Q when A < 0, else 0. So A + MQ in [0, Q-1].
      pragma Assert (if A < 0 then Sign_Ext = 16#FFFF_FFFF# else Sign_Ext = 0);
      pragma Assert (if A < 0 then MQ = U32 (Q) else MQ = 0);
      return A + I32 (MQ);
   end CAddQ;

end ML_DSA.Reduce;
