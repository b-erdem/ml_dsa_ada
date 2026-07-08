with ML_DSA.Reduce;

package body ML_DSA.Poly is
   pragma SPARK_Mode (On);

   procedure Poly_Reduce (R : in out Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              R (J) in -Reduce32_Bound .. Reduce32_Bound);
         R (I) := Reduce.Reduce32 (R (I));
      end loop;
   end Poly_Reduce;

   procedure Poly_CAddQ (R : in out Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => R (J) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all J in I .. N - 1 => R (J) = R'Loop_Entry (J));
         R (I) := Reduce.CAddQ (R (I));
      end loop;
   end Poly_CAddQ;

   procedure Poly_Add (R : in out Polynomial; B : Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              R (K) = R'Loop_Entry (K) + B (K));
         pragma Loop_Invariant
           (for all K in I .. N - 1 => R (K) = R'Loop_Entry (K));
         R (I) := R (I) + B (I);
      end loop;
   end Poly_Add;

   procedure Poly_Sub (R : in out Polynomial; B : Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              R (K) = R'Loop_Entry (K) - B (K));
         pragma Loop_Invariant
           (for all K in I .. N - 1 => R (K) = R'Loop_Entry (K));
         R (I) := R (I) - B (I);
      end loop;
   end Poly_Sub;

   procedure Poly_ShiftL (R : in out Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => R (J) in 0 .. 1023 * (2 ** D));
         pragma Loop_Invariant
           (for all J in I .. N - 1 => R (J) = R'Loop_Entry (J));
         pragma Loop_Invariant
           (for all J in I .. N - 1 => R (J) in 0 .. 1023);
         --  R(I) * 2^D fits in I32: 1023 * 8192 = 8_380_416 < 2^31.
         R (I) := R (I) * (2 ** D);
      end loop;
   end Poly_ShiftL;

   ----------------------------------------------------------------------
   --  Infinity norm check. Returns True iff some coefficient has
   --  centered absolute value >= B (i.e., the polynomial fails the
   --  norm bound).
   --
   --  The dilithium reference uses the bit-trick
   --      t = a >> 31;          // sign mask (-1 or 0)
   --      t = a - (t & 2*a);    // |a|
   --  which requires |a| <= I32'Last / 2 to avoid overflow in 2*a.
   --  We require B <= (Q-1)/8 so the caller has reduced the input;
   --  in practice the input here is the output of Reduce32.
   ----------------------------------------------------------------------
   function Poly_ChkNorm (A : Polynomial; B : I32) return Boolean is
      --  Compute |A(I)| via Ada's `abs` operator. The precondition
      --  `|A(I)| <= Reduce32_Bound` guarantees |A(I)| < I32'Last so
      --  `abs` cannot overflow.
      --
      --  GNAT 14+ at -O2 typically emits `abs` for signed I32 as
      --  `mov + sar 31 + xor + sub` (the standard branchless idiom)
      --  on x86-64 and `cmp + cneg` on AArch64. Verified by
      --  scripts/ct_disasm_check.sh.
      --
      --  Boolean `Result` is accumulated unconditionally (Ada's `or`
      --  is not short-circuit), so the iteration count is independent
      --  of input data.
      Abs_C  : I32;
      Result : Boolean := False;
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (if not Result
            then (for all J in 0 .. I - 1 => A (J) in -(B - 1) .. (B - 1)));

         Abs_C := abs A (I);
         pragma Assert (Abs_C = abs A (I));

         Result := Result or Abs_C >= B;
      end loop;
      return Result;
   end Poly_ChkNorm;

   procedure Poly_Power2Round (A0, A1 : out Polynomial; A : Polynomial) is
   begin
      A0 := [others => 0];
      A1 := [others => 0];
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              A1 (J) in 0 .. Rounding.Power2Round_High_Max
              and then A0 (J) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1));
         declare
            T0, T1 : I32;
         begin
            Rounding.Power2Round (T0, T1, A (I));
            A0 (I) := T0;
            A1 (I) := T1;
         end;
      end loop;
   end Poly_Power2Round;

   procedure Poly_Decompose (A0, A1 : out Polynomial; A : Polynomial) is
   begin
      A0 := [others => 0];
      A1 := [others => 0];
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              A1 (J) in 0 .. Rounding.Decompose_High_Max
              and then A0 (J) in -ML_DSA_Gamma2 .. ML_DSA_Gamma2);
         declare
            T0, T1 : I32;
         begin
            Rounding.Decompose (T0, T1, A (I));
            A0 (I) := T0;
            A1 (I) := T1;
         end;
      end loop;
   end Poly_Decompose;

   procedure Poly_Make_Hint
     (H     : out Polynomial;
      Count : out Natural;
      A0    : Polynomial;
      A1    : Polynomial)
   is
      Hint : U8;
      C    : Natural := 0;
   begin
      H := [others => 0];
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant (C <= I);
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => H (J) in 0 .. 1);
         pragma Loop_Invariant
           (for all J in I .. N - 1 => H (J) = 0);
         Hint := Rounding.Make_Hint (A0 (I), A1 (I));
         H (I) := I32 (Hint);
         if Hint = 1 then
            C := C + 1;
         end if;
      end loop;
      Count := C;
   end Poly_Make_Hint;

   procedure Poly_Use_Hint (R : out Polynomial; A : Polynomial; H : Polynomial) is
   begin
      R := [others => 0];
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => R (J) in 0 .. Rounding.Decompose_High_Max);
         R (I) := Rounding.Use_Hint (U8 (H (I)), A (I));
      end loop;
   end Poly_Use_Hint;

end ML_DSA.Poly;
