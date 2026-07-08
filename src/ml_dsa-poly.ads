with ML_DSA.Rounding;

--  Per-polynomial operations: add/sub/reduce/caddq/shiftl/chknorm
--  and the Power2Round / Decompose / MakeHint / UseHint lifts.
package ML_DSA.Poly is

   pragma Pure;
   pragma SPARK_Mode;

   --  Reduce all coefficients via Reduce32. Output bounded by
   --  Reduce32_Bound in absolute value.
   procedure Poly_Reduce (R : in out Polynomial)
     with Always_Terminates => True,
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -Reduce32_Bound .. Reduce32_Bound);

   --  Add Q to negative coefficients to produce the standard
   --  representation in [0, Q-1].
   procedure Poly_CAddQ (R : in out Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 => R (I) in -(Q - 1) .. (Q - 1)),
          Post => (for all I in 0 .. N - 1 => R (I) in 0 .. Q - 1);

   --  Pointwise sum. Caller must ensure no I32 overflow.
   procedure Poly_Add (R : in out Polynomial; B : Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 =>
                     I64 (R (I)) + I64 (B (I)) in
                       I64 (I32'First) .. I64 (I32'Last)),
          Post => (for all I in 0 .. N - 1 => R (I) = R'Old (I) + B (I));

   --  Pointwise difference. Caller must ensure no I32 overflow.
   procedure Poly_Sub (R : in out Polynomial; B : Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 =>
                     I64 (R (I)) - I64 (B (I)) in
                       I64 (I32'First) .. I64 (I32'Last)),
          Post => (for all I in 0 .. N - 1 => R (I) = R'Old (I) - B (I));

   --  Shift each coefficient left by D bits. Typical input is the
   --  output of t1 unpack, with coefficients in [0, 1023].
   procedure Poly_ShiftL (R : in out Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 => R (I) in 0 .. 1023),
          Post => (for all I in 0 .. N - 1 => R (I) in 0 .. 1023 * (2 ** D));

   --  Infinity-norm check. Returns True iff some coefficient of A has
   --  absolute value >= B. (Matches the dilithium reference convention
   --  where a "true" return aborts signing.)
   --
   --  Precondition restricts inputs to the Reduce32 output window so
   --  the centering negation -A(I) cannot overflow I32; every call
   --  site reduces via Poly_Reduce / PolyVecK_Reduce / PolyVecL_Reduce
   --  before this check, matching the dilithium reference's required
   --  precondition.
   function Poly_ChkNorm (A : Polynomial; B : I32) return Boolean
     with Pre  => B in 1 .. (Q - 1) / 8
                  and then (for all I in 0 .. N - 1 =>
                              A (I) in -Reduce32_Bound .. Reduce32_Bound),
          Post => (if not Poly_ChkNorm'Result
                   then (for all I in 0 .. N - 1 =>
                           A (I) in -(B - 1) .. (B - 1)));

   --  Lift Power2Round to a whole polynomial.
   procedure Poly_Power2Round (A0, A1 : out Polynomial; A : Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. Q - 1),
          Post => (for all I in 0 .. N - 1 =>
                     A1 (I) in 0 .. Rounding.Power2Round_High_Max
                     and then A0 (I) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1));

   --  Lift Decompose.
   procedure Poly_Decompose (A0, A1 : out Polynomial; A : Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. Q - 1),
          Post => (for all I in 0 .. N - 1 =>
                     A1 (I) in 0 .. Rounding.Decompose_High_Max
                     and then A0 (I) in -ML_DSA_Gamma2 .. ML_DSA_Gamma2);

   --  Lift MakeHint, returning the total number of hint bits set.
   procedure Poly_Make_Hint
     (H     : out Polynomial;
      Count : out Natural;
      A0    : Polynomial;
      A1    : Polynomial)
     with Always_Terminates => True,
          Post => Count <= N
                  and then (for all I in 0 .. N - 1 => H (I) in 0 .. 1);

   --  Lift UseHint.
   procedure Poly_Use_Hint (R : out Polynomial; A : Polynomial; H : Polynomial)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. N - 1 =>
                     A (I) in 0 .. Q - 1
                     and then H (I) in 0 .. 1),
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in 0 .. Rounding.Decompose_High_Max);

end ML_DSA.Poly;
