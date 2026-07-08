with ML_DSA.Rounding;

--  Polynomial vector / K-by-L matrix operations for ML-DSA.
--
--  ML-DSA matrix A is K rows by L columns, both depending on the
--  parameter set:
--    ML-DSA-44 : K=4, L=4
--    ML-DSA-65 : K=6, L=5
--    ML-DSA-87 : K=8, L=7
--
--  Vectors of length L are used for s1 / mask y / response z, and
--  vectors of length K for s2 / commitment t / w / hints h.
package ML_DSA.PolyVec is

   pragma Pure;
   pragma SPARK_Mode;

   ----------------------------------------------------------------------
   --  L-vector operations (length ML_DSA_L)
   ----------------------------------------------------------------------

   procedure PolyVecL_Reduce (V : in out Poly_Vector_L)
     with Always_Terminates => True,
          Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -Reduce32_Bound .. Reduce32_Bound));

   procedure PolyVecL_Add (R : in out Poly_Vector_L; B : Poly_Vector_L)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        I64 (R (I) (J)) + I64 (B (I) (J))
                          in I64 (I32'First) .. I64 (I32'Last))),
          Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) = R'Old (I) (J) + B (I) (J)));

   procedure PolyVecL_NTT (V : in out Poly_Vector_L)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -Reduce32_Bound .. Reduce32_Bound)),
          Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -(Reduce32_Bound + 8 * Q)
                                  .. (Reduce32_Bound + 8 * Q)));

   procedure PolyVecL_InvNTT_ToMont (V : in out Poly_Vector_L)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -Reduce32_Bound .. Reduce32_Bound)),
          Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -(Q - 1) .. (Q - 1)));

   --  Pointwise multiply-accumulate: w(j) = sum_{i=0}^{L-1} u_i(j) * v_i(j),
   --  reduced via Montgomery_Reduce per coefficient. Output bounded by
   --  L * (Q-1) in absolute value (sum of L Montgomery_Reduce outputs).
   procedure PolyVecL_Pointwise_Acc_Montgomery
     (W : out Polynomial;
      U : Poly_Vector_L;
      V : Poly_Vector_L)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        U (I) (J) in -(Reduce32_Bound + 8 * Q)
                                  .. (Reduce32_Bound + 8 * Q)))
                  and then (for all I in 0 .. ML_DSA_L - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 V (I) (J) in -(Reduce32_Bound + 8 * Q)
                                           .. (Reduce32_Bound + 8 * Q))),
          Post => (for all I in 0 .. N - 1 =>
                     W (I) in -(ML_DSA_L * (Q - 1)) .. (ML_DSA_L * (Q - 1)));

   ----------------------------------------------------------------------
   --  K-vector operations (length ML_DSA_K)
   ----------------------------------------------------------------------

   procedure PolyVecK_Reduce (V : in out Poly_Vector_K)
     with Always_Terminates => True,
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -Reduce32_Bound .. Reduce32_Bound));

   procedure PolyVecK_CAddQ (V : in out Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -(Q - 1) .. (Q - 1))),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in 0 .. Q - 1));

   procedure PolyVecK_Add (R : in out Poly_Vector_K; B : Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        I64 (R (I) (J)) + I64 (B (I) (J))
                          in I64 (I32'First) .. I64 (I32'Last))),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) = R'Old (I) (J) + B (I) (J)));

   procedure PolyVecK_Sub (R : in out Poly_Vector_K; B : Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        I64 (R (I) (J)) - I64 (B (I) (J))
                          in I64 (I32'First) .. I64 (I32'Last))),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) = R'Old (I) (J) - B (I) (J)));

   procedure PolyVecK_NTT (V : in out Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -Reduce32_Bound .. Reduce32_Bound)),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -(Reduce32_Bound + 8 * Q)
                                  .. (Reduce32_Bound + 8 * Q)));

   procedure PolyVecK_InvNTT_ToMont (V : in out Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -Reduce32_Bound .. Reduce32_Bound)),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in -(Q - 1) .. (Q - 1)));

   --  ShiftL each coefficient by D bits.
   procedure PolyVecK_ShiftL (V : in out Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 => V (I) (J) in 0 .. 1023)),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        V (I) (J) in 0 .. 1023 * (2 ** D)));

   --  Whole-vector ChkNorm: returns True if any coefficient violates.
   --  All call sites must Reduce first so the centered |coeff| fits.
   function PolyVecL_ChkNorm (V : Poly_Vector_L; B : I32) return Boolean
     with Pre  => B in 1 .. (Q - 1) / 8
                  and then (for all I in 0 .. ML_DSA_L - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 V (I) (J) in -Reduce32_Bound .. Reduce32_Bound)),
          Post => (if not PolyVecL_ChkNorm'Result
                   then (for all I in 0 .. ML_DSA_L - 1 =>
                           (for all J in 0 .. N - 1 =>
                              V (I) (J) in -(B - 1) .. (B - 1))));

   function PolyVecK_ChkNorm (V : Poly_Vector_K; B : I32) return Boolean
     with Pre  => B in 1 .. (Q - 1) / 8
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 V (I) (J) in -Reduce32_Bound .. Reduce32_Bound)),
          Post => (if not PolyVecK_ChkNorm'Result
                   then (for all I in 0 .. ML_DSA_K - 1 =>
                           (for all J in 0 .. N - 1 =>
                              V (I) (J) in -(B - 1) .. (B - 1))));

   ----------------------------------------------------------------------
   --  Matrix-vector multiply: t = A * v where A is K-by-L and v is
   --  L-vector, all in NTT domain.
   ----------------------------------------------------------------------
   procedure PolyVec_Matrix_Pointwise_Montgomery
     (T   : out Poly_Vector_K;
      A   : Poly_Matrix_KL;
      V   : Poly_Vector_L)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. ML_DSA_L - 1 =>
                        (for all M in 0 .. N - 1 =>
                           A (I) (J) (M) in -(Reduce32_Bound + 8 * Q)
                                         .. (Reduce32_Bound + 8 * Q))))
                  and then (for all I in 0 .. ML_DSA_L - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 V (I) (J) in -(Reduce32_Bound + 8 * Q)
                                           .. (Reduce32_Bound + 8 * Q))),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        T (I) (J) in -(ML_DSA_L * (Q - 1))
                                  .. (ML_DSA_L * (Q - 1))));

   ----------------------------------------------------------------------
   --  Per-vector lifts of Power2Round / Decompose / Make_Hint / Use_Hint.
   ----------------------------------------------------------------------

   procedure PolyVecK_Power2Round
     (A1 : out Poly_Vector_K;
      A0 : out Poly_Vector_K;
      A  : Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 => A (I) (J) in 0 .. Q - 1)),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        A1 (I) (J) in 0 .. Rounding.Power2Round_High_Max
                        and then A0 (I) (J) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1)));

   procedure PolyVecK_Decompose
     (A1 : out Poly_Vector_K;
      A0 : out Poly_Vector_K;
      A  : Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 => A (I) (J) in 0 .. Q - 1)),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        A1 (I) (J) in 0 .. Rounding.Decompose_High_Max
                        and then A0 (I) (J) in -ML_DSA_Gamma2 .. ML_DSA_Gamma2));

   --  Per-vector MakeHint, returning the total hint count across the K
   --  polynomials.
   procedure PolyVecK_Make_Hint
     (H     : out Poly_Vector_K;
      Count : out Natural;
      A0    : Poly_Vector_K;
      A1    : Poly_Vector_K)
     with Always_Terminates => True,
          Post => Count <= ML_DSA_K * N
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 H (I) (J) in 0 .. 1));

   procedure PolyVecK_Use_Hint
     (R : out Poly_Vector_K;
      A : Poly_Vector_K;
      H : Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        A (I) (J) in 0 .. Q - 1
                        and then H (I) (J) in 0 .. 1)),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) in 0 .. Rounding.Decompose_High_Max));

end ML_DSA.PolyVec;
