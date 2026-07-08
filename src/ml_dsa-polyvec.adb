with ML_DSA.NTT;
with ML_DSA.Poly;

package body ML_DSA.PolyVec is
   pragma SPARK_Mode (On);

   ----------------------------------------------------------------------
   --  L-vector
   ----------------------------------------------------------------------

   procedure PolyVecL_Reduce (V : in out Poly_Vector_L) is
   begin
      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -Reduce32_Bound .. Reduce32_Bound));
         Poly.Poly_Reduce (V (I));
      end loop;
   end PolyVecL_Reduce;

   procedure PolyVecL_Add (R : in out Poly_Vector_L; B : Poly_Vector_L) is
   begin
      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) = R'Loop_Entry (II) (J) + B (II) (J)));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_L - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) = R'Loop_Entry (II) (J)));
         Poly.Poly_Add (R (I), B (I));
      end loop;
   end PolyVecL_Add;

   procedure PolyVecL_NTT (V : in out Poly_Vector_L) is
   begin
      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -(Reduce32_Bound + 8 * Q)
                            .. (Reduce32_Bound + 8 * Q)));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_L - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -Reduce32_Bound .. Reduce32_Bound));
         NTT.NTT (V (I));
      end loop;
   end PolyVecL_NTT;

   procedure PolyVecL_InvNTT_ToMont (V : in out Poly_Vector_L) is
   begin
      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => V (II) (J) in -(Q - 1) .. (Q - 1)));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_L - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -Reduce32_Bound .. Reduce32_Bound));
         NTT.InvNTT_ToMont (V (I));
      end loop;
   end PolyVecL_InvNTT_ToMont;

   procedure PolyVecL_Pointwise_Acc_Montgomery
     (W : out Polynomial;
      U : Poly_Vector_L;
      V : Poly_Vector_L)
   is
   begin
      --  Initialize with the first product.
      NTT.Pointwise_Montgomery (W, U (0), V (0));
      --  W now bounded by Q-1 in absolute value.
      for I in 1 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. N - 1 =>
              W (J) in -(I32 (I) * I32 (Q - 1)) .. I32 (I) * I32 (Q - 1));
         declare
            T : Polynomial;
         begin
            NTT.Pointwise_Montgomery (T, U (I), V (I));
            --  T bounded by Q-1; W bounded by I*(Q-1); sum by (I+1)*(Q-1).
            for J in 0 .. N - 1 loop
               pragma Loop_Invariant
                 (for all K in 0 .. J - 1 =>
                    W (K) in -(I32 (I + 1) * I32 (Q - 1))
                          .. I32 (I + 1) * I32 (Q - 1));
               pragma Loop_Invariant
                 (for all K in J .. N - 1 =>
                    W (K) in -(I32 (I) * I32 (Q - 1))
                          .. I32 (I) * I32 (Q - 1));
               --  W(J) + T(J): I*(Q-1) + (Q-1) = (I+1)*(Q-1) <= L*(Q-1).
               --  L * (Q-1) = 7 * 8_380_416 = 58_662_912 < I32'Last.
               W (J) := W (J) + T (J);
            end loop;
         end;
      end loop;
   end PolyVecL_Pointwise_Acc_Montgomery;

   ----------------------------------------------------------------------
   --  K-vector
   ----------------------------------------------------------------------

   procedure PolyVecK_Reduce (V : in out Poly_Vector_K) is
   begin
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -Reduce32_Bound .. Reduce32_Bound));
         Poly.Poly_Reduce (V (I));
      end loop;
   end PolyVecK_Reduce;

   procedure PolyVecK_CAddQ (V : in out Poly_Vector_K) is
   begin
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => V (II) (J) in 0 .. Q - 1));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -(Q - 1) .. (Q - 1)));
         Poly.Poly_CAddQ (V (I));
      end loop;
   end PolyVecK_CAddQ;

   procedure PolyVecK_Add (R : in out Poly_Vector_K; B : Poly_Vector_K) is
   begin
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) = R'Loop_Entry (II) (J) + B (II) (J)));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) = R'Loop_Entry (II) (J)));
         Poly.Poly_Add (R (I), B (I));
      end loop;
   end PolyVecK_Add;

   procedure PolyVecK_Sub (R : in out Poly_Vector_K; B : Poly_Vector_K) is
   begin
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) = R'Loop_Entry (II) (J) - B (II) (J)));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) = R'Loop_Entry (II) (J)));
         Poly.Poly_Sub (R (I), B (I));
      end loop;
   end PolyVecK_Sub;

   procedure PolyVecK_NTT (V : in out Poly_Vector_K) is
   begin
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -(Reduce32_Bound + 8 * Q)
                            .. (Reduce32_Bound + 8 * Q)));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -Reduce32_Bound .. Reduce32_Bound));
         NTT.NTT (V (I));
      end loop;
   end PolyVecK_NTT;

   procedure PolyVecK_InvNTT_ToMont (V : in out Poly_Vector_K) is
   begin
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => V (II) (J) in -(Q - 1) .. (Q - 1)));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -Reduce32_Bound .. Reduce32_Bound));
         NTT.InvNTT_ToMont (V (I));
      end loop;
   end PolyVecK_InvNTT_ToMont;

   procedure PolyVecK_ShiftL (V : in out Poly_Vector_K) is
   begin
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in 0 .. 1023 * (2 ** D)));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_K - 1 =>
              (for all J in 0 .. N - 1 => V (II) (J) in 0 .. 1023));
         Poly.Poly_ShiftL (V (I));
      end loop;
   end PolyVecK_ShiftL;

   function PolyVecL_ChkNorm (V : Poly_Vector_L; B : I32) return Boolean is
   begin
      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -(B - 1) .. (B - 1)));
         if Poly.Poly_ChkNorm (V (I), B) then
            return True;
         end if;
      end loop;
      return False;
   end PolyVecL_ChkNorm;

   function PolyVecK_ChkNorm (V : Poly_Vector_K; B : I32) return Boolean is
   begin
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 V (II) (J) in -(B - 1) .. (B - 1)));
         if Poly.Poly_ChkNorm (V (I), B) then
            return True;
         end if;
      end loop;
      return False;
   end PolyVecK_ChkNorm;

   ----------------------------------------------------------------------
   --  Matrix-vector multiply.
   ----------------------------------------------------------------------
   procedure PolyVec_Matrix_Pointwise_Montgomery
     (T : out Poly_Vector_K;
      A : Poly_Matrix_KL;
      V : Poly_Vector_L)
   is
   begin
      T := [others => [others => 0]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 T (II) (J) in -(ML_DSA_L * (Q - 1)) .. (ML_DSA_L * (Q - 1))));
         pragma Loop_Invariant
           (for all II in I .. ML_DSA_K - 1 =>
              (for all J in 0 .. N - 1 => T (II) (J) = 0));
         PolyVecL_Pointwise_Acc_Montgomery (T (I), A (I), V);
      end loop;
   end PolyVec_Matrix_Pointwise_Montgomery;

   ----------------------------------------------------------------------
   --  Lifts of Power2Round / Decompose / Make_Hint / Use_Hint.
   ----------------------------------------------------------------------

   procedure PolyVecK_Power2Round
     (A1 : out Poly_Vector_K;
      A0 : out Poly_Vector_K;
      A  : Poly_Vector_K)
   is
   begin
      A0 := [others => [others => 0]];
      A1 := [others => [others => 0]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 A1 (II) (J) in 0 .. Rounding.Power2Round_High_Max
                 and then A0 (II) (J) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1)));
         Poly.Poly_Power2Round (A0 (I), A1 (I), A (I));
      end loop;
   end PolyVecK_Power2Round;

   procedure PolyVecK_Decompose
     (A1 : out Poly_Vector_K;
      A0 : out Poly_Vector_K;
      A  : Poly_Vector_K)
   is
   begin
      A0 := [others => [others => 0]];
      A1 := [others => [others => 0]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 A1 (II) (J) in 0 .. Rounding.Decompose_High_Max
                 and then A0 (II) (J) in -ML_DSA_Gamma2 .. ML_DSA_Gamma2));
         Poly.Poly_Decompose (A0 (I), A1 (I), A (I));
      end loop;
   end PolyVecK_Decompose;

   procedure PolyVecK_Make_Hint
     (H     : out Poly_Vector_K;
      Count : out Natural;
      A0    : Poly_Vector_K;
      A1    : Poly_Vector_K)
   is
      Total : Natural := 0;
      C     : Natural;
   begin
      H := [others => [others => 0]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant (Total <= I * N);
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => H (II) (J) in 0 .. 1));
         Poly.Poly_Make_Hint (H (I), C, A0 (I), A1 (I));
         pragma Assert (C <= N);
         Total := Total + C;
      end loop;
      Count := Total;
   end PolyVecK_Make_Hint;

   procedure PolyVecK_Use_Hint
     (R : out Poly_Vector_K;
      A : Poly_Vector_K;
      H : Poly_Vector_K)
   is
   begin
      R := [others => [others => 0]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) in 0 .. Rounding.Decompose_High_Max));
         Poly.Poly_Use_Hint (R (I), A (I), H (I));
      end loop;
   end PolyVecK_Use_Hint;

end ML_DSA.PolyVec;
