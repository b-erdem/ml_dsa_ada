package body ML_DSA.Wipe is

   pragma SPARK_Mode (On);

   procedure Wipe_Byte_Array (X : in out Byte_Array) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all J in X'First .. I - 1 => X (J) = 0);
         X (I) := 0;
      end loop;
   end Wipe_Byte_Array;

   procedure Wipe_Polynomial (X : in out Polynomial) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all J in X'First .. I - 1 => X (J) = 0);
         X (I) := 0;
      end loop;
   end Wipe_Polynomial;

   procedure Wipe_Poly_Vector_K (X : in out Poly_Vector_K) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all II in X'First .. I - 1 =>
              (for all J in X (II)'Range => X (II) (J) = 0));
         Wipe_Polynomial (X (I));
      end loop;
   end Wipe_Poly_Vector_K;

   procedure Wipe_Poly_Vector_L (X : in out Poly_Vector_L) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all II in X'First .. I - 1 =>
              (for all J in X (II)'Range => X (II) (J) = 0));
         Wipe_Polynomial (X (I));
      end loop;
   end Wipe_Poly_Vector_L;

   procedure Wipe_Poly_Matrix_KL (X : in out Poly_Matrix_KL) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all II in X'First .. I - 1 =>
              (for all J in X (II)'Range =>
                 (for all K in X (II) (J)'Range => X (II) (J) (K) = 0)));
         Wipe_Poly_Vector_L (X (I));
      end loop;
   end Wipe_Poly_Matrix_KL;

end ML_DSA.Wipe;
