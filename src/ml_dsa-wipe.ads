--  Memory wiping for sensitive intermediate data in ML-DSA.
--
--  At the end of each top-level operation (KeyGen / Sign / Verify),
--  any local variable that contained a portion of the secret seed,
--  the unpacked secret-key polynomials (s1, s2, t0), the masking
--  vector y, the response z, the challenge c, or any intermediate
--  derived from those is overwritten with zero before going out of
--  scope. The Wipe procedures below do that.
--
--  The bodies live in a separate compilation unit and the spec
--  carries `Inline => False` so the compiler cannot see the body at
--  the call site and prove the writes dead. With -O2 and no
--  whole-program LTO this gives a robust zeroisation guarantee; if
--  your build uses LTO, add `-fno-builtin-memset` or call
--  `explicit_bzero(3)` instead.
package ML_DSA.Wipe is

   pragma Pure;
   pragma SPARK_Mode;

   procedure Wipe_Byte_Array (X : in out Byte_Array)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range => X (I) = 0);

   procedure Wipe_Polynomial (X : in out Polynomial)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range => X (I) = 0);

   procedure Wipe_Poly_Vector_K (X : in out Poly_Vector_K)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range =>
                     (for all J in X (I)'Range => X (I) (J) = 0));

   procedure Wipe_Poly_Vector_L (X : in out Poly_Vector_L)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range =>
                     (for all J in X (I)'Range => X (I) (J) = 0));

   procedure Wipe_Poly_Matrix_KL (X : in out Poly_Matrix_KL)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range =>
                     (for all J in X (I)'Range =>
                        (for all K in X (I) (J)'Range =>
                           X (I) (J) (K) = 0)));

end ML_DSA.Wipe;
