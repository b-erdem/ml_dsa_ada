with ML_DSA.Rounding;

--  Bit packing / unpacking primitives for ML-DSA.
--
--  Per-polynomial:
--    polyt1 — 10 bits/coeff (320 bytes/poly)
--    polyt0 — 13 bits/coeff (416 bytes/poly)
--    polyeta — 3 or 4 bits/coeff (96 or 128 bytes/poly)
--    polyz — 18 or 20 bits/coeff (576 or 640 bytes/poly)
--    polyw1 — 6 or 4 bits/coeff (192 or 128 bytes/poly)
--
--  Top-level:
--    Pack_PK / Unpack_PK
--    Pack_SK / Unpack_SK
--    Pack_Sig / Unpack_Sig (with hint encoding)
package ML_DSA.Packing is

   pragma Pure;
   pragma SPARK_Mode;

   ----------------------------------------------------------------------
   --  Per-polynomial pack/unpack
   ----------------------------------------------------------------------

   procedure PolyT1_Pack
     (R : out Byte_Array; A : Polynomial)
     with Always_Terminates => True,
          Pre  => R'First = 0
                  and then R'Length = Poly_T1_Packed_Bytes
                  and then (for all I in 0 .. N - 1 => A (I) in 0 .. 1023);

   procedure PolyT1_Unpack
     (R : out Polynomial; A : Byte_Array)
     with Always_Terminates => True,
          Pre  => A'First = 0
                  and then A'Length = Poly_T1_Packed_Bytes,
          Post => (for all I in 0 .. N - 1 => R (I) in 0 .. 1023);

   procedure PolyT0_Pack
     (R : out Byte_Array; A : Polynomial)
     with Always_Terminates => True,
          Pre  => R'First = 0
                  and then R'Length = Poly_T0_Packed_Bytes
                  and then (for all I in 0 .. N - 1 =>
                              A (I) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1));

   procedure PolyT0_Unpack
     (R : out Polynomial; A : Byte_Array)
     with Always_Terminates => True,
          Pre  => A'First = 0
                  and then A'Length = Poly_T0_Packed_Bytes,
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1));

   procedure PolyEta_Pack
     (R : out Byte_Array; A : Polynomial)
     with Always_Terminates => True,
          Pre  => R'First = 0
                  and then R'Length = Poly_Eta_Packed_Bytes
                  and then (for all I in 0 .. N - 1 =>
                              A (I) in -ML_DSA_Eta .. ML_DSA_Eta);

   procedure PolyEta_Unpack
     (R : out Polynomial; A : Byte_Array)
     with Always_Terminates => True,
          Pre  => A'First = 0
                  and then A'Length = Poly_Eta_Packed_Bytes,
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -ML_DSA_Eta .. ML_DSA_Eta);

   procedure PolyZ_Pack
     (R : out Byte_Array; A : Polynomial)
     with Always_Terminates => True,
          Pre  => R'First = 0
                  and then R'Length = Poly_Z_Packed_Bytes
                  and then (for all I in 0 .. N - 1 =>
                              A (I) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1);

   procedure PolyZ_Unpack
     (R : out Polynomial; A : Byte_Array)
     with Always_Terminates => True,
          Pre  => A'First = 0
                  and then A'Length = Poly_Z_Packed_Bytes,
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1);

   procedure PolyW1_Pack
     (R : out Byte_Array; A : Polynomial)
     with Always_Terminates => True,
          Pre  => R'First = 0
                  and then R'Length = Poly_W1_Packed_Bytes
                  and then (for all I in 0 .. N - 1 =>
                              A (I) in 0 .. Rounding.Decompose_High_Max);

   ----------------------------------------------------------------------
   --  Top-level pack/unpack
   ----------------------------------------------------------------------

   procedure Pack_PK
     (PK  : out Byte_Array;
      Rho : Byte_Array_32;
      T1  : Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => PK'First = 0
                  and then PK'Length = ML_DSA.PK_Bytes
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 => T1 (I) (J) in 0 .. 1023));

   procedure Unpack_PK
     (Rho : out Byte_Array_32;
      T1  : out Poly_Vector_K;
      PK  : Byte_Array)
     with Always_Terminates => True,
          Pre  => PK'First = 0
                  and then PK'Length = ML_DSA.PK_Bytes,
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 => T1 (I) (J) in 0 .. 1023));

   procedure Pack_SK
     (SK    : out Byte_Array;
      Rho   : Byte_Array_32;
      Key   : Byte_Array_32;
      Tr    : Byte_Array_64;
      S1    : Poly_Vector_L;
      S2    : Poly_Vector_K;
      T0    : Poly_Vector_K)
     with Always_Terminates => True,
          Pre  => SK'First = 0
                  and then SK'Length = ML_DSA.SK_Bytes
                  and then (for all I in 0 .. ML_DSA_L - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 S1 (I) (J) in -ML_DSA_Eta .. ML_DSA_Eta))
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 S2 (I) (J) in -ML_DSA_Eta .. ML_DSA_Eta))
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 T0 (I) (J) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1)));

   procedure Unpack_SK
     (Rho : out Byte_Array_32;
      Key : out Byte_Array_32;
      Tr  : out Byte_Array_64;
      S1  : out Poly_Vector_L;
      S2  : out Poly_Vector_K;
      T0  : out Poly_Vector_K;
      SK  : Byte_Array)
     with Always_Terminates => True,
          Pre  => SK'First = 0
                  and then SK'Length = ML_DSA.SK_Bytes,
          Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        S1 (I) (J) in -ML_DSA_Eta .. ML_DSA_Eta))
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 S2 (I) (J) in -ML_DSA_Eta .. ML_DSA_Eta))
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 T0 (I) (J) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1)));

   --  Pack a signature. Hint_Count must equal the total number of 1-bits
   --  in H and must be at most Omega — the signing rejection loop
   --  guarantees both conditions before reaching this packing step.
   procedure Pack_Sig
     (Sig        : out Byte_Array;
      C_Tilde    : Byte_Array;
      Z          : Poly_Vector_L;
      H          : Poly_Vector_K;
      Hint_Count : Natural)
     with Always_Terminates => True,
          Pre  => Sig'First = 0
                  and then Sig'Length = ML_DSA.Sig_Bytes
                  and then C_Tilde'First = 0
                  and then C_Tilde'Length = ML_DSA.C_Tilde_Bytes
                  and then Hint_Count <= ML_DSA_Omega
                  and then (for all I in 0 .. ML_DSA_L - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 Z (I) (J) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1))
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 H (I) (J) in 0 .. 1));

   --  Unpack signature. Returns Ok = False if the hint encoding is
   --  malformed (out of range / non-monotonic / wrong total).
   procedure Unpack_Sig
     (C_Tilde : out Byte_Array;
      Z       : out Poly_Vector_L;
      H       : out Poly_Vector_K;
      Ok      : out Boolean;
      Sig     : Byte_Array)
     with Always_Terminates => True,
          Pre  => Sig'First = 0
                  and then Sig'Length = ML_DSA.Sig_Bytes
                  and then C_Tilde'First = 0
                  and then C_Tilde'Length = ML_DSA.C_Tilde_Bytes,
          Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        Z (I) (J) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1))
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 H (I) (J) in 0 .. 1));

end ML_DSA.Packing;
