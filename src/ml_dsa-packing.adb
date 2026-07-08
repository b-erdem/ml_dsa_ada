with Interfaces;

package body ML_DSA.Packing is
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
   --  PolyT1 — 10 bits per coefficient
   ----------------------------------------------------------------------

   procedure PolyT1_Pack
     (R : out Byte_Array; A : Polynomial)
   is
      C0, C1, C2, C3 : U32;
   begin
      R := [others => 0];
      for I in 0 .. N / 4 - 1 loop
         pragma Loop_Invariant (5 * I <= R'Last + 1);
         C0 := U32 (A (4 * I));
         C1 := U32 (A (4 * I + 1));
         C2 := U32 (A (4 * I + 2));
         C3 := U32 (A (4 * I + 3));

         R (5 * I)     := U8 (C0 and 16#FF#);
         R (5 * I + 1) := U8 ((Interfaces.Shift_Right (C0, 8)
                               or Interfaces.Shift_Left (C1, 2)) and 16#FF#);
         R (5 * I + 2) := U8 ((Interfaces.Shift_Right (C1, 6)
                               or Interfaces.Shift_Left (C2, 4)) and 16#FF#);
         R (5 * I + 3) := U8 ((Interfaces.Shift_Right (C2, 4)
                               or Interfaces.Shift_Left (C3, 6)) and 16#FF#);
         R (5 * I + 4) := U8 (Interfaces.Shift_Right (C3, 2) and 16#FF#);
      end loop;
   end PolyT1_Pack;

   procedure PolyT1_Unpack
     (R : out Polynomial; A : Byte_Array)
   is
      V : U32;
   begin
      R := [others => 0];
      for I in 0 .. N / 4 - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. 4 * I - 1 => R (K) in 0 .. 1023);
         pragma Loop_Invariant
           (for all K in 4 * I .. N - 1 => R (K) = 0);

         V := U32 (A (5 * I))
              or Interfaces.Shift_Left (U32 (A (5 * I + 1)), 8);
         R (4 * I)     := I32 (V and 16#3FF#);

         V := Interfaces.Shift_Right (U32 (A (5 * I + 1)), 2)
              or Interfaces.Shift_Left (U32 (A (5 * I + 2)), 6);
         R (4 * I + 1) := I32 (V and 16#3FF#);

         V := Interfaces.Shift_Right (U32 (A (5 * I + 2)), 4)
              or Interfaces.Shift_Left (U32 (A (5 * I + 3)), 4);
         R (4 * I + 2) := I32 (V and 16#3FF#);

         V := Interfaces.Shift_Right (U32 (A (5 * I + 3)), 6)
              or Interfaces.Shift_Left (U32 (A (5 * I + 4)), 2);
         R (4 * I + 3) := I32 (V and 16#3FF#);
      end loop;
   end PolyT1_Unpack;

   ----------------------------------------------------------------------
   --  PolyT0 — 13 bits per coefficient (centered around 2^{D-1})
   ----------------------------------------------------------------------

   procedure PolyT0_Pack
     (R : out Byte_Array; A : Polynomial)
   is
      T : array (0 .. 7) of U32;
   begin
      R := [others => 0];
      for I in 0 .. N / 8 - 1 loop
         pragma Loop_Invariant (13 * I <= R'Last + 1);

         for J in 0 .. 7 loop
            T (J) := U32 (2 ** (D - 1) - A (8 * I + J));
         end loop;

         R (13 * I)     := U8 (T (0) and 16#FF#);
         R (13 * I + 1) := U8 ((Interfaces.Shift_Right (T (0), 8)
                                or Interfaces.Shift_Left (T (1), 5)) and 16#FF#);
         R (13 * I + 2) := U8 (Interfaces.Shift_Right (T (1), 3) and 16#FF#);
         R (13 * I + 3) := U8 ((Interfaces.Shift_Right (T (1), 11)
                                or Interfaces.Shift_Left (T (2), 2)) and 16#FF#);
         R (13 * I + 4) := U8 ((Interfaces.Shift_Right (T (2), 6)
                                or Interfaces.Shift_Left (T (3), 7)) and 16#FF#);
         R (13 * I + 5) := U8 (Interfaces.Shift_Right (T (3), 1) and 16#FF#);
         R (13 * I + 6) := U8 ((Interfaces.Shift_Right (T (3), 9)
                                or Interfaces.Shift_Left (T (4), 4)) and 16#FF#);
         R (13 * I + 7) := U8 (Interfaces.Shift_Right (T (4), 4) and 16#FF#);
         R (13 * I + 8) := U8 ((Interfaces.Shift_Right (T (4), 12)
                                or Interfaces.Shift_Left (T (5), 1)) and 16#FF#);
         R (13 * I + 9) := U8 ((Interfaces.Shift_Right (T (5), 7)
                                or Interfaces.Shift_Left (T (6), 6)) and 16#FF#);
         R (13 * I + 10) := U8 (Interfaces.Shift_Right (T (6), 2) and 16#FF#);
         R (13 * I + 11) := U8 ((Interfaces.Shift_Right (T (6), 10)
                                 or Interfaces.Shift_Left (T (7), 3)) and 16#FF#);
         R (13 * I + 12) := U8 (Interfaces.Shift_Right (T (7), 5) and 16#FF#);
      end loop;
   end PolyT0_Pack;

   procedure PolyT0_Unpack
     (R : out Polynomial; A : Byte_Array)
   is
      T : U32;
   begin
      R := [others => 0];
      for I in 0 .. N / 8 - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. 8 * I - 1 =>
              R (K) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1));
         pragma Loop_Invariant
           (for all K in 8 * I .. N - 1 => R (K) = 0);

         --  c0
         T := U32 (A (13 * I))
              or Interfaces.Shift_Left (U32 (A (13 * I + 1)), 8);
         T := T and 16#1FFF#;
         R (8 * I) := 2 ** (D - 1) - I32 (T);

         --  c1
         T := Interfaces.Shift_Right (U32 (A (13 * I + 1)), 5)
              or Interfaces.Shift_Left (U32 (A (13 * I + 2)), 3)
              or Interfaces.Shift_Left (U32 (A (13 * I + 3)), 11);
         T := T and 16#1FFF#;
         R (8 * I + 1) := 2 ** (D - 1) - I32 (T);

         --  c2
         T := Interfaces.Shift_Right (U32 (A (13 * I + 3)), 2)
              or Interfaces.Shift_Left (U32 (A (13 * I + 4)), 6);
         T := T and 16#1FFF#;
         R (8 * I + 2) := 2 ** (D - 1) - I32 (T);

         --  c3
         T := Interfaces.Shift_Right (U32 (A (13 * I + 4)), 7)
              or Interfaces.Shift_Left (U32 (A (13 * I + 5)), 1)
              or Interfaces.Shift_Left (U32 (A (13 * I + 6)), 9);
         T := T and 16#1FFF#;
         R (8 * I + 3) := 2 ** (D - 1) - I32 (T);

         --  c4
         T := Interfaces.Shift_Right (U32 (A (13 * I + 6)), 4)
              or Interfaces.Shift_Left (U32 (A (13 * I + 7)), 4)
              or Interfaces.Shift_Left (U32 (A (13 * I + 8)), 12);
         T := T and 16#1FFF#;
         R (8 * I + 4) := 2 ** (D - 1) - I32 (T);

         --  c5
         T := Interfaces.Shift_Right (U32 (A (13 * I + 8)), 1)
              or Interfaces.Shift_Left (U32 (A (13 * I + 9)), 7);
         T := T and 16#1FFF#;
         R (8 * I + 5) := 2 ** (D - 1) - I32 (T);

         --  c6
         T := Interfaces.Shift_Right (U32 (A (13 * I + 9)), 6)
              or Interfaces.Shift_Left (U32 (A (13 * I + 10)), 2)
              or Interfaces.Shift_Left (U32 (A (13 * I + 11)), 10);
         T := T and 16#1FFF#;
         R (8 * I + 6) := 2 ** (D - 1) - I32 (T);

         --  c7
         T := Interfaces.Shift_Right (U32 (A (13 * I + 11)), 3)
              or Interfaces.Shift_Left (U32 (A (13 * I + 12)), 5);
         T := T and 16#1FFF#;
         R (8 * I + 7) := 2 ** (D - 1) - I32 (T);
      end loop;
   end PolyT0_Unpack;

   ----------------------------------------------------------------------
   --  PolyEta — 3 or 4 bits per coefficient
   ----------------------------------------------------------------------

   procedure PolyEta_Pack
     (R : out Byte_Array; A : Polynomial)
   is
   begin
      R := [others => 0];
      if ML_DSA_Eta = 2 then
         declare
            T : array (0 .. 7) of U8;
         begin
            for I in 0 .. N / 8 - 1 loop
               pragma Loop_Invariant (3 * I <= R'Last + 1);
               for J in 0 .. 7 loop
                  T (J) := U8 (ML_DSA_Eta - A (8 * I + J));
               end loop;
               R (3 * I)     := T (0)
                                or Interfaces.Shift_Left (T (1), 3)
                                or Interfaces.Shift_Left (T (2), 6);
               R (3 * I + 1) := Interfaces.Shift_Right (T (2), 2)
                                or Interfaces.Shift_Left (T (3), 1)
                                or Interfaces.Shift_Left (T (4), 4)
                                or Interfaces.Shift_Left (T (5), 7);
               R (3 * I + 2) := Interfaces.Shift_Right (T (5), 1)
                                or Interfaces.Shift_Left (T (6), 2)
                                or Interfaces.Shift_Left (T (7), 5);
            end loop;
         end;
      else
         --  eta=4: 4 bits each, 2 coeffs per byte.
         declare
            T0, T1 : U8;
         begin
            for I in 0 .. N / 2 - 1 loop
               pragma Loop_Invariant (I <= R'Last + 1);
               T0 := U8 (ML_DSA_Eta - A (2 * I));
               T1 := U8 (ML_DSA_Eta - A (2 * I + 1));
               R (I) := T0 or Interfaces.Shift_Left (T1, 4);
            end loop;
         end;
      end if;
   end PolyEta_Pack;

   --  Decode a single nibble v in [0, 7] (eta=2) or [0, 15] (eta=4)
   --  into a coefficient in [-eta, eta]. Out-of-spec values (v > 2*eta)
   --  are clamped to 0 (eta - eta), since malformed bit patterns
   --  cannot represent any valid s1/s2 coefficient — downstream norm
   --  checks would have rejected them anyway. Clamping is safe for
   --  KAT vectors (which only contain valid encodings).
   function Eta_Decode (V : U32) return I32 is
     (if V <= 2 * ML_DSA_Eta
      then ML_DSA_Eta - I32 (V)
      else 0)
     with Pre  => V <= 15,
          Post => Eta_Decode'Result in -ML_DSA_Eta .. ML_DSA_Eta;

   procedure PolyEta_Unpack
     (R : out Polynomial; A : Byte_Array)
   is
   begin
      R := [others => 0];
      if ML_DSA_Eta = 2 then
         for I in 0 .. N / 8 - 1 loop
            pragma Loop_Invariant
              (for all K in 0 .. 8 * I - 1 =>
                 R (K) in -ML_DSA_Eta .. ML_DSA_Eta);
            pragma Loop_Invariant
              (for all K in 8 * I .. N - 1 => R (K) = 0);

            R (8 * I)     := Eta_Decode (U32 (A (3 * I)) and 7);
            R (8 * I + 1) := Eta_Decode
              (Interfaces.Shift_Right (U32 (A (3 * I)), 3) and 7);
            R (8 * I + 2) := Eta_Decode
              ((Interfaces.Shift_Right (U32 (A (3 * I)), 6)
                or Interfaces.Shift_Left (U32 (A (3 * I + 1)), 2)) and 7);
            R (8 * I + 3) := Eta_Decode
              (Interfaces.Shift_Right (U32 (A (3 * I + 1)), 1) and 7);
            R (8 * I + 4) := Eta_Decode
              (Interfaces.Shift_Right (U32 (A (3 * I + 1)), 4) and 7);
            R (8 * I + 5) := Eta_Decode
              ((Interfaces.Shift_Right (U32 (A (3 * I + 1)), 7)
                or Interfaces.Shift_Left (U32 (A (3 * I + 2)), 1)) and 7);
            R (8 * I + 6) := Eta_Decode
              (Interfaces.Shift_Right (U32 (A (3 * I + 2)), 2) and 7);
            R (8 * I + 7) := Eta_Decode
              (Interfaces.Shift_Right (U32 (A (3 * I + 2)), 5) and 7);
         end loop;
      else
         --  eta=4: 4-bit nibbles.
         for I in 0 .. N / 2 - 1 loop
            pragma Loop_Invariant
              (for all K in 0 .. 2 * I - 1 =>
                 R (K) in -ML_DSA_Eta .. ML_DSA_Eta);
            pragma Loop_Invariant
              (for all K in 2 * I .. N - 1 => R (K) = 0);

            R (2 * I)     := Eta_Decode (U32 (A (I)) and 16#0F#);
            R (2 * I + 1) := Eta_Decode (Interfaces.Shift_Right (U32 (A (I)), 4));
         end loop;
      end if;
   end PolyEta_Unpack;

   ----------------------------------------------------------------------
   --  PolyZ — 18 or 20 bits per coefficient
   ----------------------------------------------------------------------

   procedure PolyZ_Pack
     (R : out Byte_Array; A : Polynomial)
   is
   begin
      R := [others => 0];
      if ML_DSA_Gamma1_Bits = 17 then
         --  18 bits/coeff, 4 coeffs per 9 bytes.
         declare
            T : array (0 .. 3) of U32;
         begin
            for I in 0 .. N / 4 - 1 loop
               pragma Loop_Invariant (9 * I <= R'Last + 1);
               for J in 0 .. 3 loop
                  T (J) := U32 (ML_DSA_Gamma1 - A (4 * I + J));
               end loop;
               R (9 * I)     := U8 (T (0) and 16#FF#);
               R (9 * I + 1) := U8 (Interfaces.Shift_Right (T (0), 8) and 16#FF#);
               R (9 * I + 2) := U8 ((Interfaces.Shift_Right (T (0), 16)
                                     or Interfaces.Shift_Left (T (1), 2)) and 16#FF#);
               R (9 * I + 3) := U8 (Interfaces.Shift_Right (T (1), 6) and 16#FF#);
               R (9 * I + 4) := U8 ((Interfaces.Shift_Right (T (1), 14)
                                     or Interfaces.Shift_Left (T (2), 4)) and 16#FF#);
               R (9 * I + 5) := U8 (Interfaces.Shift_Right (T (2), 4) and 16#FF#);
               R (9 * I + 6) := U8 ((Interfaces.Shift_Right (T (2), 12)
                                     or Interfaces.Shift_Left (T (3), 6)) and 16#FF#);
               R (9 * I + 7) := U8 (Interfaces.Shift_Right (T (3), 2) and 16#FF#);
               R (9 * I + 8) := U8 (Interfaces.Shift_Right (T (3), 10) and 16#FF#);
            end loop;
         end;
      else
         --  20 bits/coeff, 2 coeffs per 5 bytes.
         declare
            T0, T1 : U32;
         begin
            for I in 0 .. N / 2 - 1 loop
               pragma Loop_Invariant (5 * I <= R'Last + 1);
               T0 := U32 (ML_DSA_Gamma1 - A (2 * I));
               T1 := U32 (ML_DSA_Gamma1 - A (2 * I + 1));
               R (5 * I)     := U8 (T0 and 16#FF#);
               R (5 * I + 1) := U8 (Interfaces.Shift_Right (T0, 8) and 16#FF#);
               R (5 * I + 2) := U8 ((Interfaces.Shift_Right (T0, 16)
                                     or Interfaces.Shift_Left (T1, 4)) and 16#FF#);
               R (5 * I + 3) := U8 (Interfaces.Shift_Right (T1, 4) and 16#FF#);
               R (5 * I + 4) := U8 (Interfaces.Shift_Right (T1, 12) and 16#FF#);
            end loop;
         end;
      end if;
   end PolyZ_Pack;

   procedure PolyZ_Unpack
     (R : out Polynomial; A : Byte_Array)
   is
      T : U32;
   begin
      R := [others => 0];
      if ML_DSA_Gamma1_Bits = 17 then
         for I in 0 .. N / 4 - 1 loop
            pragma Loop_Invariant
              (for all K in 0 .. 4 * I - 1 =>
                 R (K) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1);
            pragma Loop_Invariant
              (for all K in 4 * I .. N - 1 => R (K) = 0);

            T := U32 (A (9 * I))
                 or Interfaces.Shift_Left (U32 (A (9 * I + 1)), 8)
                 or Interfaces.Shift_Left (U32 (A (9 * I + 2)), 16);
            T := T and 16#3_FFFF#;
            R (4 * I)     := ML_DSA_Gamma1 - I32 (T);

            T := Interfaces.Shift_Right (U32 (A (9 * I + 2)), 2)
                 or Interfaces.Shift_Left (U32 (A (9 * I + 3)), 6)
                 or Interfaces.Shift_Left (U32 (A (9 * I + 4)), 14);
            T := T and 16#3_FFFF#;
            R (4 * I + 1) := ML_DSA_Gamma1 - I32 (T);

            T := Interfaces.Shift_Right (U32 (A (9 * I + 4)), 4)
                 or Interfaces.Shift_Left (U32 (A (9 * I + 5)), 4)
                 or Interfaces.Shift_Left (U32 (A (9 * I + 6)), 12);
            T := T and 16#3_FFFF#;
            R (4 * I + 2) := ML_DSA_Gamma1 - I32 (T);

            T := Interfaces.Shift_Right (U32 (A (9 * I + 6)), 6)
                 or Interfaces.Shift_Left (U32 (A (9 * I + 7)), 2)
                 or Interfaces.Shift_Left (U32 (A (9 * I + 8)), 10);
            T := T and 16#3_FFFF#;
            R (4 * I + 3) := ML_DSA_Gamma1 - I32 (T);
         end loop;
      else
         for I in 0 .. N / 2 - 1 loop
            pragma Loop_Invariant
              (for all K in 0 .. 2 * I - 1 =>
                 R (K) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1);
            pragma Loop_Invariant
              (for all K in 2 * I .. N - 1 => R (K) = 0);

            T := U32 (A (5 * I))
                 or Interfaces.Shift_Left (U32 (A (5 * I + 1)), 8)
                 or Interfaces.Shift_Left (U32 (A (5 * I + 2)), 16);
            T := T and 16#F_FFFF#;
            R (2 * I)     := ML_DSA_Gamma1 - I32 (T);

            T := Interfaces.Shift_Right (U32 (A (5 * I + 2)), 4)
                 or Interfaces.Shift_Left (U32 (A (5 * I + 3)), 4)
                 or Interfaces.Shift_Left (U32 (A (5 * I + 4)), 12);
            T := T and 16#F_FFFF#;
            R (2 * I + 1) := ML_DSA_Gamma1 - I32 (T);
         end loop;
      end if;
   end PolyZ_Unpack;

   ----------------------------------------------------------------------
   --  PolyW1 — 6 or 4 bits per coefficient
   ----------------------------------------------------------------------

   procedure PolyW1_Pack
     (R : out Byte_Array; A : Polynomial)
   is
   begin
      R := [others => 0];
      if ML_DSA_Gamma2 = (Q - 1) / 88 then
         --  6 bits/coeff, 4 coeffs per 3 bytes.
         for I in 0 .. N / 4 - 1 loop
            pragma Loop_Invariant (3 * I <= R'Last + 1);
            R (3 * I)     := U8 (U32 (A (4 * I)) and 16#3F#)
                             or U8 (Interfaces.Shift_Left
                                       (U32 (A (4 * I + 1)), 6) and 16#FF#);
            R (3 * I + 1) := U8 (Interfaces.Shift_Right
                                    (U32 (A (4 * I + 1)), 2) and 16#0F#)
                             or U8 (Interfaces.Shift_Left
                                       (U32 (A (4 * I + 2)), 4) and 16#FF#);
            R (3 * I + 2) := U8 (Interfaces.Shift_Right
                                    (U32 (A (4 * I + 2)), 4) and 16#03#)
                             or U8 (Interfaces.Shift_Left
                                       (U32 (A (4 * I + 3)), 2) and 16#FF#);
         end loop;
      else
         --  4 bits/coeff, 2 coeffs per byte.
         for I in 0 .. N / 2 - 1 loop
            pragma Loop_Invariant (I <= R'Last + 1);
            R (I) := U8 (U32 (A (2 * I)) and 16#0F#)
                     or U8 (Interfaces.Shift_Left
                               (U32 (A (2 * I + 1)), 4) and 16#FF#);
         end loop;
      end if;
   end PolyW1_Pack;

   ----------------------------------------------------------------------
   --  Pack/Unpack PK
   ----------------------------------------------------------------------

   procedure Pack_PK
     (PK  : out Byte_Array;
      Rho : Byte_Array_32;
      T1  : Poly_Vector_K)
   is
      Off : Natural := 0;
   begin
      PK := [others => 0];
      PK (0 .. 31) := Rho;
      Off := 32;
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant (Off = 32 + I * Poly_T1_Packed_Bytes);
         pragma Loop_Invariant (Off + Poly_T1_Packed_Bytes <= PK'Length);
         declare
            Tmp : Byte_Array (0 .. Poly_T1_Packed_Bytes - 1);
         begin
            PolyT1_Pack (Tmp, T1 (I));
            PK (Off .. Off + Poly_T1_Packed_Bytes - 1) := Tmp;
         end;
         Off := Off + Poly_T1_Packed_Bytes;
      end loop;
   end Pack_PK;

   procedure Unpack_PK
     (Rho : out Byte_Array_32;
      T1  : out Poly_Vector_K;
      PK  : Byte_Array)
   is
      Off : Natural := 32;
   begin
      Rho := Byte_Array_32 (PK (0 .. 31));
      T1  := [others => [others => 0]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant (Off = 32 + I * Poly_T1_Packed_Bytes);
         pragma Loop_Invariant (Off + Poly_T1_Packed_Bytes <= PK'Length);
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => T1 (II) (J) in 0 .. 1023));
         declare
            Tmp : constant Byte_Array (0 .. Poly_T1_Packed_Bytes - 1) :=
              PK (Off .. Off + Poly_T1_Packed_Bytes - 1);
         begin
            PolyT1_Unpack (T1 (I), Tmp);
         end;
         Off := Off + Poly_T1_Packed_Bytes;
      end loop;
   end Unpack_PK;

   ----------------------------------------------------------------------
   --  Pack/Unpack SK
   ----------------------------------------------------------------------

   procedure Pack_SK
     (SK    : out Byte_Array;
      Rho   : Byte_Array_32;
      Key   : Byte_Array_32;
      Tr    : Byte_Array_64;
      S1    : Poly_Vector_L;
      S2    : Poly_Vector_K;
      T0    : Poly_Vector_K)
   is
      Off : Natural := 0;
   begin
      SK := [others => 0];
      SK (0 .. 31) := Rho;
      Off := Off + 32;
      SK (Off .. Off + 31) := Key;
      Off := Off + 32;
      SK (Off .. Off + 63) := Tr;
      Off := Off + 64;

      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (Off = 128 + I * Poly_Eta_Packed_Bytes);
         pragma Loop_Invariant
           (Off + Poly_Eta_Packed_Bytes <= SK'Length);
         declare
            Tmp : Byte_Array (0 .. Poly_Eta_Packed_Bytes - 1);
         begin
            PolyEta_Pack (Tmp, S1 (I));
            SK (Off .. Off + Poly_Eta_Packed_Bytes - 1) := Tmp;
         end;
         Off := Off + Poly_Eta_Packed_Bytes;
      end loop;

      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (Off = 128 + ML_DSA_L * Poly_Eta_Packed_Bytes
                  + I * Poly_Eta_Packed_Bytes);
         pragma Loop_Invariant
           (Off + Poly_Eta_Packed_Bytes <= SK'Length);
         declare
            Tmp : Byte_Array (0 .. Poly_Eta_Packed_Bytes - 1);
         begin
            PolyEta_Pack (Tmp, S2 (I));
            SK (Off .. Off + Poly_Eta_Packed_Bytes - 1) := Tmp;
         end;
         Off := Off + Poly_Eta_Packed_Bytes;
      end loop;

      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (Off = 128 + (ML_DSA_L + ML_DSA_K) * Poly_Eta_Packed_Bytes
                  + I * Poly_T0_Packed_Bytes);
         pragma Loop_Invariant
           (Off + Poly_T0_Packed_Bytes <= SK'Length);
         declare
            Tmp : Byte_Array (0 .. Poly_T0_Packed_Bytes - 1);
         begin
            PolyT0_Pack (Tmp, T0 (I));
            SK (Off .. Off + Poly_T0_Packed_Bytes - 1) := Tmp;
         end;
         Off := Off + Poly_T0_Packed_Bytes;
      end loop;
   end Pack_SK;

   procedure Unpack_SK
     (Rho : out Byte_Array_32;
      Key : out Byte_Array_32;
      Tr  : out Byte_Array_64;
      S1  : out Poly_Vector_L;
      S2  : out Poly_Vector_K;
      T0  : out Poly_Vector_K;
      SK  : Byte_Array)
   is
      Off : Natural := 0;
   begin
      Rho := Byte_Array_32 (SK (0 .. 31));
      Off := Off + 32;
      Key := Byte_Array_32 (SK (Off .. Off + 31));
      Off := Off + 32;
      Tr  := Byte_Array_64 (SK (Off .. Off + 63));
      Off := Off + 64;

      S1 := [others => [others => 0]];
      S2 := [others => [others => 0]];
      T0 := [others => [others => 0]];

      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (Off = 128 + I * Poly_Eta_Packed_Bytes);
         pragma Loop_Invariant
           (Off + Poly_Eta_Packed_Bytes <= SK'Length);
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 S1 (II) (J) in -ML_DSA_Eta .. ML_DSA_Eta));
         declare
            Tmp : constant Byte_Array (0 .. Poly_Eta_Packed_Bytes - 1) :=
              SK (Off .. Off + Poly_Eta_Packed_Bytes - 1);
         begin
            PolyEta_Unpack (S1 (I), Tmp);
         end;
         Off := Off + Poly_Eta_Packed_Bytes;
      end loop;

      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (Off = 128 + ML_DSA_L * Poly_Eta_Packed_Bytes
                  + I * Poly_Eta_Packed_Bytes);
         pragma Loop_Invariant
           (Off + Poly_Eta_Packed_Bytes <= SK'Length);
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 S2 (II) (J) in -ML_DSA_Eta .. ML_DSA_Eta));
         declare
            Tmp : constant Byte_Array (0 .. Poly_Eta_Packed_Bytes - 1) :=
              SK (Off .. Off + Poly_Eta_Packed_Bytes - 1);
         begin
            PolyEta_Unpack (S2 (I), Tmp);
         end;
         Off := Off + Poly_Eta_Packed_Bytes;
      end loop;

      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (Off = 128 + (ML_DSA_L + ML_DSA_K) * Poly_Eta_Packed_Bytes
                  + I * Poly_T0_Packed_Bytes);
         pragma Loop_Invariant
           (Off + Poly_T0_Packed_Bytes <= SK'Length);
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 T0 (II) (J) in -(2 ** (D - 1) - 1) .. 2 ** (D - 1)));
         declare
            Tmp : constant Byte_Array (0 .. Poly_T0_Packed_Bytes - 1) :=
              SK (Off .. Off + Poly_T0_Packed_Bytes - 1);
         begin
            PolyT0_Unpack (T0 (I), Tmp);
         end;
         Off := Off + Poly_T0_Packed_Bytes;
      end loop;
   end Unpack_SK;

   ----------------------------------------------------------------------
   --  Pack/Unpack signature
   ----------------------------------------------------------------------

   procedure Pack_Sig
     (Sig        : out Byte_Array;
      C_Tilde    : Byte_Array;
      Z          : Poly_Vector_L;
      H          : Poly_Vector_K;
      Hint_Count : Natural)
   is
      Off : Natural := 0;
      Cnt : Natural := 0;
   begin
      Sig := [others => 0];
      Sig (0 .. C_Tilde_Bytes - 1) := C_Tilde;
      Off := C_Tilde_Bytes;

      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (Off = C_Tilde_Bytes + I * Poly_Z_Packed_Bytes);
         pragma Loop_Invariant
           (Off + Poly_Z_Packed_Bytes <= Sig'Length);
         declare
            Tmp : Byte_Array (0 .. Poly_Z_Packed_Bytes - 1);
         begin
            PolyZ_Pack (Tmp, Z (I));
            Sig (Off .. Off + Poly_Z_Packed_Bytes - 1) := Tmp;
         end;
         Off := Off + Poly_Z_Packed_Bytes;
      end loop;

      --  Hint encoding: positions of nonzero hint bits in each polynomial,
      --  followed by K cumulative-count bytes.
      pragma Assert (Off = C_Tilde_Bytes + ML_DSA_L * Poly_Z_Packed_Bytes);
      pragma Assert (Off + ML_DSA_Omega + ML_DSA_K = Sig'Length);

      --  First Omega bytes: positions of 1-bits within each polynomial,
      --  laid out contiguously and indexed by the K cumulative counts
      --  in the trailing K bytes. Defensive: stop emitting positions
      --  once Cnt reaches Hint_Count, which is bounded by Omega — the
      --  caller's precondition guards against overflow.
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant (Cnt <= I * N);
         pragma Loop_Invariant (Cnt <= Hint_Count);
         pragma Loop_Invariant (Cnt <= ML_DSA_Omega);
         pragma Loop_Invariant
           (Off + ML_DSA_Omega + ML_DSA_K = Sig'Length);

         for J in 0 .. N - 1 loop
            pragma Loop_Invariant (Cnt <= I * N + J);
            pragma Loop_Invariant (Cnt <= Hint_Count);
            pragma Loop_Invariant (Cnt <= ML_DSA_Omega);
            if H (I) (J) /= 0 and then Cnt < Hint_Count then
               Sig (Off + Cnt) := U8 (J);
               Cnt := Cnt + 1;
            end if;
         end loop;
         --  Cumulative count after row I.
         Sig (Off + ML_DSA_Omega + I) := U8 (Cnt);
      end loop;
   end Pack_Sig;

   procedure Unpack_Sig
     (C_Tilde : out Byte_Array;
      Z       : out Poly_Vector_L;
      H       : out Poly_Vector_K;
      Ok      : out Boolean;
      Sig     : Byte_Array)
   is
      Off : Natural := 0;
      Prev_Cum : Natural := 0;
      Cum : Natural;
   begin
      C_Tilde := Sig (0 .. C_Tilde_Bytes - 1);
      Off := C_Tilde_Bytes;
      Z := [others => [others => 0]];
      H := [others => [others => 0]];
      Ok := True;

      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (Off = C_Tilde_Bytes + I * Poly_Z_Packed_Bytes);
         pragma Loop_Invariant
           (Off + Poly_Z_Packed_Bytes <= Sig'Length);
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 Z (II) (J) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1));
         declare
            Tmp : constant Byte_Array (0 .. Poly_Z_Packed_Bytes - 1) :=
              Sig (Off .. Off + Poly_Z_Packed_Bytes - 1);
         begin
            PolyZ_Unpack (Z (I), Tmp);
         end;
         Off := Off + Poly_Z_Packed_Bytes;
      end loop;

      --  Decode hint bytes.
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant (Prev_Cum <= ML_DSA_Omega);
         pragma Loop_Invariant
           (Off + ML_DSA_Omega + ML_DSA_K = Sig'Length);
         pragma Loop_Invariant
           (for all II in 0 .. ML_DSA_K - 1 =>
              (for all J in 0 .. N - 1 => H (II) (J) in 0 .. 1));

         Cum := Natural (Sig (Off + ML_DSA_Omega + I));
         if Cum < Prev_Cum or else Cum > ML_DSA_Omega then
            Ok := False;
            return;
         end if;
         declare
            J_Prev : Integer := -1;
         begin
            for K in Prev_Cum .. Cum - 1 loop
               pragma Loop_Invariant (Prev_Cum <= K);
               pragma Loop_Invariant (K < Cum);
               pragma Loop_Invariant (Cum <= ML_DSA_Omega);
               pragma Loop_Invariant
                 (for all II in 0 .. ML_DSA_K - 1 =>
                    (for all J in 0 .. N - 1 => H (II) (J) in 0 .. 1));
               declare
                  Pos : constant Natural := Natural (Sig (Off + K));
               begin
                  if Pos <= J_Prev or else Pos >= N then
                     --  Position must be strictly increasing within
                     --  one polynomial's hint set (FIPS 204 §6.1).
                     Ok := False;
                     return;
                  end if;
                  H (I) (Pos) := 1;
                  J_Prev := Pos;
               end;
            end loop;
         end;
         Prev_Cum := Cum;
      end loop;

      --  Trailing zero check: bytes after the last position must be 0.
      for K in Prev_Cum .. ML_DSA_Omega - 1 loop
         if Sig (Off + K) /= 0 then
            Ok := False;
            return;
         end if;
      end loop;
   end Unpack_Sig;

end ML_DSA.Packing;
