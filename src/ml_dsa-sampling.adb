with Interfaces;
with SHA3;
with ML_DSA.Symmetric;

package body ML_DSA.Sampling is
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

   --  Block-count comments for each XOF stream are folded into the
   --  per-procedure cap loops (e.g. `for Block in 1 .. 256` in
   --  Poly_Uniform). See the comments at each call site.

   ----------------------------------------------------------------------
   --  Inner rejection samplers
   ----------------------------------------------------------------------

   procedure RejUniform
     (Buf     :     Byte_Array;
      Buf_Len :     Natural;
      R       : in out Polynomial;
      R_Len   : in out Natural)
   is
      T   : U32;
      Idx : Natural := R_Len;
      Pos : Natural := 0;
   begin
      while Idx < N and then Pos + 3 <= Buf_Len loop
         pragma Loop_Invariant (Idx >= R_Len and then Idx <= N);
         pragma Loop_Invariant (Pos <= Buf_Len);
         pragma Loop_Invariant (Pos + 3 <= Buf_Len);
         pragma Loop_Invariant (Buf_Len <= Buf'Length);
         pragma Loop_Invariant (Pos + 2 <= Buf'Last);
         pragma Loop_Invariant
           (for all I in 0 .. R_Len - 1 => R (I) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all I in R_Len .. Idx - 1 => R (I) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all I in Idx .. N - 1 => R (I) = 0);
         pragma Loop_Variant (Increases => Pos);

         T := U32 (Buf (Pos))
              or Interfaces.Shift_Left (U32 (Buf (Pos + 1)), 8)
              or Interfaces.Shift_Left (U32 (Buf (Pos + 2)), 16);
         T := T and 16#7F_FFFF#;  -- 23 bits
         Pos := Pos + 3;

         if T < U32 (Q) then
            R (Idx) := I32 (T);
            Idx := Idx + 1;
         end if;
      end loop;
      R_Len := Idx;
   end RejUniform;

   procedure RejEta
     (Buf     :     Byte_Array;
      Buf_Len :     Natural;
      R       : in out Polynomial;
      R_Len   : in out Natural)
   is
      Idx : Natural := R_Len;
      Pos : Natural := 0;
      T0, T1 : U32;
   begin
      while Idx < N and then Pos < Buf_Len loop
         pragma Loop_Invariant (Idx >= R_Len and then Idx <= N);
         pragma Loop_Invariant (Pos <= Buf_Len);
         pragma Loop_Invariant (Pos < Buf_Len);
         pragma Loop_Invariant (Pos < Buf'Length);
         pragma Loop_Invariant
           (for all I in 0 .. Idx - 1 => R (I) in -ML_DSA_Eta .. ML_DSA_Eta);
         pragma Loop_Invariant
           (for all I in Idx .. N - 1 => R (I) = 0);
         pragma Loop_Variant (Increases => Pos);

         T0 := U32 (Buf (Pos)) and 16#0F#;
         T1 := Interfaces.Shift_Right (U32 (Buf (Pos)), 4);
         Pos := Pos + 1;

         if ML_DSA_Eta = 2 then
            if T0 < 15 then
               --  T0 mod 5 via reciprocal trick: (205 * T0) >> 10.
               --  205 * 14 = 2870; 2870 >> 10 = 2; so 14 mod 5 ~ 14 - 2*5 = 4. ✓
               declare
                  R0 : constant U32 :=
                    T0 - Interfaces.Shift_Right (205 * T0, 10) * 5;
               begin
                  R (Idx) := 2 - I32 (R0);
                  Idx := Idx + 1;
               end;
            end if;
            if T1 < 15 and then Idx < N then
               declare
                  R1 : constant U32 :=
                    T1 - Interfaces.Shift_Right (205 * T1, 10) * 5;
               begin
                  R (Idx) := 2 - I32 (R1);
                  Idx := Idx + 1;
               end;
            end if;
         else
            --  ML_DSA_Eta = 4
            if T0 < 9 then
               R (Idx) := 4 - I32 (T0);
               Idx := Idx + 1;
            end if;
            if T1 < 9 and then Idx < N then
               R (Idx) := 4 - I32 (T1);
               Idx := Idx + 1;
            end if;
         end if;
      end loop;
      R_Len := Idx;
   end RejEta;

   ----------------------------------------------------------------------
   --  poly_uniform: drive RejUniform from a SHAKE128 XOF.
   ----------------------------------------------------------------------
   procedure Poly_Uniform
     (R     : out Polynomial;
      Seed  : Byte_Array_32;
      Nonce : U16)
   is
      State    : SHA3.Sponge_State;
      Buf      : Byte_Array (0 .. Symmetric.XOF128_Rate - 1) := [others => 0];
      Idx      : Natural;
      Nonce_Lo : constant U8 := U8 (Nonce mod 256);
      Nonce_Hi : constant U8 := U8 (Nonce / 256);
   begin
      R := [others => 0];
      Symmetric.XOF128_Init_Absorb (State, Seed, Nonce_Hi, Nonce_Lo);
      Idx := 0;

      --  Bound the loop to keep static stack analysis tractable. With
      --  168 bytes/block (rate) and ~5/16 rejection rate, expected
      --  blocks for 256 accepts is ~5.5; the 256-block cap caters for
      --  pathological seeds with failure prob < 2^-1024.
      for Block in 1 .. 256 loop
         pragma Loop_Invariant (Idx <= N);
         pragma Loop_Invariant (State.Byte_Pos < State.Rate);
         pragma Loop_Invariant (State.Rate < SHA3.State_Bytes);
         pragma Loop_Invariant
           (for all K in 0 .. Idx - 1 => R (K) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all K in Idx .. N - 1 => R (K) = 0);

         exit when Idx >= N;
         Symmetric.XOF128_Squeeze (State, Buf);
         RejUniform (Buf, Buf'Length, R, Idx);
      end loop;
   end Poly_Uniform;

   ----------------------------------------------------------------------
   --  poly_uniform_eta: drive RejEta from a SHAKE256 XOF.
   ----------------------------------------------------------------------
   procedure Poly_Uniform_Eta
     (R     : out Polynomial;
      Seed  : Byte_Array_64;
      Nonce : U16)
   is
      State    : SHA3.Sponge_State;
      Buf      : Byte_Array (0 .. Symmetric.XOF256_Rate - 1) := [others => 0];
      Idx      : Natural;
      Nonce_Lo : constant U8 := U8 (Nonce mod 256);
      Nonce_Hi : constant U8 := U8 (Nonce / 256);
   begin
      R := [others => 0];
      Symmetric.XOF256_Init_Absorb (State, Seed, Nonce_Hi, Nonce_Lo);
      Idx := 0;

      for Block in 1 .. 256 loop
         pragma Loop_Invariant (Idx <= N);
         pragma Loop_Invariant (State.Byte_Pos < State.Rate);
         pragma Loop_Invariant (State.Rate < SHA3.State_Bytes);
         pragma Loop_Invariant
           (for all K in 0 .. Idx - 1 => R (K) in -ML_DSA_Eta .. ML_DSA_Eta);
         pragma Loop_Invariant
           (for all K in Idx .. N - 1 => R (K) = 0);

         exit when Idx >= N;
         Symmetric.XOF256_Squeeze (State, Buf);
         RejEta (Buf, Buf'Length, R, Idx);
      end loop;
   end Poly_Uniform_Eta;

   ----------------------------------------------------------------------
   --  polyz_unpack: bit-decode the gamma1 mask polynomial.
   ----------------------------------------------------------------------
   procedure Polyz_Unpack
     (R   : out Polynomial;
      Buf : Byte_Array)
     with Pre  => (if ML_DSA_Gamma1_Bits = 17
                   then Buf'First = 0 and then Buf'Length = 576
                   else Buf'First = 0 and then Buf'Length = 640),
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1)
   is
      T : U32;
   begin
      R := [others => 0];
      if ML_DSA_Gamma1_Bits = 17 then
         --  Each coefficient is 18 bits; 4 coeffs per 9 bytes.
         for I in 0 .. N / 4 - 1 loop
            pragma Loop_Invariant
              (for all K in 0 .. 4 * I - 1 =>
                 R (K) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1);

            --  R(4i+0)
            T := U32 (Buf (9 * I))
                 or Interfaces.Shift_Left (U32 (Buf (9 * I + 1)), 8)
                 or Interfaces.Shift_Left (U32 (Buf (9 * I + 2)), 16);
            T := T and 16#3_FFFF#;  -- 18 bits
            R (4 * I)     := ML_DSA_Gamma1 - I32 (T);

            --  R(4i+1)
            T := Interfaces.Shift_Right (U32 (Buf (9 * I + 2)), 2)
                 or Interfaces.Shift_Left (U32 (Buf (9 * I + 3)), 6)
                 or Interfaces.Shift_Left (U32 (Buf (9 * I + 4)), 14);
            T := T and 16#3_FFFF#;
            R (4 * I + 1) := ML_DSA_Gamma1 - I32 (T);

            --  R(4i+2)
            T := Interfaces.Shift_Right (U32 (Buf (9 * I + 4)), 4)
                 or Interfaces.Shift_Left (U32 (Buf (9 * I + 5)), 4)
                 or Interfaces.Shift_Left (U32 (Buf (9 * I + 6)), 12);
            T := T and 16#3_FFFF#;
            R (4 * I + 2) := ML_DSA_Gamma1 - I32 (T);

            --  R(4i+3)
            T := Interfaces.Shift_Right (U32 (Buf (9 * I + 6)), 6)
                 or Interfaces.Shift_Left (U32 (Buf (9 * I + 7)), 2)
                 or Interfaces.Shift_Left (U32 (Buf (9 * I + 8)), 10);
            T := T and 16#3_FFFF#;
            R (4 * I + 3) := ML_DSA_Gamma1 - I32 (T);
         end loop;
      else
         --  gamma1=2^19, 20 bits/coeff, 2 coeffs per 5 bytes.
         for I in 0 .. N / 2 - 1 loop
            pragma Loop_Invariant
              (for all K in 0 .. 2 * I - 1 =>
                 R (K) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1);

            T := U32 (Buf (5 * I))
                 or Interfaces.Shift_Left (U32 (Buf (5 * I + 1)), 8)
                 or Interfaces.Shift_Left (U32 (Buf (5 * I + 2)), 16);
            T := T and 16#F_FFFF#;  -- 20 bits
            R (2 * I)     := ML_DSA_Gamma1 - I32 (T);

            T := Interfaces.Shift_Right (U32 (Buf (5 * I + 2)), 4)
                 or Interfaces.Shift_Left (U32 (Buf (5 * I + 3)), 4)
                 or Interfaces.Shift_Left (U32 (Buf (5 * I + 4)), 12);
            T := T and 16#F_FFFF#;
            R (2 * I + 1) := ML_DSA_Gamma1 - I32 (T);
         end loop;
      end if;
   end Polyz_Unpack;

   ----------------------------------------------------------------------
   --  poly_uniform_gamma1: SHAKE256 stream + polyz_unpack.
   ----------------------------------------------------------------------
   procedure Poly_Uniform_Gamma1
     (R     : out Polynomial;
      Seed  : Byte_Array_64;
      Nonce : U16)
   is
      Buf_Bytes : constant Natural := Poly_Z_Packed_Bytes;
      State     : SHA3.Sponge_State;
      Buf       : Byte_Array (0 .. Buf_Bytes - 1) := [others => 0];
      Nonce_Lo  : constant U8 := U8 (Nonce mod 256);
      Nonce_Hi  : constant U8 := U8 (Nonce / 256);
      Off       : Natural := 0;
      Block_Buf : Byte_Array (0 .. Symmetric.XOF256_Rate - 1) := [others => 0];
   begin
      R := [others => 0];
      Symmetric.XOF256_Init_Absorb (State, Seed, Nonce_Hi, Nonce_Lo);

      --  Squeeze enough rate-blocks to cover Buf.
      while Off + Symmetric.XOF256_Rate <= Buf_Bytes loop
         pragma Loop_Invariant (Off <= Buf_Bytes);
         pragma Loop_Invariant (Off mod Symmetric.XOF256_Rate = 0);
         pragma Loop_Invariant (State.Byte_Pos < State.Rate);
         pragma Loop_Invariant (State.Rate < SHA3.State_Bytes);
         pragma Loop_Variant (Increases => Off);
         Symmetric.XOF256_Squeeze (State, Block_Buf);
         Buf (Off .. Off + Symmetric.XOF256_Rate - 1) := Block_Buf;
         Off := Off + Symmetric.XOF256_Rate;
      end loop;
      --  Tail (if any). Buf_Bytes is 576 or 640; XOF256_Rate = 136.
      --  576 / 136 = 4.235, tail = 32. 640 / 136 = 4.7, tail = 96.
      if Off < Buf_Bytes then
         Symmetric.XOF256_Squeeze (State, Block_Buf);
         Buf (Off .. Buf_Bytes - 1) :=
           Block_Buf (0 .. Buf_Bytes - Off - 1);
      end if;

      Polyz_Unpack (R, Buf);
   end Poly_Uniform_Gamma1;

   ----------------------------------------------------------------------
   --  poly_challenge: sample sparse ±1 polynomial.
   ----------------------------------------------------------------------
   procedure Poly_Challenge
     (R    : out Polynomial;
      Seed : Byte_Array)
   is
      State : SHA3.Sponge_State;
      Buf   : Byte_Array (0 .. Symmetric.XOF256_Rate - 1) := [others => 0];
      Signs : U64 := 0;
      Pos   : Natural := 0;
      B     : Natural;
   begin
      R := [others => 0];
      Symmetric.SHAKE256_Init (State);
      Symmetric.SHAKE256_Absorb (State, Seed);
      Symmetric.SHAKE256_Squeeze (State, Buf);

      --  First 8 bytes form a 64-bit "signs" word, LSB first.
      --  No loop invariant needed: Signs is simply accumulated and
      --  later consumed bit-by-bit; SPARK's range checks suffice.
      for I in 0 .. 7 loop
         Signs := Signs or Interfaces.Shift_Left (U64 (Buf (I)), 8 * I);
      end loop;
      Pos := 8;

      --  Fisher-Yates-like loop: for i in [N-Tau, N-1], pick random b
      --  in [0, i] (rejecting bytes > i), set R(i) := R(b) and
      --  R(b) := ±1 (sign comes from Signs LSB, then Signs >>= 1).
      --  The inner rejection loop is bounded by Max_Reject_Attempts;
      --  empirically termination occurs within a handful of bytes
      --  (rejection probability decays as i grows from N-Tau to N-1).
      for I in N - ML_DSA_Tau .. N - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. N - 1 => R (K) in -1 .. 1);
         pragma Loop_Invariant (State.Byte_Pos < State.Rate);
         pragma Loop_Invariant (State.Rate < SHA3.State_Bytes);
         pragma Loop_Invariant (Pos <= Symmetric.XOF256_Rate);

         B := I + 1;
         for Attempts in 1 .. 65536 loop
            pragma Loop_Invariant (State.Byte_Pos < State.Rate);
            pragma Loop_Invariant (State.Rate < SHA3.State_Bytes);
            pragma Loop_Invariant (Pos <= Symmetric.XOF256_Rate);

            if Pos >= Symmetric.XOF256_Rate then
               Symmetric.SHAKE256_Squeeze (State, Buf);
               Pos := 0;
            end if;
            B := Natural (Buf (Pos));
            Pos := Pos + 1;
            exit when B <= I;
         end loop;
         --  Defensive: if Attempts exhausted without finding b <= I
         --  (probability ~ 0 in practice), use a deterministic fallback.
         if B > I then
            B := I;
         end if;

         R (I) := R (B);
         R (B) := 1 - 2 * I32 (Signs and 1);
         Signs := Interfaces.Shift_Right (Signs, 1);
      end loop;
   end Poly_Challenge;

end ML_DSA.Sampling;
