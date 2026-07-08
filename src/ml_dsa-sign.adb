with SHA3;
with ML_DSA.NTT;
with ML_DSA.Packing;
with ML_DSA.PolyVec;
with ML_DSA.Rounding;
with ML_DSA.Sampling;
with ML_DSA.Symmetric;
with ML_DSA.Wipe;

package body ML_DSA.Sign is
   pragma SPARK_Mode (On);

   --  Maximum signing attempts before giving up. Per-attempt rejection
   --  probability is empirically ~2-4%; failing all 1000 attempts has
   --  probability < 2^{-8000}.
   Max_Sign_Retries : constant := 1000;

   ----------------------------------------------------------------------
   --  Helpers: matrix expansion and per-row sampling lifts.
   ----------------------------------------------------------------------

   procedure Expand_Matrix (A : out Poly_Matrix_KL; Rho : Byte_Array_32)
     with Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. ML_DSA_L - 1 =>
                        (for all M in 0 .. N - 1 =>
                           A (I) (J) (M) in 0 .. Q - 1)))
   is
      Nonce : U16;
   begin
      A := [others => [others => [others => 0]]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. ML_DSA_L - 1 =>
                 (for all M in 0 .. N - 1 =>
                    A (II) (J) (M) in 0 .. Q - 1)));
         for J in 0 .. ML_DSA_L - 1 loop
            pragma Loop_Invariant
              (for all II in 0 .. I - 1 =>
                 (for all JJ in 0 .. ML_DSA_L - 1 =>
                    (for all M in 0 .. N - 1 =>
                       A (II) (JJ) (M) in 0 .. Q - 1)));
            pragma Loop_Invariant
              (for all JJ in 0 .. J - 1 =>
                 (for all M in 0 .. N - 1 =>
                    A (I) (JJ) (M) in 0 .. Q - 1));
            --  Domain separation: nonce = (i << 8) | j.
            Nonce := U16 (I) * 256 + U16 (J);
            Sampling.Poly_Uniform (A (I) (J), Rho, Nonce);
         end loop;
      end loop;
   end Expand_Matrix;

   procedure Expand_S1
     (S1       : out Poly_Vector_L;
      Rho_Prime : Byte_Array_64)
     with Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        S1 (I) (J) in -ML_DSA_Eta .. ML_DSA_Eta))
   is
   begin
      S1 := [others => [others => 0]];
      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 S1 (II) (J) in -ML_DSA_Eta .. ML_DSA_Eta));
         Sampling.Poly_Uniform_Eta (S1 (I), Rho_Prime, U16 (I));
      end loop;
   end Expand_S1;

   procedure Expand_S2
     (S2       : out Poly_Vector_K;
      Rho_Prime : Byte_Array_64)
     with Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        S2 (I) (J) in -ML_DSA_Eta .. ML_DSA_Eta))
   is
   begin
      S2 := [others => [others => 0]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 S2 (II) (J) in -ML_DSA_Eta .. ML_DSA_Eta));
         Sampling.Poly_Uniform_Eta (S2 (I), Rho_Prime, U16 (ML_DSA_L) + U16 (I));
      end loop;
   end Expand_S2;

   procedure Expand_Mask
     (Y         : out Poly_Vector_L;
      Rho_Prime : Byte_Array_64;
      Nonce     : U16)
     with Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        Y (I) (J) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1))
   is
   begin
      Y := [others => [others => 0]];
      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 Y (II) (J) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1));
         Sampling.Poly_Uniform_Gamma1
           (Y (I), Rho_Prime, Nonce + U16 (I));
      end loop;
   end Expand_Mask;

   --  Multiply a single polynomial cp pointwise by each row of a vector.
   procedure PolyVecL_Pointwise_Poly_Montgomery
     (R  : out Poly_Vector_L;
      Cp : Polynomial;
      V  : Poly_Vector_L)
     with Pre  => (for all J in 0 .. N - 1 =>
                     Cp (J) in -(Reduce32_Bound + 8 * Q)
                            .. (Reduce32_Bound + 8 * Q))
                  and then (for all I in 0 .. ML_DSA_L - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 V (I) (J) in -(Reduce32_Bound + 8 * Q)
                                           .. (Reduce32_Bound + 8 * Q))),
          Post => (for all I in 0 .. ML_DSA_L - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) in -(Q - 1) .. (Q - 1)))
   is
   begin
      R := [others => [others => 0]];
      for I in 0 .. ML_DSA_L - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) in -(Q - 1) .. (Q - 1)));
         NTT.Pointwise_Montgomery (R (I), Cp, V (I));
      end loop;
   end PolyVecL_Pointwise_Poly_Montgomery;

   procedure PolyVecK_Pointwise_Poly_Montgomery
     (R  : out Poly_Vector_K;
      Cp : Polynomial;
      V  : Poly_Vector_K)
     with Pre  => (for all J in 0 .. N - 1 =>
                     Cp (J) in -(Reduce32_Bound + 8 * Q)
                            .. (Reduce32_Bound + 8 * Q))
                  and then (for all I in 0 .. ML_DSA_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 V (I) (J) in -(Reduce32_Bound + 8 * Q)
                                           .. (Reduce32_Bound + 8 * Q))),
          Post => (for all I in 0 .. ML_DSA_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) in -(Q - 1) .. (Q - 1)))
   is
   begin
      R := [others => [others => 0]];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (II) (J) in -(Q - 1) .. (Q - 1)));
         NTT.Pointwise_Montgomery (R (I), Cp, V (I));
      end loop;
   end PolyVecK_Pointwise_Poly_Montgomery;

   --  Pack the K-vector w1 into a contiguous byte buffer for hashing.
   procedure Pack_W1
     (Buf : out Byte_Array;
      W1  : Poly_Vector_K)
     with Pre => Buf'First = 0
                 and then Buf'Length = ML_DSA_K * Poly_W1_Packed_Bytes
                 and then (for all I in 0 .. ML_DSA_K - 1 =>
                             (for all J in 0 .. N - 1 =>
                                W1 (I) (J) in 0 .. Rounding.Decompose_High_Max))
   is
      Off : Natural := 0;
   begin
      Buf := [others => 0];
      for I in 0 .. ML_DSA_K - 1 loop
         pragma Loop_Invariant (Off = I * Poly_W1_Packed_Bytes);
         pragma Loop_Invariant (Off + Poly_W1_Packed_Bytes <= Buf'Length);
         declare
            Tmp : Byte_Array (0 .. Poly_W1_Packed_Bytes - 1);
         begin
            Packing.PolyW1_Pack (Tmp, W1 (I));
            Buf (Off .. Off + Poly_W1_Packed_Bytes - 1) := Tmp;
         end;
         Off := Off + Poly_W1_Packed_Bytes;
      end loop;
   end Pack_W1;

   ----------------------------------------------------------------------
   --  KeyGen
   ----------------------------------------------------------------------
   procedure KeyGen
     (PK   : out Byte_Array;
      SK   : out Byte_Array;
      Seed : Byte_Array_32)
   is
      Seed_Buf : Byte_Array (0 .. 33) := [others => 0];
      Hash_Out : Byte_Array (0 .. 127) := [others => 0];  -- 32 + 64 + 32
      Rho      : Byte_Array_32 := [others => 0];
      Rho_Prime : Byte_Array_64 := [others => 0];
      Key      : Byte_Array_32 := [others => 0];
      Tr       : Byte_Array_64 := [others => 0];

      A        : Poly_Matrix_KL := [others => [others => [others => 0]]];
      S1       : Poly_Vector_L := [others => [others => 0]];
      S1_Hat   : Poly_Vector_L := [others => [others => 0]];
      S2       : Poly_Vector_K := [others => [others => 0]];
      T        : Poly_Vector_K := [others => [others => 0]];
      T0, T1   : Poly_Vector_K := [others => [others => 0]];
   begin
      --  PK and SK are filled completely by Pack_PK / Pack_SK below;
      --  no defensive init needed.

      --  Expand seed: SHAKE256(seed || K || L) -> rho || rhoprime || key.
      Seed_Buf (0 .. 31) := Seed;
      Seed_Buf (32) := U8 (ML_DSA_K);
      Seed_Buf (33) := U8 (ML_DSA_L);
      Symmetric.SHAKE256 (Seed_Buf, Hash_Out);
      Rho       := Byte_Array_32 (Hash_Out (0 .. 31));
      Rho_Prime := Byte_Array_64 (Hash_Out (32 .. 95));
      Key       := Byte_Array_32 (Hash_Out (96 .. 127));

      --  Expand A from rho.
      Expand_Matrix (A, Rho);

      --  Sample s1 and s2 from rhoprime.
      Expand_S1 (S1, Rho_Prime);
      Expand_S2 (S2, Rho_Prime);

      --  Compute t = A * NTT(s1) + s2.
      S1_Hat := S1;
      PolyVec.PolyVecL_NTT (S1_Hat);
      PolyVec.PolyVec_Matrix_Pointwise_Montgomery (T, A, S1_Hat);
      PolyVec.PolyVecK_Reduce (T);
      PolyVec.PolyVecK_InvNTT_ToMont (T);
      PolyVec.PolyVecK_Add (T, S2);
      --  Reduce before CAddQ: |T+S2| could reach Q-1+eta which exceeds
      --  the CAddQ precondition. Reduce32 normalises modulo Q so the
      --  packed bytes are unchanged.
      PolyVec.PolyVecK_Reduce (T);
      PolyVec.PolyVecK_CAddQ (T);

      --  Power2Round to split t into t1 (high) and t0 (low).
      PolyVec.PolyVecK_Power2Round (T1, T0, T);

      --  Pack public key = rho || t1.
      Packing.Pack_PK (PK, Rho, T1);

      --  Compute tr = SHAKE256(pk).
      Symmetric.SHAKE256 (PK, Tr);

      --  Pack secret key = rho || key || tr || s1 || s2 || t0.
      Packing.Pack_SK (SK, Rho, Key, Tr, S1, S2, T0);

      --  Zeroise locals derived from the secret seed. Public values
      --  (rho, t1, A — derived from rho) need not be wiped.
      pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (Off, "statement has no effect");
      Wipe.Wipe_Byte_Array (Seed_Buf);
      Wipe.Wipe_Byte_Array (Hash_Out);
      Wipe.Wipe_Byte_Array (Rho_Prime);
      Wipe.Wipe_Byte_Array (Key);
      Wipe.Wipe_Poly_Vector_L (S1);
      Wipe.Wipe_Poly_Vector_L (S1_Hat);
      Wipe.Wipe_Poly_Vector_K (S2);
      Wipe.Wipe_Poly_Vector_K (T0);
      pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (On, "statement has no effect");
   end KeyGen;

   ----------------------------------------------------------------------
   --  Sign (FIPS 204 hedged signing)
   ----------------------------------------------------------------------
   procedure Sign
     (Sig : out Byte_Array;
      Ok  : out Boolean;
      M   : Byte_Array;
      Ctx : Byte_Array;
      Rnd : Byte_Array_32;
      SK  : Byte_Array)
   is
      Rho      : Byte_Array_32 := [others => 0];
      Key      : Byte_Array_32 := [others => 0];
      Tr       : Byte_Array_64 := [others => 0];
      S1       : Poly_Vector_L := [others => [others => 0]];
      S2       : Poly_Vector_K := [others => [others => 0]];
      T0       : Poly_Vector_K := [others => [others => 0]];
      A        : Poly_Matrix_KL := [others => [others => [others => 0]]];

      Mu       : Byte_Array_64 := [others => 0];
      Rho_PP   : Byte_Array_64 := [others => 0];  -- rhoprime
      State    : SHA3.Sponge_State;

      Y, Z     : Poly_Vector_L := [others => [others => 0]];
      W, W1, W0 : Poly_Vector_K := [others => [others => 0]];
      H        : Poly_Vector_K := [others => [others => 0]];
      Cp       : Polynomial := [others => 0];
      Cp_Hat   : Polynomial := [others => 0];
      C_Tilde  : Byte_Array (0 .. C_Tilde_Bytes - 1) := [others => 0];
      W1_Buf   : Byte_Array (0 .. ML_DSA_K * Poly_W1_Packed_Bytes - 1)
                 := [others => 0];
      Pre_Hdr  : Byte_Array (0 .. 1) := [others => 0];

      CS2       : Poly_Vector_K := [others => [others => 0]];
      CT0       : Poly_Vector_K := [others => [others => 0]];
      Hint_Cnt  : Natural := 0;
      Nonce     : U16 := 0;
      Accepted  : Boolean := False;
      Retries   : Natural := 0;
   begin
      Sig := [others => 0];
      Ok  := False;

      --  1. Unpack secret key.
      Packing.Unpack_SK (Rho, Key, Tr, S1, S2, T0, SK);

      --  2. Compute mu = SHAKE256(tr || pre || M) where pre = 0x00 || ctxlen || ctx.
      Pre_Hdr (0) := 0;
      Pre_Hdr (1) := U8 (Ctx'Length);
      Symmetric.SHAKE256_Init (State);
      Symmetric.SHAKE256_Absorb (State, Tr);
      Symmetric.SHAKE256_Absorb (State, Pre_Hdr);
      Symmetric.SHAKE256_Absorb (State, Ctx);
      Symmetric.SHAKE256_Absorb (State, M);
      Symmetric.SHAKE256_Squeeze (State, Mu);

      --  3. Compute rhoprime = SHAKE256(key || rnd || mu).
      Symmetric.SHAKE256_Init (State);
      Symmetric.SHAKE256_Absorb (State, Key);
      Symmetric.SHAKE256_Absorb (State, Rnd);
      Symmetric.SHAKE256_Absorb (State, Mu);
      Symmetric.SHAKE256_Squeeze (State, Rho_PP);

      --  4. Expand matrix A and transform secret-vector polynomials to NTT.
      Expand_Matrix (A, Rho);
      PolyVec.PolyVecL_NTT (S1);
      PolyVec.PolyVecK_NTT (S2);
      PolyVec.PolyVecK_NTT (T0);

      --  5. Rejection-sampling loop (bounded).
      while not Accepted and then Retries < Max_Sign_Retries loop
         pragma Loop_Variant (Increases => Retries);
         pragma Loop_Invariant (not Accepted);
         pragma Loop_Invariant (Retries < Max_Sign_Retries);

         --  5a. Sample masking vector y.
         Expand_Mask (Y, Rho_PP, Nonce);
         Nonce := Nonce + U16 (ML_DSA_L);

         --  5b. Compute w = A * NTT(y), then InvNTT, then split.
         Z := Y;
         PolyVec.PolyVecL_NTT (Z);
         PolyVec.PolyVec_Matrix_Pointwise_Montgomery (W, A, Z);
         PolyVec.PolyVecK_Reduce (W);
         PolyVec.PolyVecK_InvNTT_ToMont (W);
         PolyVec.PolyVecK_CAddQ (W);
         PolyVec.PolyVecK_Decompose (W1, W0, W);

         --  5c. Compute c~ = SHAKE256(mu || w1_packed).
         Pack_W1 (W1_Buf, W1);
         Symmetric.SHAKE256_Init (State);
         Symmetric.SHAKE256_Absorb (State, Mu);
         Symmetric.SHAKE256_Absorb (State, W1_Buf);
         Symmetric.SHAKE256_Squeeze (State, C_Tilde);

         --  5d. Sample challenge c, transform to NTT.
         Sampling.Poly_Challenge (Cp, C_Tilde);
         Cp_Hat := Cp;
         NTT.NTT (Cp_Hat);

         --  5e. Compute z = y + c*s1 (in NTT, then InvNTT).
         PolyVecL_Pointwise_Poly_Montgomery (Z, Cp_Hat, S1);
         PolyVec.PolyVecL_Reduce (Z);   -- bound: Q-1 -> R32_B (InvNTT pre)
         PolyVec.PolyVecL_InvNTT_ToMont (Z);
         PolyVec.PolyVecL_Add (Z, Y);
         PolyVec.PolyVecL_Reduce (Z);
         if PolyVec.PolyVecL_ChkNorm (Z, ML_DSA_Gamma1 - ML_DSA_Beta) then
            Retries := Retries + 1;
            goto Continue_Loop;
         end if;

         --  5f. Compute c*s2 and check w0 - c*s2 norm.
         PolyVecK_Pointwise_Poly_Montgomery (CS2, Cp_Hat, S2);
         PolyVec.PolyVecK_Reduce (CS2);   -- bound: Q-1 -> R32_B
         PolyVec.PolyVecK_InvNTT_ToMont (CS2);
         PolyVec.PolyVecK_Sub (W0, CS2);
         PolyVec.PolyVecK_Reduce (W0);
         if PolyVec.PolyVecK_ChkNorm (W0, ML_DSA_Gamma2 - ML_DSA_Beta) then
            Retries := Retries + 1;
            goto Continue_Loop;
         end if;

         --  5g. Compute c*t0 and check norm.
         PolyVecK_Pointwise_Poly_Montgomery (CT0, Cp_Hat, T0);
         PolyVec.PolyVecK_Reduce (CT0);   -- bound: Q-1 -> R32_B
         PolyVec.PolyVecK_InvNTT_ToMont (CT0);
         PolyVec.PolyVecK_Reduce (CT0);
         if PolyVec.PolyVecK_ChkNorm (CT0, ML_DSA_Gamma2) then
            Retries := Retries + 1;
            goto Continue_Loop;
         end if;

         --  5h. Compute hints.
         PolyVec.PolyVecK_Add (W0, CT0);
         PolyVec.PolyVecK_Make_Hint (H, Hint_Cnt, W0, W1);
         if Hint_Cnt > ML_DSA_Omega then
            Retries := Retries + 1;
            goto Continue_Loop;
         end if;

         --  All checks passed.
         Accepted := True;

         <<Continue_Loop>>
         null;
      end loop;

      if not Accepted then
         --  Highly unlikely: rejection probability per attempt ~2-4%,
         --  failing 1000 attempts has prob < 2^{-8000}.
         return;
      end if;

      --  6. Pack the signature.
      Packing.Pack_Sig (Sig, C_Tilde, Z, H, Hint_Cnt);
      Ok := True;

      --  Zeroise locals derived from the secret key (s1, s2, t0,
      --  key) and from the per-signature randomness (rho_pp, mu, y).
      --  C_Tilde, Z, H are public (they live in Sig). PK is public.
      pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (Off, "statement has no effect");
      Wipe.Wipe_Byte_Array (Key);
      Wipe.Wipe_Byte_Array (Mu);
      Wipe.Wipe_Byte_Array (Rho_PP);
      Wipe.Wipe_Poly_Vector_L (S1);
      Wipe.Wipe_Poly_Vector_K (S2);
      Wipe.Wipe_Poly_Vector_K (T0);
      Wipe.Wipe_Poly_Vector_L (Y);
      Wipe.Wipe_Poly_Vector_K (W);
      Wipe.Wipe_Poly_Vector_K (W0);
      Wipe.Wipe_Poly_Vector_K (CS2);
      Wipe.Wipe_Poly_Vector_K (CT0);
      Wipe.Wipe_Polynomial (Cp);
      Wipe.Wipe_Polynomial (Cp_Hat);
      pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (On, "statement has no effect");
   end Sign;

   ----------------------------------------------------------------------
   --  Sign_With_Self_Verify (fault-injection countermeasure)
   ----------------------------------------------------------------------
   procedure Sign_With_Self_Verify
     (Sig : out Byte_Array;
      Ok  : out Boolean;
      M   : Byte_Array;
      Ctx : Byte_Array;
      Rnd : Byte_Array_32;
      SK  : Byte_Array;
      PK  : Byte_Array)
   is
   begin
      Sign (Sig, Ok, M, Ctx, Rnd, SK);
      if Ok then
         if not Verify (Sig, M, Ctx, PK) then
            --  Self-verify failed: a fault corrupted the signing
            --  computation (or pk/sk are mismatched). Either way,
            --  the produced signature must not be released.
            Sig := [others => 0];
            Ok := False;
         end if;
      end if;
   end Sign_With_Self_Verify;

   ----------------------------------------------------------------------
   --  Verify
   ----------------------------------------------------------------------
   function Verify
     (Sig : Byte_Array;
      M   : Byte_Array;
      Ctx : Byte_Array;
      PK  : Byte_Array) return Boolean
   is
      Rho      : Byte_Array_32 := [others => 0];
      T1       : Poly_Vector_K := [others => [others => 0]];
      C_Tilde  : Byte_Array (0 .. C_Tilde_Bytes - 1) := [others => 0];
      C_Tilde2 : Byte_Array (0 .. C_Tilde_Bytes - 1) := [others => 0];
      Z        : Poly_Vector_L := [others => [others => 0]];
      H        : Poly_Vector_K := [others => [others => 0]];
      Sig_Ok   : Boolean := False;
      A        : Poly_Matrix_KL := [others => [others => [others => 0]]];
      Cp       : Polynomial := [others => 0];
      Cp_Hat   : Polynomial := [others => 0];
      W1_Recon : Poly_Vector_K := [others => [others => 0]];
      Tr       : Byte_Array_64 := [others => 0];
      Mu       : Byte_Array_64 := [others => 0];
      State    : SHA3.Sponge_State;
      W1_Buf   : Byte_Array (0 .. ML_DSA_K * Poly_W1_Packed_Bytes - 1)
                 := [others => 0];
      Pre_Hdr  : Byte_Array (0 .. 1) := [others => 0];
   begin
      --  1. Unpack PK and SIG.
      Packing.Unpack_PK (Rho, T1, PK);
      Packing.Unpack_Sig (C_Tilde, Z, H, Sig_Ok, Sig);
      if not Sig_Ok then
         return False;
      end if;

      --  2. Norm check on z.
      if PolyVec.PolyVecL_ChkNorm (Z, ML_DSA_Gamma1 - ML_DSA_Beta) then
         return False;
      end if;

      --  3. Compute mu = SHAKE256(SHAKE256(pk) || pre || M).
      Symmetric.SHAKE256 (PK, Tr);
      Pre_Hdr (0) := 0;
      Pre_Hdr (1) := U8 (Ctx'Length);
      Symmetric.SHAKE256_Init (State);
      Symmetric.SHAKE256_Absorb (State, Tr);
      Symmetric.SHAKE256_Absorb (State, Pre_Hdr);
      Symmetric.SHAKE256_Absorb (State, Ctx);
      Symmetric.SHAKE256_Absorb (State, M);
      Symmetric.SHAKE256_Squeeze (State, Mu);

      --  4. Sample challenge c from c_tilde, NTT it.
      Sampling.Poly_Challenge (Cp, C_Tilde);
      Cp_Hat := Cp;
      NTT.NTT (Cp_Hat);

      --  5. Reconstruct w1 = UseHint(A*z - c*2^D*t1, h).
      Expand_Matrix (A, Rho);
      PolyVec.PolyVecL_NTT (Z);
      PolyVec.PolyVec_Matrix_Pointwise_Montgomery (W1_Recon, A, Z);

      --  c * 2^D * t1
      PolyVec.PolyVecK_ShiftL (T1);
      PolyVec.PolyVecK_Reduce (T1);   -- bound: Q-1 -> R32_B (NTT pre)
      PolyVec.PolyVecK_NTT (T1);
      declare
         Ct1 : Poly_Vector_K;
      begin
         PolyVecK_Pointwise_Poly_Montgomery (Ct1, Cp_Hat, T1);
         T1 := Ct1;
      end;

      PolyVec.PolyVecK_Sub (W1_Recon, T1);
      PolyVec.PolyVecK_Reduce (W1_Recon);
      PolyVec.PolyVecK_InvNTT_ToMont (W1_Recon);
      PolyVec.PolyVecK_CAddQ (W1_Recon);

      --  Apply hints to recover w1'.
      declare
         W1_New : Poly_Vector_K;
      begin
         PolyVec.PolyVecK_Use_Hint (W1_New, W1_Recon, H);
         W1_Recon := W1_New;
      end;

      Pack_W1 (W1_Buf, W1_Recon);

      --  6. Recompute c~' and compare.
      Symmetric.SHAKE256_Init (State);
      Symmetric.SHAKE256_Absorb (State, Mu);
      Symmetric.SHAKE256_Absorb (State, W1_Buf);
      Symmetric.SHAKE256_Squeeze (State, C_Tilde2);

      --  Constant-time-ish equality check.
      declare
         Diff : U8 := 0;
      begin
         for I in 0 .. C_Tilde_Bytes - 1 loop
            Diff := Diff or (C_Tilde (I) xor C_Tilde2 (I));
         end loop;
         return Diff = 0;
      end;
   end Verify;

end ML_DSA.Sign;
