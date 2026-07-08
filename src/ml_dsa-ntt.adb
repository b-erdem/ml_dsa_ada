with ML_DSA.NTT_Zetas;
with ML_DSA.Reduce;

package body ML_DSA.NTT is
   pragma SPARK_Mode (On);

   --  f = 2^32 / 256 mod q in Montgomery form (matches dilithium reference).
   F_InvNTT : constant I32 := 41_978;

   ----------------------------------------------------------------------
   --  Single butterfly: t = MR(zeta * R(j_plus_len));
   --  R(j_plus_len) := R(j) - t;
   --  R(j)         := R(j) + t;
   --
   --  Bound contract: if every coefficient is in -B_In..B_In with
   --  B_In <= NTT_Output_Bound - Q, then after the butterfly R(j) and
   --  R(j+len) are in -(B_In+Q) .. (B_In+Q) (Montgomery_Reduce yields
   --  |t| < Q). Other coefficients are unchanged.
   ----------------------------------------------------------------------
   procedure Butterfly
     (R          : in out Polynomial;
      J          : Natural;
      J_Plus_Len : Natural;
      Zeta       : NTT_Zetas.Zeta_Type;
      B_In       : I32)
     with Pre  => J < J_Plus_Len
                  and then J_Plus_Len < N
                  and then B_In in Reduce32_Bound .. NTT_Output_Bound - Q
                  and then (for all I in 0 .. N - 1 =>
                              R (I) in -(B_In + Q) .. (B_In + Q))
                  and then R (J) in -B_In .. B_In
                  and then R (J_Plus_Len) in -B_In .. B_In,
          Post => (for all I in 0 .. N - 1 =>
                     (if I = J or I = J_Plus_Len then
                        R (I) in -(B_In + Q) .. (B_In + Q)
                      else
                        R (I) = R'Old (I)))
   is
      T   : I32;
      Mul : constant I64 := I64 (Zeta) * I64 (R (J_Plus_Len));
   begin
      --  |Zeta * R(j+len)| <= ((Q-1)/2) * B_In <= ((Q-1)/2) * NTT_Output_Bound
      --   ~ 4.2e6 * 7.3e7 ~ 3.07e14, well below MR precondition Q*2^31 ~ 1.8e16.
      T := Reduce.Montgomery_Reduce (Mul);
      R (J_Plus_Len) := R (J) - T;
      R (J) := R (J) + T;
   end Butterfly;

   ----------------------------------------------------------------------
   --  Forward NTT
   ----------------------------------------------------------------------
   procedure NTT (R : in out Polynomial) is
      Len   : Natural := 128;
      Start : Natural;
      K_Idx : Natural := 0;
      --  Bound on |R(I)| at the start of each outer (Len) iteration.
      --  Initially Reduce32_Bound (input precondition); each butterfly
      --  layer adds Q.
      Bound : I32 := Reduce32_Bound;
   begin
      while Len >= 1 loop
         pragma Loop_Variant (Decreases => Len);
         pragma Loop_Invariant (Len in 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128);
         pragma Loop_Invariant
           (case Len is
              when 128 => Bound = Reduce32_Bound,
              when 64  => Bound = Reduce32_Bound + 1 * Q,
              when 32  => Bound = Reduce32_Bound + 2 * Q,
              when 16  => Bound = Reduce32_Bound + 3 * Q,
              when 8   => Bound = Reduce32_Bound + 4 * Q,
              when 4   => Bound = Reduce32_Bound + 5 * Q,
              when 2   => Bound = Reduce32_Bound + 6 * Q,
              when 1   => Bound = Reduce32_Bound + 7 * Q,
              when others => False);
         pragma Loop_Invariant
           (for all I in 0 .. N - 1 => R (I) in -Bound .. Bound);
         pragma Loop_Invariant (K_Idx * Len = 128 - Len);

         Start := 0;
         while Start < N loop
            pragma Loop_Invariant (Len in 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128);
            pragma Loop_Invariant (Start mod (2 * Len) = 0);
            pragma Loop_Invariant (Start <= N);
            pragma Loop_Invariant (Start + 2 * Len <= N);
            pragma Loop_Invariant (Bound <= NTT_Output_Bound - Q);
            pragma Loop_Invariant (Bound >= Reduce32_Bound);
            pragma Loop_Invariant (K_Idx * Len = 128 - Len + Start / 2);
            pragma Loop_Invariant (K_Idx <= 254);
            --  Already-processed segments: positions [0, Start-1] are
            --  in the looser post-layer bound -(Bound+Q)..(Bound+Q).
            pragma Loop_Invariant
              (for all I in 0 .. Start - 1 =>
                 R (I) in -(Bound + Q) .. (Bound + Q));
            --  Untouched segments: positions [Start, N-1] are still
            --  in the original layer-entry bound -Bound..Bound.
            pragma Loop_Invariant
              (for all I in Start .. N - 1 => R (I) in -Bound .. Bound);
            pragma Loop_Variant (Increases => Start);

            K_Idx := K_Idx + 1;

            --  Process segment [Start, Start+2*Len-1] in place.
            for J in Start .. Start + Len - 1 loop
               pragma Loop_Invariant (J in Start .. Start + Len - 1);
               pragma Loop_Invariant (J + Len <= N - 1);
               pragma Loop_Invariant (K_Idx in 1 .. 255);
               pragma Loop_Invariant (Bound <= NTT_Output_Bound - Q);
               pragma Loop_Invariant (Bound >= Reduce32_Bound);
               --  Prior segments already in post-layer bound.
               pragma Loop_Invariant
                 (for all I in 0 .. Start - 1 =>
                    R (I) in -(Bound + Q) .. (Bound + Q));
               --  Low half already processed in this segment.
               pragma Loop_Invariant
                 (for all I in Start .. J - 1 =>
                    R (I) in -(Bound + Q) .. (Bound + Q));
               --  High half already processed in this segment.
               pragma Loop_Invariant
                 (for all I in Start + Len .. J + Len - 1 =>
                    R (I) in -(Bound + Q) .. (Bound + Q));
               --  Low half still pending (includes current J).
               pragma Loop_Invariant
                 (for all I in J .. Start + Len - 1 =>
                    R (I) in -Bound .. Bound);
               --  High half still pending (includes current J+Len).
               pragma Loop_Invariant
                 (for all I in J + Len .. Start + 2 * Len - 1 =>
                    R (I) in -Bound .. Bound);
               --  Subsequent segments untouched.
               pragma Loop_Invariant
                 (for all I in Start + 2 * Len .. N - 1 =>
                    R (I) in -Bound .. Bound);
               --  Loose universal invariant for Butterfly precondition.
               pragma Loop_Invariant
                 (for all I in 0 .. N - 1 =>
                    R (I) in -(Bound + Q) .. (Bound + Q));

               Butterfly (R, J, J + Len, NTT_Zetas.Zetas (K_Idx), Bound);
            end loop;

            Start := Start + 2 * Len;
         end loop;

         Len := Len / 2;
         Bound := Bound + Q;
         exit when Len = 0;
      end loop;
   end NTT;

   ----------------------------------------------------------------------
   --  Inverse NTT, scaled by 2^32 (Montgomery factor).
   --
   --  Each butterfly:
   --      t := R(j);
   --      R(j)     := t + R(j+len);
   --      R(j+len) := MR (zeta * (t - R(j+len)));
   --
   --  Bound analysis with `Bound = 2^L * R32_B` at start of layer L:
   --   * Pre-body: R(I) in -Bound..Bound for all I.
   --   * During body: T+U and T-U are bounded by 2*Bound, fitting in
   --     I32 since 2 * 128 * R32_B = 256 * R32_B = 1_608_450_304 < 2^31.
   --   * Post-body (universal envelope): R(I) in -(2*Bound)..(2*Bound).
   --   * Layer transition: Bound := 2*Bound, restoring the pre-body
   --     invariant for the next layer.
   --
   --  After 8 layers the max envelope is 256 * R32_B. The final
   --  f-multiply with Montgomery_Reduce brings every coeff into (-Q, Q).
   ----------------------------------------------------------------------
   procedure InvNTT_ToMont (R : in out Polynomial) is
      Len   : Natural := 1;
      Start : Natural;
      K_Idx : Natural := 256;
      Bound : I32 := Reduce32_Bound;  -- = 2^0 * R32_B
      T, U  : I32;
      Mul   : I64;
      Zeta  : I32;
   begin
      while Len < N loop
         pragma Loop_Variant (Increases => Len);
         pragma Loop_Invariant (Len in 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128);
         pragma Loop_Invariant
           (case Len is
              when 1   => Bound = Reduce32_Bound,
              when 2   => Bound = 2 * Reduce32_Bound,
              when 4   => Bound = 4 * Reduce32_Bound,
              when 8   => Bound = 8 * Reduce32_Bound,
              when 16  => Bound = 16 * Reduce32_Bound,
              when 32  => Bound = 32 * Reduce32_Bound,
              when 64  => Bound = 64 * Reduce32_Bound,
              when 128 => Bound = 128 * Reduce32_Bound,
              when others => False);
         pragma Loop_Invariant (Bound <= 128 * Reduce32_Bound);
         pragma Loop_Invariant (Bound >= Reduce32_Bound);
         pragma Loop_Invariant (K_Idx in 2 .. 256);
         pragma Loop_Invariant (K_Idx * Len = 256);
         pragma Loop_Invariant
           (for all I in 0 .. N - 1 => R (I) in -Bound .. Bound);

         Start := 0;
         while Start < N loop
            pragma Loop_Variant (Increases => Start);
            pragma Loop_Invariant (Len in 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128);
            pragma Loop_Invariant (Start mod (2 * Len) = 0);
            pragma Loop_Invariant (Start <= N);
            pragma Loop_Invariant (Start + 2 * Len <= N);
            pragma Loop_Invariant (Bound <= 128 * Reduce32_Bound);
            pragma Loop_Invariant (Bound >= Reduce32_Bound);
            pragma Loop_Invariant (K_Idx in 1 .. 256);
            pragma Loop_Invariant (2 * K_Idx * Len + Start = 2 * N);
            --  Six-piece segment invariant: prefix already processed
            --  (loose envelope), suffix still at layer-entry tight
            --  bound. Mirrors the forward NTT's structure, adapted to
            --  the InvNTT bound (each layer's max grows by 2x rather
            --  than additively by Q).
            pragma Loop_Invariant
              (for all I in 0 .. Start - 1 =>
                 R (I) in -(2 * Bound) .. (2 * Bound));
            pragma Loop_Invariant
              (for all I in Start .. N - 1 => R (I) in -Bound .. Bound);

            K_Idx := K_Idx - 1;
            --  zeta = -zetas[k]. Negation never overflows since zetas
            --  are in -(Q-1)/2 .. (Q-1)/2.
            Zeta := -NTT_Zetas.Zetas (K_Idx);

            for J in Start .. Start + Len - 1 loop
               pragma Loop_Invariant (J in Start .. Start + Len - 1);
               pragma Loop_Invariant (J + Len <= N - 1);
               pragma Loop_Invariant (Bound <= 128 * Reduce32_Bound);
               pragma Loop_Invariant (Bound >= Reduce32_Bound);
               --  Prior segments processed (loose).
               pragma Loop_Invariant
                 (for all I in 0 .. Start - 1 =>
                    R (I) in -(2 * Bound) .. (2 * Bound));
               --  Low half processed in current segment (loose).
               pragma Loop_Invariant
                 (for all I in Start .. J - 1 =>
                    R (I) in -(2 * Bound) .. (2 * Bound));
               --  High half processed in current segment (Q-tight,
               --  fits the loose envelope).
               pragma Loop_Invariant
                 (for all I in Start + Len .. J + Len - 1 =>
                    R (I) in -(Q - 1) .. (Q - 1));
               --  Low half pending (tight).
               pragma Loop_Invariant
                 (for all I in J .. Start + Len - 1 =>
                    R (I) in -Bound .. Bound);
               --  High half pending (tight).
               pragma Loop_Invariant
                 (for all I in J + Len .. Start + 2 * Len - 1 =>
                    R (I) in -Bound .. Bound);
               --  Subsequent segments untouched (tight).
               pragma Loop_Invariant
                 (for all I in Start + 2 * Len .. N - 1 =>
                    R (I) in -Bound .. Bound);

               T := R (J);
               U := R (J + Len);
               --  T, U at currently-pending positions: in -Bound..Bound.
               --  T+U, T-U <= 2*Bound fit I32 since 2*128*R32_B
               --  = 256 * R32_B ~ 1.6e9 < 2^31.
               R (J) := T + U;
               R (J + Len) := T - U;

               Mul := I64 (Zeta) * I64 (R (J + Len));
               --  |Zeta| <= (Q-1)/2; |R(j+len)| <= 2*Bound.
               --  Product bound (Q-1)/2 * 2*Bound = (Q-1)*Bound
               --  <= (Q-1) * 128 * R32_B ~ 1.07e15 < Q*2^31 ~ 1.8e16.
               R (J + Len) := Reduce.Montgomery_Reduce (Mul);
            end loop;

            Start := Start + 2 * Len;
         end loop;

         Len := Len * 2;
         Bound := 2 * Bound;
      end loop;

      --  At this point: all positions bounded by 256 * Reduce32_Bound
      --  < 2^31. The final f-multiply with Mont reduce brings each
      --  coefficient into (-Q, Q).
      pragma Assert (Bound = 256 * Reduce32_Bound);
      for J in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all I in 0 .. J - 1 => R (I) in -(Q - 1) .. (Q - 1));
         pragma Loop_Invariant
           (for all I in J .. N - 1 =>
              R (I) in -(256 * Reduce32_Bound) .. (256 * Reduce32_Bound));

         Mul := I64 (F_InvNTT) * I64 (R (J));
         --  |F_InvNTT * R(J)| <= 41978 * 256 * R32_B ~ 6.7e13
         --  < Q*2^31 ~ 1.8e16.
         R (J) := Reduce.Montgomery_Reduce (Mul);
      end loop;
   end InvNTT_ToMont;

   ----------------------------------------------------------------------
   --  Pointwise multiply in NTT domain (each coefficient is independent).
   ----------------------------------------------------------------------
   procedure Pointwise_Montgomery
     (R    : out Polynomial;
      A, B : Polynomial)
   is
      Mul : I64;
   begin
      R := [others => 0];
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => R (J) in -(Q - 1) .. (Q - 1));

         Mul := I64 (A (I)) * I64 (B (I));
         --  |A(I)|, |B(I)| <= NTT_Output_Bound; product magnitude
         --  <= NTT_Output_Bound^2 < (Q-1)/2 * NTT_Output_Bound (since
         --  NTT_Output_Bound < (Q-1)/2). So MR precondition holds.
         R (I) := Reduce.Montgomery_Reduce (Mul);
      end loop;
   end Pointwise_Montgomery;

end ML_DSA.NTT;
