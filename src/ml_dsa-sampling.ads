--  ML-DSA sampling: rejection-sampling primitives for the matrix A
--  expansion (rej_uniform), the secret vectors s1/s2 (rej_eta), the
--  masking vector y (uniform_gamma1 — bit unpacking, not rejection),
--  and the challenge polynomial c (sample_in_ball).
package ML_DSA.Sampling is

   pragma Pure;
   pragma SPARK_Mode;

   ----------------------------------------------------------------------
   --  rej_uniform: extract 23-bit values from `Buf`, accept those < Q.
   --
   --  Reads `Buf_Len` bytes total; advances `R_Len` (number of accepted
   --  coefficients written into `R`). May terminate early if `Buf` is
   --  exhausted; the caller is expected to top up the buffer and call
   --  again until R_Len = N.
   ----------------------------------------------------------------------
   procedure RejUniform
     (Buf     :     Byte_Array;
      Buf_Len :     Natural;
      R       : in out Polynomial;
      R_Len   : in out Natural)
     with Always_Terminates => True,
          Pre  => Buf'First = 0
                  and then Buf'Last < Natural'Last
                  and then Buf_Len <= Buf'Length
                  and then Buf_Len <= Natural'Last - 3
                  and then R_Len <= N
                  and then (for all I in 0 .. R_Len - 1 =>
                              R (I) in 0 .. Q - 1)
                  and then (for all I in R_Len .. N - 1 => R (I) = 0),
          Post => R_Len >= R_Len'Old
                  and then R_Len <= N
                  and then (for all I in 0 .. R_Len - 1 =>
                              R (I) in 0 .. Q - 1)
                  and then (for all I in R_Len .. N - 1 => R (I) = 0);

   ----------------------------------------------------------------------
   --  rej_eta: extract 4-bit values; reject those >= 15 (eta=2) or
   --  >= 9 (eta=4); map remaining values to {-eta..eta}.
   ----------------------------------------------------------------------
   procedure RejEta
     (Buf     :     Byte_Array;
      Buf_Len :     Natural;
      R       : in out Polynomial;
      R_Len   : in out Natural)
     with Always_Terminates => True,
          Pre  => Buf'First = 0
                  and then Buf'Last < Natural'Last
                  and then Buf_Len <= Buf'Length
                  and then R_Len <= N
                  and then (for all I in 0 .. R_Len - 1 =>
                              R (I) in -ML_DSA_Eta .. ML_DSA_Eta)
                  and then (for all I in R_Len .. N - 1 => R (I) = 0),
          Post => R_Len >= R_Len'Old
                  and then R_Len <= N
                  and then (for all I in 0 .. R_Len - 1 =>
                              R (I) in -ML_DSA_Eta .. ML_DSA_Eta)
                  and then (for all I in R_Len .. N - 1 => R (I) = 0);

   ----------------------------------------------------------------------
   --  poly_uniform: sample one polynomial with coefficients uniform in
   --  [0, Q-1] using SHAKE128 stream seeded by Seed and 16-bit Nonce.
   ----------------------------------------------------------------------
   procedure Poly_Uniform
     (R     : out Polynomial;
      Seed  : Byte_Array_32;
      Nonce : U16)
     with Always_Terminates => True,
          Post => (for all I in 0 .. N - 1 => R (I) in 0 .. Q - 1);

   ----------------------------------------------------------------------
   --  poly_uniform_eta: sample one polynomial with coefficients in
   --  [-eta, eta] using SHAKE256 seeded by Seed (64 bytes) and Nonce.
   ----------------------------------------------------------------------
   procedure Poly_Uniform_Eta
     (R     : out Polynomial;
      Seed  : Byte_Array_64;
      Nonce : U16)
     with Always_Terminates => True,
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -ML_DSA_Eta .. ML_DSA_Eta);

   ----------------------------------------------------------------------
   --  poly_uniform_gamma1: sample one polynomial with coefficients in
   --  (-Gamma1, Gamma1] (the masking vector y).  Implementation is bit
   --  unpacking with no rejection.
   ----------------------------------------------------------------------
   procedure Poly_Uniform_Gamma1
     (R     : out Polynomial;
      Seed  : Byte_Array_64;
      Nonce : U16)
     with Always_Terminates => True,
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -(ML_DSA_Gamma1 - 1) .. ML_DSA_Gamma1);

   ----------------------------------------------------------------------
   --  poly_challenge: sample the sparse ±1 polynomial c with exactly
   --  Tau nonzero coefficients from a c-tilde seed.
   ----------------------------------------------------------------------
   procedure Poly_Challenge
     (R    : out Polynomial;
      Seed : Byte_Array)
     with Always_Terminates => True,
          Pre  => Seed'First = 0
                  and then Seed'Length = C_Tilde_Bytes,
          Post => (for all I in 0 .. N - 1 => R (I) in -1 .. 1);

end ML_DSA.Sampling;
