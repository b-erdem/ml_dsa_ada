with Interfaces;
with Ml_Dsa_Ada_Config;

--  ML-DSA (FIPS 204) — Module-Lattice-Based Digital Signature Algorithm.
--  Top-level types and parameter-set-specific constants.
--
--  All three FIPS 204 parameter sets are supported and selected at
--  build time via the `parameter_set` Alire crate configuration
--  variable; default is ML-DSA-65 (NIST Category III).
--
--    ML-DSA-44 : K=4, L=4, eta=2, tau=39, gamma1=2^17, gamma2=(Q-1)/88
--    ML-DSA-65 : K=6, L=5, eta=4, tau=49, gamma1=2^19, gamma2=(Q-1)/32
--    ML-DSA-87 : K=8, L=7, eta=2, tau=60, gamma1=2^19, gamma2=(Q-1)/32
package ML_DSA is

   pragma Pure;
   pragma SPARK_Mode;

   use type Ml_Dsa_Ada_Config.Parameter_Set_Kind;

   --  Suppress "use clause has no effect" warnings: the use clauses
   --  ARE used by every package that withs us (operators on I32,
   --  shift functions on U32, etc.), but at this declaration point
   --  GNAT can't see the downstream usage and warns. The clauses
   --  are functionally required.
   pragma Warnings (Off, "use clause for type * has no effect");
   use type Interfaces.Integer_16;
   use type Interfaces.Integer_32;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   pragma Warnings (On, "use clause for type * has no effect");

   subtype I16 is Interfaces.Integer_16;
   subtype I32 is Interfaces.Integer_32;
   subtype I64 is Interfaces.Integer_64;
   subtype U8  is Interfaces.Unsigned_8;
   subtype U16 is Interfaces.Unsigned_16;
   subtype U32 is Interfaces.Unsigned_32;
   subtype U64 is Interfaces.Unsigned_64;

   --  ML-DSA prime modulus: q = 2^23 - 2^13 + 1 = 8 380 417.
   --  Coefficients fit in I32 with plenty of headroom.
   Q : constant := 8_380_417;
   N : constant := 256;
   D : constant := 13;  -- Power2Round split bit count

   --  Montgomery reduction parameters (matching pq-crystals/dilithium).
   --  Q_Inv = -q^{-1} mod 2^32 = -58_728_449.
   Q_Inv_Neg : constant := 58_728_449;
   --  Mont = 2^32 mod Q (Montgomery one).
   Mont      : constant := 4_193_792;

   ----------------------------------------------------------------------
   --  Core type: a single polynomial in R_q = Z_q[X]/(X^256+1).
   --
   --  Coefficients are stored as signed 32-bit integers ranging widely
   --  during NTT and Montgomery accumulation. The exact valid range is
   --  context-dependent and tracked by per-call preconditions.
   ----------------------------------------------------------------------
   type Polynomial is array (0 .. N - 1) of I32;
   type Byte_Array is array (Natural range <>) of U8;

   subtype Byte_Array_32  is Byte_Array (0 .. 31);
   subtype Byte_Array_48  is Byte_Array (0 .. 47);
   subtype Byte_Array_64  is Byte_Array (0 .. 63);
   subtype Byte_Array_128 is Byte_Array (0 .. 127);

   ----------------------------------------------------------------------
   --  Coefficient ranges that arise repeatedly. Used in pre/postconditions
   --  for the field-arithmetic and rounding modules.
   ----------------------------------------------------------------------

   --  After Reduce32: |coeff| <= 2^22 + 256 * (2^23 - Q) for any I32
   --  input. The dilithium reference cites |coeff| < 6_283_009 under
   --  the tighter precondition |a| <= 2^31 - 2^22 - 1; we use the
   --  slightly wider 6_291_200 = 2^22 + 256 * 8191 so the bound holds
   --  for every I32 input without precondition. The difference is
   --  8191 ~ 2^13.
   Reduce32_Bound : constant := 6_291_200;

   --  After caddq (conditional add Q): coefficient in [0, Q-1].
   subtype Coeff_Standard is I32 range 0 .. Q - 1;

   --  After Montgomery reduce of 64-bit input: in (-Q, Q).
   subtype Coeff_Mont is I32 range -(Q - 1) .. (Q - 1);

   ----------------------------------------------------------------------
   --  Parameter-set-specific constants, derived at compile time from
   --  the Alire configuration enum.
   ----------------------------------------------------------------------

   ML_DSA_K     : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 4,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 6,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 8);

   ML_DSA_L     : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 4,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 5,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 7);

   ML_DSA_Eta   : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 2,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 4,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 2);

   ML_DSA_Tau   : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 39,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 49,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 60);

   ML_DSA_Beta  : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 78,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 196,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 120);

   --  Gamma1 selects the masking range. y has coefficients in
   --  (-Gamma1, Gamma1].
   ML_DSA_Gamma1_Bits : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 17,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 19,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 19);

   ML_DSA_Gamma1 : constant := 2 ** ML_DSA_Gamma1_Bits;

   --  Gamma2 selects the Decompose granularity. Two variants:
   --   - ML-DSA-44: gamma2 = (Q-1)/88 = 95_232
   --   - ML-DSA-65, ML-DSA-87: gamma2 = (Q-1)/32 = 261_888
   ML_DSA_Gamma2 : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => (Q - 1) / 88,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => (Q - 1) / 32,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => (Q - 1) / 32);

   --  Maximum total number of hint bits (size of h) the verifier will
   --  accept. Signing rejects when more hints than Omega are needed.
   ML_DSA_Omega : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 80,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 55,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 75);

   --  Length of c~ (the challenge hash) and the commitment hash mu in
   --  bytes. (FIPS 204 Lambda parameter.) Tied to NIST security level.
   C_Tilde_Bytes : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 32,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 48,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 64);

   --  Symmetric byte sizes. Seeds: rho/key/tr/rnd are 32 bytes;
   --  rhoprime is 64 bytes (CRH output).
   Seed_Bytes      : constant := 32;
   CRH_Bytes       : constant := 64;
   Tr_Bytes        : constant := 64;
   Rnd_Bytes       : constant := 32;

   --  Per-poly packed sizes:
   --    t1 : 10 bits/coeff -> 320 bytes
   --    t0 : 13 bits/coeff -> 416 bytes
   --    eta=2: 3 bits/coeff -> 96 bytes
   --    eta=4: 4 bits/coeff -> 128 bytes
   --    z (gamma1=2^17): 18 bits/coeff -> 576 bytes
   --    z (gamma1=2^19): 20 bits/coeff -> 640 bytes
   --    w1 (gamma2=(Q-1)/88): 6 bits/coeff -> 192 bytes
   --    w1 (gamma2=(Q-1)/32): 4 bits/coeff -> 128 bytes
   Poly_T1_Packed_Bytes : constant := 320;
   Poly_T0_Packed_Bytes : constant := 416;
   Poly_Eta_Packed_Bytes : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 96,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 128,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 96);
   Poly_Z_Packed_Bytes  : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 576,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 640,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 640);
   Poly_W1_Packed_Bytes : constant := (case Ml_Dsa_Ada_Config.Parameter_Set is
     when Ml_Dsa_Ada_Config.Ml_Dsa_44 => 192,
     when Ml_Dsa_Ada_Config.Ml_Dsa_65 => 128,
     when Ml_Dsa_Ada_Config.Ml_Dsa_87 => 128);

   --  FIPS 204 public key: rho || t1 (packed).
   PK_Bytes : constant :=
     Seed_Bytes + ML_DSA_K * Poly_T1_Packed_Bytes;

   --  FIPS 204 secret key: rho || key || tr || s1 || s2 || t0.
   SK_Bytes : constant :=
     Seed_Bytes + Seed_Bytes + Tr_Bytes
     + ML_DSA_L * Poly_Eta_Packed_Bytes
     + ML_DSA_K * Poly_Eta_Packed_Bytes
     + ML_DSA_K * Poly_T0_Packed_Bytes;

   --  Hint vector size in bytes: omega + K (FIPS 204 Algorithm 21).
   Hint_Bytes : constant := ML_DSA_Omega + ML_DSA_K;

   --  Signature: c~ || z || h.
   Sig_Bytes : constant :=
     C_Tilde_Bytes + ML_DSA_L * Poly_Z_Packed_Bytes + Hint_Bytes;

   ----------------------------------------------------------------------
   --  Polynomial vector / matrix types.
   --  Note: ML-DSA matrix A is K×L (NOT square as in ML-KEM).
   --  L = number of secret-key polynomials in s1 / mask y / response z
   --  K = number of public-key polynomials in s2 / commitment t / w
   ----------------------------------------------------------------------
   type Poly_Vector_K is array (0 .. ML_DSA_K - 1) of Polynomial;
   type Poly_Vector_L is array (0 .. ML_DSA_L - 1) of Polynomial;
   type Poly_Matrix_KL is array (0 .. ML_DSA_K - 1) of Poly_Vector_L;

end ML_DSA;
