with SHA3;

--  Thin wrappers around sha3_ada's SHAKE128 / SHAKE256 / SHA3 primitives
--  so that ML-DSA modules can use ML_DSA byte arrays without juggling
--  package conversions everywhere.
package ML_DSA.Symmetric is

   pragma Pure;
   pragma SPARK_Mode;

   XOF128_Rate : constant := 168;  -- SHAKE128 block size
   XOF256_Rate : constant := 136;  -- SHAKE256 block size

   --  One-shot SHAKE256 for arbitrary input/output lengths.
   procedure SHAKE256
     (Data   : Byte_Array;
      Result : out Byte_Array)
     with Always_Terminates => True,
          Pre  => Data'First >= 0
                  and then Data'Last < Natural'Last
                  and then Result'First >= 0
                  and then Result'Last < Natural'Last;

   --  One-shot SHAKE128.
   procedure SHAKE128
     (Data   : Byte_Array;
      Result : out Byte_Array)
     with Always_Terminates => True,
          Pre  => Data'First >= 0
                  and then Data'Last < Natural'Last
                  and then Result'First >= 0
                  and then Result'Last < Natural'Last;

   ----------------------------------------------------------------------
   --  Streaming XOF (matrix expansion / per-poly sampling).
   --
   --  Use Init -> Absorb -> Squeeze (possibly multiple Squeezes).
   ----------------------------------------------------------------------

   procedure XOF128_Init_Absorb
     (S    : out SHA3.Sponge_State;
      Seed : Byte_Array_32;
      Nonce_Hi : U8;
      Nonce_Lo : U8)
     with Always_Terminates => True,
          Post => S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then S.Rate = XOF128_Rate;

   procedure XOF128_Squeeze
     (S      : in out SHA3.Sponge_State;
      Result : out Byte_Array)
     with Always_Terminates => True,
          Pre  => Result'First >= 0
                  and then Result'Last < Natural'Last
                  and then S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes,
          Post => S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then S.Rate = S.Rate'Old;

   procedure XOF256_Init_Absorb
     (S    : out SHA3.Sponge_State;
      Seed : Byte_Array_64;
      Nonce_Hi : U8;
      Nonce_Lo : U8)
     with Always_Terminates => True,
          Post => S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then S.Rate = XOF256_Rate;

   procedure XOF256_Squeeze
     (S      : in out SHA3.Sponge_State;
      Result : out Byte_Array)
     with Always_Terminates => True,
          Pre  => Result'First >= 0
                  and then Result'Last < Natural'Last
                  and then S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes,
          Post => S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then S.Rate = S.Rate'Old;

   --  General-purpose multi-chunk SHAKE256 (used for mu, rhoprime,
   --  c~ tilde, and the seed expansion in keygen).
   procedure SHAKE256_Init (S : out SHA3.Sponge_State)
     with Always_Terminates => True,
          Post => S.Byte_Pos = 0
                  and then S.Rate = XOF256_Rate
                  and then S.Domain = SHA3.SHAKE_Domain
                  and then not S.Squeezing;

   procedure SHAKE256_Absorb
     (S    : in out SHA3.Sponge_State;
      Data : Byte_Array)
     with Always_Terminates => True,
          Pre  => not S.Squeezing
                  and then S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then Data'First >= 0
                  and then Data'Last < Natural'Last,
          Post => not S.Squeezing
                  and then S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then S.Rate = S.Rate'Old;

   procedure SHAKE256_Squeeze
     (S      : in out SHA3.Sponge_State;
      Result : out Byte_Array)
     with Always_Terminates => True,
          Pre  => Result'First >= 0
                  and then Result'Last < Natural'Last
                  and then S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes,
          Post => S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then S.Rate = S.Rate'Old;

end ML_DSA.Symmetric;
