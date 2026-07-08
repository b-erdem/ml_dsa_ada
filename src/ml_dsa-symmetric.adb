package body ML_DSA.Symmetric is
   pragma SPARK_Mode (On);

   --  Helper: copy ML_DSA.Byte_Array into SHA3.Byte_Array element-by-element
   --  (the two types are structurally identical but Ada distinguishes them).
   function To_SHA3 (A : Byte_Array) return SHA3.Byte_Array
     with Post => To_SHA3'Result'First = A'First
                  and then To_SHA3'Result'Last = A'Last
   is
      R : SHA3.Byte_Array (A'Range) := [others => 0];
   begin
      for I in A'Range loop
         pragma Loop_Invariant
           (for all J in A'First .. I - 1 => R (J) = SHA3.U8 (A (J)));
         R (I) := SHA3.U8 (A (I));
      end loop;
      return R;
   end To_SHA3;

   procedure From_SHA3 (Src : SHA3.Byte_Array; Dst : out Byte_Array)
     with Pre  => Src'First = Dst'First
                  and then Src'Last = Dst'Last
   is
   begin
      Dst := [others => 0];
      for I in Dst'Range loop
         pragma Loop_Invariant
           (for all J in Dst'First .. I - 1 => Dst (J) = U8 (Src (J)));
         Dst (I) := U8 (Src (I));
      end loop;
   end From_SHA3;

   ----------------------------------------------------------------------
   --  One-shot SHAKE
   ----------------------------------------------------------------------

   procedure SHAKE256
     (Data   : Byte_Array;
      Result : out Byte_Array)
   is
      S_Result : SHA3.Byte_Array (Result'Range);
   begin
      SHA3.SHAKE256 (To_SHA3 (Data), S_Result);
      From_SHA3 (S_Result, Result);
   end SHAKE256;

   procedure SHAKE128
     (Data   : Byte_Array;
      Result : out Byte_Array)
   is
      S_Result : SHA3.Byte_Array (Result'Range);
   begin
      SHA3.SHAKE128 (To_SHA3 (Data), S_Result);
      From_SHA3 (S_Result, Result);
   end SHAKE128;

   ----------------------------------------------------------------------
   --  Streaming XOFs
   ----------------------------------------------------------------------

   procedure XOF128_Init_Absorb
     (S    : out SHA3.Sponge_State;
      Seed : Byte_Array_32;
      Nonce_Hi : U8;
      Nonce_Lo : U8)
   is
      Data : SHA3.Byte_Array (0 .. 33) := [others => 0];
   begin
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => Data (J) = SHA3.U8 (Seed (J)));
         Data (I) := SHA3.U8 (Seed (I));
      end loop;
      Data (32) := SHA3.U8 (Nonce_Lo);
      Data (33) := SHA3.U8 (Nonce_Hi);
      SHA3.Init (S, SHA3.SHAKE128_Rate, SHA3.SHAKE_Domain);
      SHA3.Absorb (S, Data);
   end XOF128_Init_Absorb;

   procedure XOF128_Squeeze
     (S      : in out SHA3.Sponge_State;
      Result : out Byte_Array)
   is
      S_Result : SHA3.Byte_Array (Result'Range);
   begin
      SHA3.Squeeze (S, S_Result);
      From_SHA3 (S_Result, Result);
   end XOF128_Squeeze;

   procedure XOF256_Init_Absorb
     (S    : out SHA3.Sponge_State;
      Seed : Byte_Array_64;
      Nonce_Hi : U8;
      Nonce_Lo : U8)
   is
      Data : SHA3.Byte_Array (0 .. 65) := [others => 0];
   begin
      for I in 0 .. 63 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => Data (J) = SHA3.U8 (Seed (J)));
         Data (I) := SHA3.U8 (Seed (I));
      end loop;
      Data (64) := SHA3.U8 (Nonce_Lo);
      Data (65) := SHA3.U8 (Nonce_Hi);
      SHA3.Init (S, SHA3.SHAKE256_Rate, SHA3.SHAKE_Domain);
      SHA3.Absorb (S, Data);
   end XOF256_Init_Absorb;

   procedure XOF256_Squeeze
     (S      : in out SHA3.Sponge_State;
      Result : out Byte_Array)
   is
      S_Result : SHA3.Byte_Array (Result'Range);
   begin
      SHA3.Squeeze (S, S_Result);
      From_SHA3 (S_Result, Result);
   end XOF256_Squeeze;

   ----------------------------------------------------------------------
   --  Multi-chunk SHAKE256 (for variable-input absorb chains)
   ----------------------------------------------------------------------

   procedure SHAKE256_Init (S : out SHA3.Sponge_State) is
   begin
      SHA3.Init (S, SHA3.SHAKE256_Rate, SHA3.SHAKE_Domain);
   end SHAKE256_Init;

   procedure SHAKE256_Absorb
     (S    : in out SHA3.Sponge_State;
      Data : Byte_Array)
   is
   begin
      SHA3.Absorb (S, To_SHA3 (Data));
   end SHAKE256_Absorb;

   procedure SHAKE256_Squeeze
     (S      : in out SHA3.Sponge_State;
      Result : out Byte_Array)
   is
      S_Result : SHA3.Byte_Array (Result'Range);
   begin
      SHA3.Squeeze (S, S_Result);
      From_SHA3 (S_Result, Result);
   end SHAKE256_Squeeze;

end ML_DSA.Symmetric;
