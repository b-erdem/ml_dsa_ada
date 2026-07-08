--  ML-DSA top-level API: KeyGen, Sign, Verify (FIPS 204).
package ML_DSA.Sign is

   pragma Pure;
   pragma SPARK_Mode;

   --  Generate a key pair from a 32-byte seed (xi). The seed should
   --  come from a cryptographically secure RNG; passed in by the
   --  caller so this library has no entropy dependency.
   procedure KeyGen
     (PK   : out Byte_Array;
      SK   : out Byte_Array;
      Seed : Byte_Array_32)
     with Pre  => PK'First = 0
                  and then SK'First = 0
                  and then PK'Length = ML_DSA.PK_Bytes
                  and then SK'Length = ML_DSA.SK_Bytes;

   --  Sign a message. The "context" byte string ctx (max 255 bytes)
   --  is part of FIPS 204 §5.2; pass an empty slice for default ctx.
   --  The 32-byte rnd argument is the per-signature randomness for
   --  hedged signing; pass zeros for deterministic signing (matching
   --  FIPS 204 deterministic mode).
   procedure Sign
     (Sig : out Byte_Array;
      Ok  : out Boolean;
      M   : Byte_Array;
      Ctx : Byte_Array;
      Rnd : Byte_Array_32;
      SK  : Byte_Array)
     with Pre  => Sig'First = 0
                  and then SK'First = 0
                  and then Sig'Length = ML_DSA.Sig_Bytes
                  and then SK'Length = ML_DSA.SK_Bytes
                  and then M'First >= 0
                  and then M'Last < Natural'Last
                  and then Ctx'First >= 0
                  and then Ctx'Last < Natural'Last
                  and then Ctx'Length <= 255;

   --  Sign with self-verify: produce a signature and then immediately
   --  re-verify it against the corresponding public key. If
   --  verification fails (a transient fault may have corrupted the
   --  signing computation, e.g. via voltage glitching or particle
   --  strike), the output is zeroed and Ok is set to False.
   --
   --  The caller is responsible for providing a matching pk/sk pair
   --  (e.g. generated together via KeyGen). Cost: ~1.5x of a plain
   --  Sign, since Verify is roughly half the work of Sign.
   procedure Sign_With_Self_Verify
     (Sig : out Byte_Array;
      Ok  : out Boolean;
      M   : Byte_Array;
      Ctx : Byte_Array;
      Rnd : Byte_Array_32;
      SK  : Byte_Array;
      PK  : Byte_Array)
     with Pre  => Sig'First = 0
                  and then SK'First = 0
                  and then PK'First = 0
                  and then Sig'Length = ML_DSA.Sig_Bytes
                  and then SK'Length = ML_DSA.SK_Bytes
                  and then PK'Length = ML_DSA.PK_Bytes
                  and then M'First >= 0
                  and then M'Last < Natural'Last
                  and then Ctx'First >= 0
                  and then Ctx'Last < Natural'Last
                  and then Ctx'Length <= 255;

   --  Verify a signature.
   function Verify
     (Sig : Byte_Array;
      M   : Byte_Array;
      Ctx : Byte_Array;
      PK  : Byte_Array) return Boolean
     with Pre => Sig'First = 0
                 and then PK'First = 0
                 and then Sig'Length = ML_DSA.Sig_Bytes
                 and then PK'Length = ML_DSA.PK_Bytes
                 and then M'First >= 0
                 and then M'Last < Natural'Last
                 and then Ctx'First >= 0
                 and then Ctx'Last < Natural'Last
                 and then Ctx'Length <= 255;

end ML_DSA.Sign;
