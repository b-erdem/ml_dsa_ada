with Ada.Text_IO;
with ML_DSA;
with ML_DSA.Reduce;
with ML_DSA.Rounding;
with ML_DSA.NTT;
with ML_DSA.Sign;

procedure Test_ML_DSA is

   use Ada.Text_IO;
   use type ML_DSA.I32;
   use type ML_DSA.U8;
   use type ML_DSA.Byte_Array;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   procedure Check (Name : String; Condition : Boolean) is
   begin
      if Condition then
         Pass_Count := Pass_Count + 1;
         Put_Line ("  PASS: " & Name);
      else
         Put_Line ("  FAIL: " & Name);
         Fail_Count := Fail_Count + 1;
      end if;
   end Check;

begin
   Put_Line ("=== ML-DSA basic test suite ===");
   Put_Line ("");

   ----------------------------------------------------------------------
   --  Reduce module
   ----------------------------------------------------------------------
   Put_Line ("Reduce:");
   declare
      V : ML_DSA.I32;
   begin
      V := ML_DSA.Reduce.Reduce32 (0);
      Check ("Reduce32(0) = 0", V = 0);

      V := ML_DSA.Reduce.Reduce32 (ML_DSA.Q);
      Check ("Reduce32(Q) = 0", V = 0);

      V := ML_DSA.Reduce.Reduce32 (1);
      Check ("Reduce32(1) = 1", V = 1);

      V := ML_DSA.Reduce.Reduce32 (-1);
      Check ("Reduce32(-1) = -1", V = -1);

      --  Montgomery_Reduce of 0 = 0.
      V := ML_DSA.Reduce.Montgomery_Reduce (0);
      Check ("Montgomery_Reduce(0) = 0", V = 0);

      --  CAddQ basic.
      V := ML_DSA.Reduce.CAddQ (0);
      Check ("CAddQ(0) = 0", V = 0);
      V := ML_DSA.Reduce.CAddQ (-1);
      Check ("CAddQ(-1) = Q-1", V = ML_DSA.Q - 1);
      V := ML_DSA.Reduce.CAddQ (ML_DSA.Q - 1);
      Check ("CAddQ(Q-1) = Q-1", V = ML_DSA.Q - 1);
   end;

   ----------------------------------------------------------------------
   --  Rounding module
   ----------------------------------------------------------------------
   Put_Line ("Rounding:");
   declare
      A0, A1 : ML_DSA.I32;
   begin
      ML_DSA.Rounding.Power2Round (A0, A1, 0);
      Check ("Power2Round(0) = (0, 0)", A0 = 0 and then A1 = 0);

      ML_DSA.Rounding.Power2Round (A0, A1, ML_DSA.Q - 1);
      --  Q-1 = 1023*8192 + (Q-1 - 1023*8192) = 1023*8192 + (Q-1 - 8380416)
      --  = 1023*8192 + (8380416 - 8380416) = 1023*8192. So a1=1023, a0=0.
      --  Wait: 1023 * 8192 = 8_380_416 = Q-1. Yes.
      Check ("Power2Round(Q-1).a1 = 1023", A1 = 1023);
      Check ("Power2Round(Q-1).a0 = 0", A0 = 0);

      ML_DSA.Rounding.Power2Round (A0, A1, 8192);
      --  8192 = 1*8192 + 0
      Check ("Power2Round(8192).a1 = 1", A1 = 1);
      Check ("Power2Round(8192).a0 = 0", A0 = 0);

      ML_DSA.Rounding.Power2Round (A0, A1, 8200);
      --  8200 = 1*8192 + 8
      Check ("Power2Round(8200).a1 = 1", A1 = 1);
      Check ("Power2Round(8200).a0 = 8", A0 = 8);

      --  Decompose round-trip via UseHint with hint=0.
      declare
         V : ML_DSA.I32;
      begin
         V := ML_DSA.Rounding.HighBits (12345);
         Check ("HighBits(12345) is in range",
                V in 0 .. ML_DSA.Rounding.Decompose_High_Max);
      end;
   end;

   ----------------------------------------------------------------------
   --  NTT round-trip on the zero polynomial
   ----------------------------------------------------------------------
   Put_Line ("NTT:");
   declare
      P : ML_DSA.Polynomial := [others => 0];
   begin
      ML_DSA.NTT.NTT (P);
      Check ("NTT(0) is all zeros",
             (for all I in 0 .. ML_DSA.N - 1 => P (I) = 0));
      ML_DSA.NTT.InvNTT_ToMont (P);
      Check ("InvNTT(NTT(0)) is all zeros",
             (for all I in 0 .. ML_DSA.N - 1 => P (I) = 0));
   end;

   ----------------------------------------------------------------------
   --  KeyGen / Sign / Verify roundtrip with deterministic seed.
   ----------------------------------------------------------------------
   Put_Line ("Sign / Verify:");
   declare
      Seed : constant ML_DSA.Byte_Array_32 := [others => 1];
      Rnd  : constant ML_DSA.Byte_Array_32 := [others => 0];  -- deterministic
      Msg  : constant ML_DSA.Byte_Array (0 .. 4) :=
        [Character'Pos ('h'), Character'Pos ('e'),
         Character'Pos ('l'), Character'Pos ('l'),
         Character'Pos ('o')];
      Ctx  : constant ML_DSA.Byte_Array (1 .. 0) := (others => 0);  -- empty

      PK   : ML_DSA.Byte_Array (0 .. ML_DSA.PK_Bytes - 1);
      SK   : ML_DSA.Byte_Array (0 .. ML_DSA.SK_Bytes - 1);
      Sig  : ML_DSA.Byte_Array (0 .. ML_DSA.Sig_Bytes - 1);
      Sign_Ok : Boolean;
   begin
      ML_DSA.Sign.KeyGen (PK, SK, Seed);
      Put_Line ("  KeyGen produced " & Natural'Image (PK'Length)
                & "-byte PK, " & Natural'Image (SK'Length) & "-byte SK");

      ML_DSA.Sign.Sign (Sig, Sign_Ok, Msg, Ctx, Rnd, SK);
      Check ("Sign returned ok", Sign_Ok);

      Check ("Verify(sig, msg, pk) = true",
             ML_DSA.Sign.Verify (Sig, Msg, Ctx, PK));

      --  Verify with tampered message must fail.
      declare
         Tampered : ML_DSA.Byte_Array := Msg;
      begin
         Tampered (0) := Tampered (0) xor 1;
         Check ("Verify(sig, tampered_msg, pk) = false",
                not ML_DSA.Sign.Verify (Sig, Tampered, Ctx, PK));
      end;

      --  Verify with tampered signature must fail.
      declare
         Tampered : ML_DSA.Byte_Array := Sig;
      begin
         Tampered (0) := Tampered (0) xor 1;
         Check ("Verify(tampered_sig, msg, pk) = false",
                not ML_DSA.Sign.Verify (Tampered, Msg, Ctx, PK));
      end;

      --  Sign_With_Self_Verify happy path: matching pk/sk -> succeeds.
      declare
         Sig2 : ML_DSA.Byte_Array (0 .. ML_DSA.Sig_Bytes - 1);
         Ok2  : Boolean;
      begin
         ML_DSA.Sign.Sign_With_Self_Verify (Sig2, Ok2, Msg, Ctx, Rnd, SK, PK);
         Check ("Sign_With_Self_Verify returned ok", Ok2);
         Check ("Sig2 verifies", ML_DSA.Sign.Verify (Sig2, Msg, Ctx, PK));
      end;

      --  Sign_With_Self_Verify with mismatched pk -> rejects (simulates
      --  a fault that produced a wrong signature).
      declare
         Other_Seed : ML_DSA.Byte_Array_32 := [others => 16#FE#];
         Other_PK   : ML_DSA.Byte_Array (0 .. ML_DSA.PK_Bytes - 1);
         Other_SK   : ML_DSA.Byte_Array (0 .. ML_DSA.SK_Bytes - 1);
         Sig3       : ML_DSA.Byte_Array (0 .. ML_DSA.Sig_Bytes - 1);
         Ok3        : Boolean;
      begin
         ML_DSA.Sign.KeyGen (Other_PK, Other_SK, Other_Seed);
         --  Sign with SK but verify against unrelated PK.
         ML_DSA.Sign.Sign_With_Self_Verify (Sig3, Ok3, Msg, Ctx, Rnd,
                                             SK, Other_PK);
         Check ("Sign_With_Self_Verify rejects pk/sk mismatch", not Ok3);
      end;
   end;

   ----------------------------------------------------------------------
   --  Summary
   ----------------------------------------------------------------------
   Put_Line ("");
   Put_Line ("Summary: " & Natural'Image (Pass_Count) & " passed, "
             & Natural'Image (Fail_Count) & " failed");
   if Fail_Count > 0 then
      Put_Line ("FAILED");
      raise Program_Error;
   end if;
end Test_ML_DSA;
