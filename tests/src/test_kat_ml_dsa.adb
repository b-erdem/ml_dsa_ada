with Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;
with SHA3;
with ML_DSA;
with ML_DSA.Sign;

--  Deterministic self-consistency KAT for ML-DSA.
--
--  This test runs KeyGen with a fixed seed, then signs a known message
--  with a fixed rnd, and compares SHA3-256 hashes of the public key,
--  secret key, and signature against pre-recorded values.
--
--  These hashes are *self-consistent* — they pin down our implementation's
--  byte-exact output to detect regressions, but they do NOT validate
--  against another FIPS 204 implementation. For interoperability proof,
--  cross-check against pq-crystals/dilithium with the same seed/rnd/msg.
--
--  Each parameter set has its own expected hashes; the test selects
--  based on the build-time `parameter_set` configuration.
--
--  Usage: ./test_kat_ml_dsa            -- run, expect pass
--         ./test_kat_ml_dsa --record   -- print actual hashes (for
--                                         updating the expected values
--                                         after intentional changes)
procedure Test_KAT_ML_DSA is

   use Ada.Text_IO;
   use type Interfaces.Unsigned_8;
   use type ML_DSA.Byte_Array;

   subtype U8 is Interfaces.Unsigned_8;

   --  Fixed deterministic inputs.
   Seed : constant ML_DSA.Byte_Array_32 :=
     [16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#,
      16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#, 16#10#,
      16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#, 16#18#,
      16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#, 16#20#];

   Rnd : constant ML_DSA.Byte_Array_32 := [others => 0];  -- deterministic mode

   Msg : constant ML_DSA.Byte_Array (0 .. 21) :=
     [16#54#, 16#68#, 16#65#, 16#20#,
      16#71#, 16#75#, 16#69#, 16#63#, 16#6B#, 16#20#,
      16#62#, 16#72#, 16#6F#, 16#77#, 16#6E#, 16#20#,
      16#66#, 16#6F#, 16#78#, 16#20#, 16#2E#, 16#2E#];

   Empty_Ctx : constant ML_DSA.Byte_Array (1 .. 0) := (others => 0);

   --  Pre-recorded SHA3-256 hashes of the PK, SK, and Sig for each
   --  parameter set, computed by running this test in --record mode.
   --
   --  ML-DSA-44: K=4, L=4, eta=2, gamma1=2^17
   --  ML-DSA-65: K=6, L=5, eta=4, gamma1=2^19  (default)
   --  ML-DSA-87: K=8, L=7, eta=2, gamma1=2^19

   Expected_PK_Hash_44 : constant ML_DSA.Byte_Array_32 :=
     [16#94#, 16#10#, 16#49#, 16#DA#, 16#6D#, 16#BF#, 16#B1#, 16#41#,
      16#F7#, 16#70#, 16#F0#, 16#75#, 16#F7#, 16#96#, 16#8F#, 16#24#,
      16#3C#, 16#D4#, 16#53#, 16#3E#, 16#97#, 16#19#, 16#F1#, 16#21#,
      16#BE#, 16#0E#, 16#B7#, 16#C5#, 16#F8#, 16#EE#, 16#76#, 16#45#];
   Expected_SK_Hash_44 : constant ML_DSA.Byte_Array_32 :=
     [16#A5#, 16#35#, 16#7B#, 16#17#, 16#36#, 16#76#, 16#6C#, 16#3E#,
      16#B5#, 16#F3#, 16#D9#, 16#19#, 16#85#, 16#4E#, 16#A8#, 16#92#,
      16#E5#, 16#B1#, 16#67#, 16#61#, 16#B8#, 16#BF#, 16#20#, 16#C9#,
      16#18#, 16#8F#, 16#F4#, 16#C6#, 16#C9#, 16#33#, 16#E9#, 16#A6#];
   Expected_Sig_Hash_44 : constant ML_DSA.Byte_Array_32 :=
     [16#98#, 16#AD#, 16#36#, 16#C7#, 16#0D#, 16#43#, 16#7C#, 16#83#,
      16#BC#, 16#F2#, 16#6B#, 16#4C#, 16#56#, 16#75#, 16#BF#, 16#91#,
      16#3E#, 16#60#, 16#85#, 16#65#, 16#D0#, 16#71#, 16#6A#, 16#A6#,
      16#1B#, 16#76#, 16#F1#, 16#B0#, 16#A0#, 16#67#, 16#7F#, 16#B9#];

   Expected_PK_Hash_65 : constant ML_DSA.Byte_Array_32 :=
     [16#2F#, 16#E3#, 16#C3#, 16#C8#, 16#E3#, 16#75#, 16#11#, 16#36#,
      16#EF#, 16#8D#, 16#17#, 16#16#, 16#6C#, 16#2E#, 16#7A#, 16#07#,
      16#32#, 16#B6#, 16#79#, 16#CA#, 16#76#, 16#D3#, 16#EC#, 16#2A#,
      16#06#, 16#32#, 16#CE#, 16#C5#, 16#4A#, 16#B5#, 16#8F#, 16#16#];
   Expected_SK_Hash_65 : constant ML_DSA.Byte_Array_32 :=
     [16#06#, 16#2B#, 16#20#, 16#74#, 16#65#, 16#6E#, 16#B9#, 16#67#,
      16#27#, 16#D9#, 16#46#, 16#24#, 16#F4#, 16#33#, 16#A4#, 16#2F#,
      16#FA#, 16#75#, 16#1F#, 16#8D#, 16#F9#, 16#55#, 16#27#, 16#74#,
      16#AC#, 16#DB#, 16#2C#, 16#58#, 16#C7#, 16#49#, 16#8D#, 16#98#];
   Expected_Sig_Hash_65 : constant ML_DSA.Byte_Array_32 :=
     [16#06#, 16#40#, 16#E7#, 16#68#, 16#E2#, 16#93#, 16#17#, 16#C5#,
      16#3C#, 16#50#, 16#CF#, 16#F8#, 16#48#, 16#BA#, 16#31#, 16#41#,
      16#F0#, 16#41#, 16#A0#, 16#38#, 16#9A#, 16#0E#, 16#11#, 16#D1#,
      16#D5#, 16#21#, 16#86#, 16#81#, 16#AD#, 16#11#, 16#0D#, 16#3F#];

   Expected_PK_Hash_87 : constant ML_DSA.Byte_Array_32 :=
     [16#72#, 16#91#, 16#42#, 16#BC#, 16#7A#, 16#44#, 16#38#, 16#80#,
      16#79#, 16#1A#, 16#F8#, 16#81#, 16#7A#, 16#2E#, 16#72#, 16#42#,
      16#BD#, 16#BB#, 16#13#, 16#3D#, 16#32#, 16#F4#, 16#D0#, 16#EF#,
      16#8E#, 16#7A#, 16#D1#, 16#09#, 16#B6#, 16#45#, 16#5E#, 16#F5#];
   Expected_SK_Hash_87 : constant ML_DSA.Byte_Array_32 :=
     [16#06#, 16#F6#, 16#55#, 16#24#, 16#59#, 16#71#, 16#4F#, 16#9E#,
      16#67#, 16#09#, 16#24#, 16#38#, 16#D5#, 16#C5#, 16#37#, 16#91#,
      16#7E#, 16#A8#, 16#9C#, 16#BD#, 16#2C#, 16#85#, 16#75#, 16#34#,
      16#20#, 16#A2#, 16#CD#, 16#42#, 16#19#, 16#E5#, 16#C1#, 16#C6#];
   Expected_Sig_Hash_87 : constant ML_DSA.Byte_Array_32 :=
     [16#38#, 16#C8#, 16#FF#, 16#3F#, 16#95#, 16#B7#, 16#9A#, 16#2A#,
      16#B5#, 16#7A#, 16#70#, 16#D1#, 16#FB#, 16#E5#, 16#3B#, 16#3F#,
      16#B7#, 16#AC#, 16#81#, 16#28#, 16#5F#, 16#80#, 16#BD#, 16#E9#,
      16#1D#, 16#BA#, 16#39#, 16#E6#, 16#DE#, 16#7B#, 16#06#, 16#DE#];

   procedure Hash_Bytes (Data : ML_DSA.Byte_Array; H : out ML_DSA.Byte_Array_32) is
      D : SHA3.Byte_Array (Data'Range);
      R : SHA3.Byte_Array_32;
   begin
      for I in Data'Range loop
         D (I) := SHA3.U8 (Data (I));
      end loop;
      SHA3.SHA3_256 (D, R);
      for I in 0 .. 31 loop
         H (I) := U8 (R (I));
      end loop;
   end Hash_Bytes;

   procedure Print_Hex (Label : String; Data : ML_DSA.Byte_Array_32) is
      Hex : constant String := "0123456789ABCDEF";
   begin
      Put (Label);
      Put (" = 16#");
      for I in 0 .. 31 loop
         Put (Hex (Integer (Data (I) / 16) + 1));
         Put (Hex (Integer (Data (I) mod 16) + 1));
      end loop;
      Put_Line ("#");
   end Print_Hex;

   function Match (A, B : ML_DSA.Byte_Array_32) return Boolean is
   begin
      for I in 0 .. 31 loop
         if A (I) /= B (I) then
            return False;
         end if;
      end loop;
      return True;
   end Match;

   PK   : ML_DSA.Byte_Array (0 .. ML_DSA.PK_Bytes - 1);
   SK   : ML_DSA.Byte_Array (0 .. ML_DSA.SK_Bytes - 1);
   Sig  : ML_DSA.Byte_Array (0 .. ML_DSA.Sig_Bytes - 1);
   PK_H, SK_H, Sig_H : ML_DSA.Byte_Array_32;
   Sign_Ok : Boolean;

   Record_Mode : Boolean := False;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   procedure Check (Name : String; Cond : Boolean) is
   begin
      if Cond then
         Pass_Count := Pass_Count + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail_Count := Fail_Count + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

begin
   for I in 1 .. Ada.Command_Line.Argument_Count loop
      if Ada.Command_Line.Argument (I) = "--record" then
         Record_Mode := True;
      end if;
   end loop;

   Put_Line ("=== ML-DSA self-consistency KAT ===");

   ML_DSA.Sign.KeyGen (PK, SK, Seed);
   ML_DSA.Sign.Sign (Sig, Sign_Ok, Msg, Empty_Ctx, Rnd, SK);

   Hash_Bytes (PK,  PK_H);
   Hash_Bytes (SK,  SK_H);
   Hash_Bytes (Sig, Sig_H);

   Check ("Sign succeeded",       Sign_Ok);
   Check ("Verify accepts sig",   ML_DSA.Sign.Verify (Sig, Msg, Empty_Ctx, PK));

   if Record_Mode then
      Put_Line ("");
      Put_Line ("Computed hashes (paste into Expected_*_Hash_* constants):");
      Print_Hex ("  PK_Hash ", PK_H);
      Print_Hex ("  SK_Hash ", SK_H);
      Print_Hex ("  Sig_Hash", Sig_H);
   else
      --  Compare against expected hashes for the active parameter set.
      --  We use the parameter-set-distinguishing PK byte length to
      --  branch.
      if PK'Length = 1312 then
         Check ("PK hash matches ML-DSA-44",  Match (PK_H,  Expected_PK_Hash_44));
         Check ("SK hash matches ML-DSA-44",  Match (SK_H,  Expected_SK_Hash_44));
         Check ("Sig hash matches ML-DSA-44", Match (Sig_H, Expected_Sig_Hash_44));
      elsif PK'Length = 1952 then
         Check ("PK hash matches ML-DSA-65",  Match (PK_H,  Expected_PK_Hash_65));
         Check ("SK hash matches ML-DSA-65",  Match (SK_H,  Expected_SK_Hash_65));
         Check ("Sig hash matches ML-DSA-65", Match (Sig_H, Expected_Sig_Hash_65));
      elsif PK'Length = 2592 then
         Check ("PK hash matches ML-DSA-87",  Match (PK_H,  Expected_PK_Hash_87));
         Check ("SK hash matches ML-DSA-87",  Match (SK_H,  Expected_SK_Hash_87));
         Check ("Sig hash matches ML-DSA-87", Match (Sig_H, Expected_Sig_Hash_87));
      else
         Put_Line ("  FAIL: unknown parameter set (PK size " &
                   Natural'Image (PK'Length) & ")");
         Fail_Count := Fail_Count + 1;
      end if;
   end if;

   Put_Line ("");
   Put_Line ("Summary: " & Natural'Image (Pass_Count) & " passed, "
             & Natural'Image (Fail_Count) & " failed");
   if Fail_Count > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_KAT_ML_DSA;
