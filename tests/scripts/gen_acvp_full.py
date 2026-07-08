#!/usr/bin/env python3
"""Generate the Ada test program test_acvp_full.adb for the active
ML-DSA parameter set, embedding every NIST ACVP test vector for
KeyGen, SigGen (external/pure/deterministic), and SigVer (external/
pure).

Usage:
    python3 gen_acvp_full.py [44|65|87] [out.adb]

The active set is auto-detected from
config/ml_dsa_ada_config.ads if no argument is given.

Source JSON (cached under /tmp on first run, fetched if missing):
    https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/
        gen-val/json-files/ML-DSA-keyGen-FIPS204/...
        gen-val/json-files/ML-DSA-sigGen-FIPS204/...
        gen-val/json-files/ML-DSA-sigVer-FIPS204/...
"""

import hashlib
import json
import os
import re
import subprocess
import sys

ACVP_BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
             "master/gen-val/json-files")
ACVP_FILES = {
    'keygen_prompt':   'ML-DSA-keyGen-FIPS204/prompt.json',
    'keygen_expected': 'ML-DSA-keyGen-FIPS204/expectedResults.json',
    'siggen_prompt':   'ML-DSA-sigGen-FIPS204/prompt.json',
    'siggen_expected': 'ML-DSA-sigGen-FIPS204/expectedResults.json',
    'sigver_prompt':   'ML-DSA-sigVer-FIPS204/prompt.json',
    'sigver_expected': 'ML-DSA-sigVer-FIPS204/expectedResults.json',
}


def fetch_json(label, path):
    target = f'/tmp/ml_dsa_{label}.json'
    if not os.path.exists(target):
        url = f'{ACVP_BASE}/{path}'
        print(f"Fetching {url} -> {target}")
        subprocess.check_call(['curl', '-sL', '-o', target, url])
    return json.load(open(target))


def detect_active_set(config_path):
    if not os.path.exists(config_path):
        return 'ML-DSA-65'
    with open(config_path) as f:
        text = f.read()
    m = re.search(r'parameter_set : constant parameter_set_Kind := (ML_DSA_\d+)',
                  text)
    if not m:
        return 'ML-DSA-65'
    return m.group(1).replace('ML_DSA_', 'ML-DSA-')


def hex_chunks_ada(hex_str):
    return [f"16#{hex_str[i:i + 2]}#" for i in range(0, len(hex_str), 2)]


def fmt_byte_array(name, hex_str, indent="      "):
    if not hex_str:
        return f"{indent}{name} : constant ML_DSA.Byte_Array (1 .. 0) := (others => 0);"
    n = len(hex_str) // 2
    chunks = hex_chunks_ada(hex_str)
    lines = [f"{indent}{name} : constant ML_DSA.Byte_Array (0 .. {n - 1}) :="]
    lines.append(f"{indent}  [")
    for i in range(0, len(chunks), 16):
        row = ", ".join(chunks[i:i + 16])
        if i + 16 < len(chunks):
            row += ","
        lines.append(f"{indent}     {row}")
    lines.append(f"{indent}  ];")
    return "\n".join(lines)


def fmt_hash32(name, hex_str, indent="      "):
    chunks = hex_chunks_ada(hex_str)
    assert len(chunks) == 32, f"want 32 bytes, got {len(chunks)}"
    lines = [f"{indent}{name} : constant ML_DSA.Byte_Array_32 :="]
    lines.append(f"{indent}  [")
    for i in range(0, 32, 8):
        row = ", ".join(chunks[i:i + 8])
        if i + 8 < 32:
            row += ","
        lines.append(f"{indent}     {row}")
    lines.append(f"{indent}  ];")
    return "\n".join(lines)


def gen_keygen_block(tcId, seed_hex, pk_hex, sk_hex):
    pk_h = hashlib.sha3_256(bytes.fromhex(pk_hex)).hexdigest().upper()
    sk_h = hashlib.sha3_256(bytes.fromhex(sk_hex)).hexdigest().upper()
    out = []
    out.append(f"   declare  --  KeyGen tcId {tcId}")
    out.append(fmt_hash32("Seed", seed_hex))
    out.append(fmt_hash32("PK_Want", pk_h))
    out.append(fmt_hash32("SK_Want", sk_h))
    out.append("   begin")
    out.append("      ML_DSA.Sign.KeyGen (PK_Buf, SK_Buf, Seed);")
    out.append("      Hash_Bytes (PK_Buf, PK_H);")
    out.append("      Hash_Bytes (SK_Buf, SK_H);")
    out.append("      if Match (PK_H, PK_Want) and then Match (SK_H, SK_Want) then")
    out.append("         Pass_Count := Pass_Count + 1;")
    out.append("      else")
    out.append("         Fail_Count := Fail_Count + 1;")
    out.append(f'         Put_Line ("  FAIL keyGen tcId {tcId}");')
    out.append("      end if;")
    out.append("   end;")
    return "\n".join(out)


def gen_siggen_block(tcId, sk_hex, msg_hex, ctx_hex, sig_hash):
    out = []
    out.append(f"   declare  --  SigGen tcId {tcId}")
    out.append(fmt_byte_array("Sk_C", sk_hex))
    out.append(fmt_byte_array("Msg_C", msg_hex))
    if ctx_hex:
        out.append(fmt_byte_array("Ctx_C", ctx_hex))
    else:
        out.append("      Ctx_C : constant ML_DSA.Byte_Array (1 .. 0) := (others => 0);")
    out.append(fmt_hash32("Sig_Want", sig_hash))
    out.append("      Sig_H_Got : ML_DSA.Byte_Array_32;")
    out.append("      Ok        : Boolean;")
    out.append("   begin")
    out.append("      ML_DSA.Sign.Sign (Sig_Buf, Ok, Msg_C, Ctx_C, Rnd_Zero, Sk_C);")
    out.append("      Hash_Bytes (Sig_Buf, Sig_H_Got);")
    out.append("      if Ok and then Match (Sig_H_Got, Sig_Want) then")
    out.append("         Pass_Count := Pass_Count + 1;")
    out.append("      else")
    out.append("         Fail_Count := Fail_Count + 1;")
    out.append(f'         Put_Line ("  FAIL sigGen tcId {tcId}");')
    out.append("      end if;")
    out.append("   end;")
    return "\n".join(out)


def gen_sigver_block(tcId, pk_hex, msg_hex, ctx_hex, sig_hex, expected_pass):
    out = []
    label = 'PASS' if expected_pass else 'REJECT'
    out.append(f"   declare  --  SigVer tcId {tcId} (expected: {label})")
    out.append(fmt_byte_array("Pk_C", pk_hex))
    out.append(fmt_byte_array("Msg_C", msg_hex))
    if ctx_hex:
        out.append(fmt_byte_array("Ctx_C", ctx_hex))
    else:
        out.append("      Ctx_C : constant ML_DSA.Byte_Array (1 .. 0) := (others => 0);")
    out.append(fmt_byte_array("Sig_C", sig_hex))
    out.append(f"      Want : constant Boolean := {'True' if expected_pass else 'False'};")
    out.append("      Got  : Boolean;")
    out.append("   begin")
    out.append("      Got := ML_DSA.Sign.Verify (Sig_C, Msg_C, Ctx_C, Pk_C);")
    out.append("      if Got = Want then")
    out.append("         Pass_Count := Pass_Count + 1;")
    out.append("      else")
    out.append("         Fail_Count := Fail_Count + 1;")
    out.append(f'         Put_Line ("  FAIL sigVer tcId {tcId} (got " &')
    out.append('                   Boolean\'Image (Got) & ", want " &')
    out.append('                   Boolean\'Image (Want) & ")");')
    out.append("      end if;")
    out.append("   end;")
    return "\n".join(out)


def gen_for_set(target_set):
    kg_p = fetch_json('keygen_prompt',   ACVP_FILES['keygen_prompt'])
    kg_e = fetch_json('keygen_expected', ACVP_FILES['keygen_expected'])
    sg_p = fetch_json('siggen_prompt',   ACVP_FILES['siggen_prompt'])
    sg_e = fetch_json('siggen_expected', ACVP_FILES['siggen_expected'])
    sv_p = fetch_json('sigver_prompt',   ACVP_FILES['sigver_prompt'])
    sv_e = fetch_json('sigver_expected', ACVP_FILES['sigver_expected'])

    kg_seeds = {}
    for tg in kg_p['testGroups']:
        if tg['parameterSet'] != target_set:
            continue
        for t in tg['tests']:
            kg_seeds[t['tcId']] = t['seed']
    kg_outputs = {}
    for tg in kg_e['testGroups']:
        for t in tg['tests']:
            if t['tcId'] in kg_seeds:
                kg_outputs[t['tcId']] = (t['pk'], t['sk'])

    sg_tests = []
    sg_exp = {t['tcId']: t['signature']
              for tg in sg_e['testGroups'] for t in tg['tests']}
    for tg in sg_p['testGroups']:
        if tg['parameterSet'] != target_set:
            continue
        if (tg.get('signatureInterface') != 'external'
                or tg.get('preHash') != 'pure'
                or tg.get('deterministic') is not True):
            continue
        for t in tg['tests']:
            sig = sg_exp[t['tcId']]
            sig_h = hashlib.sha3_256(bytes.fromhex(sig)).hexdigest().upper()
            sg_tests.append((t['tcId'], t['sk'], t['message'],
                             t.get('context', ''), sig_h))

    sv_tests = []
    sv_exp = {t['tcId']: t['testPassed']
              for tg in sv_e['testGroups'] for t in tg['tests']}
    for tg in sv_p['testGroups']:
        if tg['parameterSet'] != target_set:
            continue
        if (tg.get('signatureInterface') != 'external'
                or tg.get('preHash') != 'pure'):
            continue
        group_pk = tg.get('pk')
        for t in tg['tests']:
            pk = t.get('pk') or group_pk
            sv_tests.append((t['tcId'], pk, t['message'],
                             t.get('context', ''), t['signature'],
                             sv_exp[t['tcId']]))

    out = []
    out.append("with Ada.Text_IO;")
    out.append("with Ada.Command_Line;")
    out.append("with Interfaces;")
    out.append("with SHA3;")
    out.append("with ML_DSA;")
    out.append("with ML_DSA.Sign;")
    out.append("")
    out.append(f"--  Full NIST ACVP cross-validation for {target_set}.")
    out.append("--  KeyGen, SigGen (external/pure/det), SigVer (external/pure).")
    out.append("--  Vectors: github.com/usnistgov/ACVP-Server, gen-val/json-files/.")
    out.append("--  Generated by tests/scripts/gen_acvp_full.py — do not edit.")
    out.append("procedure Test_ACVP_Full is")
    out.append("")
    out.append("   use Ada.Text_IO;")
    out.append("   use type Interfaces.Unsigned_8;")
    out.append("   subtype U8 is Interfaces.Unsigned_8;")
    out.append("")
    out.append("   procedure Hash_Bytes (Data : ML_DSA.Byte_Array;")
    out.append("                          H    : out ML_DSA.Byte_Array_32) is")
    out.append("      D : SHA3.Byte_Array (Data'Range);")
    out.append("      R : SHA3.Byte_Array_32;")
    out.append("   begin")
    out.append("      for I in Data'Range loop")
    out.append("         D (I) := SHA3.U8 (Data (I));")
    out.append("      end loop;")
    out.append("      SHA3.SHA3_256 (D, R);")
    out.append("      for I in 0 .. 31 loop")
    out.append("         H (I) := U8 (R (I));")
    out.append("      end loop;")
    out.append("   end Hash_Bytes;")
    out.append("")
    out.append("   function Match (A, B : ML_DSA.Byte_Array_32) return Boolean is")
    out.append("   begin")
    out.append("      for I in 0 .. 31 loop")
    out.append("         if A (I) /= B (I) then return False; end if;")
    out.append("      end loop;")
    out.append("      return True;")
    out.append("   end Match;")
    out.append("")
    out.append("   PK_Buf  : ML_DSA.Byte_Array (0 .. ML_DSA.PK_Bytes - 1);")
    out.append("   SK_Buf  : ML_DSA.Byte_Array (0 .. ML_DSA.SK_Bytes - 1);")
    out.append("   Sig_Buf : ML_DSA.Byte_Array (0 .. ML_DSA.Sig_Bytes - 1);")
    out.append("   PK_H, SK_H : ML_DSA.Byte_Array_32;")
    out.append("   Rnd_Zero : constant ML_DSA.Byte_Array_32 := [others => 0];")
    out.append("")
    out.append("   Pass_Count, Fail_Count : Natural := 0;")
    out.append("")
    out.append("begin")
    out.append(f'   Put_Line ("=== ACVP cross-validation: {target_set} ===");')
    out.append("   New_Line;")
    out.append("")
    out.append(f'   Put_Line ("--- KeyGen ({len(kg_outputs)} tests) ---");')
    for tcId in sorted(kg_outputs):
        seed = kg_seeds[tcId]
        pk, sk = kg_outputs[tcId]
        out.append(gen_keygen_block(tcId, seed, pk, sk))
    out.append("")
    out.append("   New_Line;")
    out.append(
        f'   Put_Line ("--- SigGen external/pure/det ({len(sg_tests)} tests) ---");'
    )
    for tcId, sk, msg, ctx, sh in sg_tests:
        out.append(gen_siggen_block(tcId, sk, msg, ctx, sh))
    out.append("")
    out.append("   New_Line;")
    out.append(
        f'   Put_Line ("--- SigVer external/pure ({len(sv_tests)} tests) ---");'
    )
    for tcId, pk, msg, ctx, sig, expected in sv_tests:
        out.append(gen_sigver_block(tcId, pk, msg, ctx, sig, expected))
    out.append("")
    out.append("   New_Line;")
    out.append('   Put_Line ("Summary:" & Natural\'Image (Pass_Count) & " passed,"')
    out.append('             & Natural\'Image (Fail_Count) & " failed");')
    out.append("   if Fail_Count > 0 then")
    out.append("      Ada.Command_Line.Set_Exit_Status (1);")
    out.append("   end if;")
    out.append("end Test_ACVP_Full;")

    return "\n".join(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    config = os.path.normpath(os.path.join(here, '..', '..', 'config',
                                            'ml_dsa_ada_config.ads'))
    out_path = os.path.normpath(os.path.join(here, '..', 'src',
                                              'test_acvp_full.adb'))

    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg in ('44', '65', '87'):
            target = f'ML-DSA-{arg}'
        elif arg.startswith('ML-DSA-') or arg.startswith('ML_DSA_'):
            target = arg.replace('_', '-')
        else:
            sys.exit(f"unknown set: {arg}")
    else:
        target = detect_active_set(config)

    if len(sys.argv) > 2:
        out_path = sys.argv[2]

    text = gen_for_set(target)
    with open(out_path, 'w') as f:
        f.write(text)
    print(f"Wrote {out_path} ({text.count(chr(10)) + 1} lines, "
          f"target {target})")


if __name__ == '__main__':
    main()
