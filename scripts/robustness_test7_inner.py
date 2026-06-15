#!/usr/bin/env python3
"""Test 7 (continued) — find the m_impl_vtable for the CDM_11 outer class in
Edge 150 widevinecdm.dll, enumerate its 19 inner bodies, classify each as
clean / obfuscated. Closes the obfuscation-distribution claim.

Strategy:
- Note 10 byte-confirmed slot 5's inner wrapper at RVA 0x1d4ab0 (the
  UpdateSession wrapper that calls into the obfuscated parser at 0x22e310).
- That means somewhere in .rdata there is a QWORD whose value is
  `image_base + 0x1d4ab0`, sitting at the slot-5 position of the m_impl
  vtable.
- Find every match, back up 5*8 bytes, validate by checking 19 consecutive
  QWORDs all point into .text, classify each.
"""
import struct, json, collections
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = "/home/trxnegro/redteam/projects/netflix-drm-bh2027"
DLL  = f"{ROOT}/binaries/widevinecdm-edge150.dll"
OUT  = f"{ROOT}/research-notes/13b-test7-inner-bodies.md"

SLOT5_INNER_RVA = 0x1d4ab0   # byte-confirmed in note 10
KNOWN_OBF_INNER = {3: 0x21f200}  # slot 3 inner that note 12 verified MBA-obf

pe = pefile.PE(DLL, fast_load=True)
img_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)

text_rva = text_data = rdata_rva = rdata_data = None
for sec in pe.sections:
    name = sec.Name.rstrip(b'\x00').decode(errors='ignore')
    if name == '.text':
        text_rva = sec.VirtualAddress; text_data = sec.get_data()
    if name == '.rdata':
        rdata_rva = sec.VirtualAddress; rdata_data = sec.get_data()

def in_text(rva):
    return text_rva <= rva < text_rva + len(text_data)

def read_q_at(off_in_rdata):
    return struct.unpack_from("<Q", rdata_data, off_in_rdata)[0]

def disasm_at(rva, max_n=30, max_bytes=256):
    if not in_text(rva): return []
    off = rva - text_rva
    code = text_data[off:off+max_bytes]
    return list(md.disasm(code, img_base + rva))[:max_n]

OBFUSCATION_MAGICS = {0xaaaaaaaa, 0xaaaaaaaaaaaaaaaa}

def classify_body(rva):
    """Same classifier as note-13 Test 7 but tuned for inner bodies."""
    insns = disasm_at(rva, max_n=30)
    if not insns: return "no_text", "rva outside .text", []

    # Detect "trampoline": short body ending in jmp/call immediately
    if len(insns) <= 6 and any(i.mnemonic in ('jmp',) for i in insns[:6]):
        # Was it a simple "mov + jmp" pattern?
        if any('rip + 0x' in i.op_str for i in insns[:6]):
            return "trampoline", f"len={len(insns)} insn body, rip-rel jmp", insns

    magic_writes = 0
    aaaa_count = 0
    has_imul_hash = False
    has_cmovae = False
    has_movabs_aaaa = False
    for insn in insns[:25]:
        op = insn.op_str
        if insn.mnemonic in ('mov','movabs'):
            if '[rsp' in op and ', 0x' in op:
                try:
                    imm = int(op.split(', 0x')[-1], 16)
                    if imm in OBFUSCATION_MAGICS:
                        aaaa_count += 1
                    elif 0x10000000 < imm < 0xffffffff:
                        magic_writes += 1
                except Exception:
                    pass
            if insn.mnemonic == 'movabs' and ', 0xaaaaaaaaaaaaaaaa' in op:
                has_movabs_aaaa = True
        if insn.mnemonic == 'imul' and ', 0x' in op:
            has_imul_hash = True
        if insn.mnemonic == 'cmovae':
            has_cmovae = True

    score = magic_writes*3 + aaaa_count*2 + (5 if has_imul_hash else 0) + \
            (3 if has_cmovae else 0) + (4 if has_movabs_aaaa else 0)
    evidence = (f"magic_imm={magic_writes} aaaa_fills={aaaa_count} "
                f"movabs_aaaa={has_movabs_aaaa} imul_hash={has_imul_hash} "
                f"cmovae={has_cmovae} score={score}")
    if score >= 8:
        return "obfuscated", evidence, insns
    if score >= 4:
        return "obfuscated_lite", evidence, insns

    pushes = sum(1 for i in insns[:8] if i.mnemonic == 'push')
    has_sub_rsp = any(i.mnemonic == 'sub' and 'rsp' in i.op_str for i in insns[:10])
    if pushes >= 4 and has_sub_rsp:
        return "clean_prolog", f"{pushes} pushes + sub rsp", insns

    return "other", evidence, insns

# ============================================================================
# Step 1: locate m_impl_vtable by searching for slot-5 pointer in .rdata
# ============================================================================
SLOT5_VA = img_base + SLOT5_INNER_RVA
slot5_bytes = struct.pack("<Q", SLOT5_VA)

candidates = []
off = 0
while True:
    idx = rdata_data.find(slot5_bytes, off)
    if idx == -1: break
    vtable_off = idx - 5*8
    if vtable_off >= 0:
        candidates.append(vtable_off)
    off = idx + 8

# For each candidate, verify ALL 19 consecutive QWORDs are valid code pointers
verified = []
for c in candidates:
    if c + 19*8 > len(rdata_data): continue
    slots = [read_q_at(c + i*8) for i in range(19)]
    rvas = [s - img_base for s in slots]
    n_in_text = sum(1 for r in rvas if in_text(r))
    if n_in_text >= 18:  # allow 1 NULL or special-case slot
        verified.append((c, rvas, n_in_text))

# ============================================================================
# Build report
# ============================================================================
sections = []
sections.append("# Test 7 (continued) — Inner m_impl vtable bodies\n")
sections.append("**Date:** 2026-06-15  \n**Method:** locate the inner `m_impl` vtable in `.rdata` by reverse-search "
                f"for the known slot-5 wrapper RVA `0x{SLOT5_INNER_RVA:x}` (confirmed in note 10). "
                "Then classify all 19 inner bodies.\n")
sections.append(f"- Search target: VA `0x{SLOT5_VA:x}` (= image_base + slot5 RVA)")
sections.append(f"- Candidate matches in .rdata: {len(candidates)}")
sections.append(f"- After validating 18+/19 slots are valid code pointers: {len(verified)}\n")

if not verified:
    sections.append("❌ FAIL: no valid m_impl_vtable candidate found by reverse search.")
    sections.append("Fallback: would need to disasm the constructor at rva 0x1db270 and trace where")
    sections.append("the m_impl vtable pointer gets written. Skipping for this iteration.")
    with open(OUT, "w") as f: f.write("\n".join(sections))
    print(f"Wrote {OUT} (FAIL)")
    raise SystemExit

# Use the first verified candidate
vtable_off, rvas, n_in_text = verified[0]
vtable_rva = rdata_rva + vtable_off
sections.append(f"✅ m_impl_vtable located at RVA `0x{vtable_rva:x}` ({n_in_text}/19 slots are code pointers)\n")

if len(verified) > 1:
    sections.append(f"⚠️  Note: {len(verified)} candidates matched. Using the first; others at:")
    for c, _, _ in verified[1:]:
        sections.append(f"  - RVA `0x{rdata_rva + c:x}`")
    sections.append("")

# Classify each
cdm11_methods = {
    0:"Initialize", 1:"GetStatusForPolicy", 2:"SetServerCertificate",
    3:"CreateSessionAndGenerateRequest", 4:"LoadSession", 5:"UpdateSession",
    6:"CloseSession", 7:"RemoveSession", 8:"TimerExpired", 9:"Decrypt",
    10:"InitializeAudioDecoder", 11:"InitializeVideoDecoder",
    12:"DeinitializeDecoder", 13:"ResetDecoder",
    14:"DecryptAndDecodeFrame", 15:"DecryptAndDecodeSamples",
    16:"OnPlatformChallengeResponse", 17:"OnQueryOutputProtectionStatus",
    18:"OnStorageId",
}

attacker_input_slots = {0,1,3,4,5,9,14,15,16}   # ingest parseable structures
opaque_passthrough = {2,18}                      # blob passthrough

sections.append("## Classification per inner body\n")
sections.append("| # | inner RVA | label | evidence | CDM_11 method | attacker-input? |")
sections.append("|---|---|---|---|---|---|")
labels = collections.Counter()
results = []
for i, rva in enumerate(rvas):
    label, evidence, insns = classify_body(rva)
    labels[label] += 1
    is_input = "**yes**" if i in attacker_input_slots else ("blob" if i in opaque_passthrough else "—")
    sections.append(f"| {i} | 0x{rva:x} | **{label}** | {evidence} | {cdm11_methods[i]} | {is_input} |")
    results.append((i, rva, label, evidence, insns))

sections.append("")
sections.append(f"**Distribution:** {dict(labels)}\n")

# Cross-check with note 12 known finding
for s, expected_rva in KNOWN_OBF_INNER.items():
    actual = rvas[s]
    if actual != expected_rva:
        sections.append(f"⚠️  Discrepancy on slot {s}: classifier found inner at 0x{actual:x}, "
                        f"note 12 verified 0x{expected_rva:x}. May indicate slot-5 pivot picked wrong vtable, "
                        f"OR slot {s} wrapper points to a different inner than slot {s} vtable entry.")
    else:
        sections.append(f"✓ Cross-check passed: slot {s} inner at 0x{expected_rva:x} matches note 12.")

# Distribution analysis
input_slots = [r for i, r, lab, _, _ in results if i in attacker_input_slots]
blob_slots = [r for i, r, lab, _, _ in results if i in opaque_passthrough]
input_labels = [lab for i, r, lab, _, _ in results if i in attacker_input_slots]
blob_labels = [lab for i, r, lab, _, _ in results if i in opaque_passthrough]

obf_labels = {"obfuscated", "obfuscated_lite"}
input_obf = sum(1 for l in input_labels if l in obf_labels)
blob_obf = sum(1 for l in blob_labels if l in obf_labels)

sections.append("")
sections.append("## Obfuscation distribution finding (full 19-slot version)\n")
sections.append(f"- Attacker-input slots ({len(attacker_input_slots)}): {input_obf} obfuscated  "
                f"→ obfuscation rate = {input_obf/len(attacker_input_slots)*100:.0f}%")
sections.append(f"- Opaque-passthrough slots ({len(opaque_passthrough)}): {blob_obf} obfuscated  "
                f"→ obfuscation rate = {blob_obf/len(opaque_passthrough)*100:.0f}%")

if input_obf >= len(attacker_input_slots)*0.5 and blob_obf == 0:
    sections.append("\n✅ **Strong support for the obfuscation-distribution claim** — attacker-input slots majority-obfuscated, passthrough slots clean.")
elif input_obf == 0 and blob_obf == 0:
    sections.append("\n⚠️  **CLAIM WEAKENED** — no obfuscation detected in either group. May indicate classifier is wrong or the vtable found is not the right m_impl. Re-investigate.")
else:
    sections.append(f"\n🟡  **PARTIAL** — pattern visible but not clean. Need to refine claim wording in paper § 4.3.")

# Dump first 12 insns of each non-trampoline inner body for the appendix
sections.append("\n## Per-slot first-12-insns appendix\n")
for i, rva, label, _, insns in results:
    sections.append(f"### slot {i} — {cdm11_methods[i]} — `0x{rva:x}` — **{label}**\n```")
    for ins in insns[:12]:
        sections.append(f"  0x{ins.address:x}: {ins.mnemonic:8s} {ins.op_str}")
    sections.append("```\n")

with open(OUT, "w") as f: f.write("\n".join(sections))
print(f"Wrote {OUT}")
print(f"m_impl_vtable @ rva 0x{vtable_rva:x}, distribution: {dict(labels)}")
