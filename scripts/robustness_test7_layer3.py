#!/usr/bin/env python3
"""Test 7 (layer 3) — follow each m_impl_vtable[i] into its layer-3 handler
and classify obfuscation. This is the REAL test of the distribution claim
(layer 2 is mostly clean wrappers/trampolines, layer 3 is where parsing lives).
"""
import struct, json, collections
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = "/home/trxnegro/redteam/projects/netflix-drm-bh2027"
DLL  = f"{ROOT}/binaries/widevinecdm-edge150.dll"
OUT  = f"{ROOT}/research-notes/13c-test7-layer3.md"

# m_impl_vtable located in note 13b
MIMPL_VTABLE_RVA = 0x77d370

pe = pefile.PE(DLL, fast_load=True)
img_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
text_rva = text_data = rdata_rva = rdata_data = None
for sec in pe.sections:
    name = sec.Name.rstrip(b'\x00').decode(errors='ignore')
    if name == '.text': text_rva = sec.VirtualAddress; text_data = sec.get_data()
    if name == '.rdata': rdata_rva = sec.VirtualAddress; rdata_data = sec.get_data()
def in_text(rva): return text_rva <= rva < text_rva + len(text_data)
def read_q_at(off): return struct.unpack_from("<Q", rdata_data, off)[0]
def disasm_at(rva, max_n=40, max_bytes=512):
    if not in_text(rva): return []
    off = rva - text_rva
    return list(md.disasm(text_data[off:off+max_bytes], img_base + rva))[:max_n]

OBFUSCATION_MAGICS = {0xaaaaaaaa, 0xaaaaaaaaaaaaaaaa}

def follow_to_layer3(slot, layer2_rva):
    """Return (layer3_rva, transition_kind, transition_detail).

    layer2 is either:
      - 'double_trampoline': mov rcx, [rcx+N]; jmp <target>   → layer3 = target
      - 'clean_wrapper': normal prolog + calls into layer3 → layer3 = first 'call imm' target
      - 'stub': returns immediately → layer3 = None
    """
    insns = disasm_at(layer2_rva, max_n=30)
    if not insns:
        return None, "no_text", ""

    # Double-trampoline: 1st insn = mov rcx, [rcx+N], 2nd = jmp
    if (len(insns) >= 2
        and insns[0].mnemonic == 'mov' and 'rcx' in insns[0].op_str and '[rcx + 0x' in insns[0].op_str
        and insns[1].mnemonic == 'jmp' and '0x' in insns[1].op_str):
        try:
            tgt = int(insns[1].op_str, 16) - img_base
            return tgt, "double_trampoline", f"jmp 0x{tgt:x}"
        except Exception:
            return None, "double_trampoline_bad", insns[1].op_str

    # Stub: short body ending in ret
    if len(insns) <= 3 and any(i.mnemonic == 'ret' for i in insns):
        return None, "stub", " ".join(f"{i.mnemonic} {i.op_str}" for i in insns[:3])

    # Clean wrapper: scan body for the FIRST `call <imm>` instruction
    for i in range(len(insns)):
        if insns[i].mnemonic == 'call':
            op = insns[i].op_str
            if op.startswith('0x'):
                try:
                    tgt = int(op, 16) - img_base
                    return tgt, "wrapper_call", f"call 0x{tgt:x} @ insn #{i}"
                except Exception:
                    pass
    return None, "wrapper_no_call", "no direct call found in first 30 insns"

def classify_handler(rva):
    """Same classifier as layer-2."""
    insns = disasm_at(rva, max_n=35)
    if not insns: return "no_text", "rva outside .text", []
    magic_writes = 0
    aaaa_count = 0
    has_imul_hash = False
    has_cmovae = False
    has_movabs_aaaa = False
    for insn in insns[:30]:
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
    if pushes >= 4 and has_sub_rsp: return "clean_prolog", f"{pushes} pushes + sub rsp", insns
    return "other", evidence, insns

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
attacker_input_slots = {0,1,3,4,5,9,14,15,16}
opaque_passthrough = {2,18}

sections = []
sections.append("# Test 7 (layer 3) — Inner handler obfuscation classification\n")
sections.append("**Date:** 2026-06-15  \n**Method:** for each `m_impl_vtable[i]` body (layer-2), follow into layer-3 handler. Layer-3 is where the actual parsing/processing happens. The obfuscation distribution claim is about layer 3.\n")
sections.append(f"- m_impl_vtable RVA: `0x{MIMPL_VTABLE_RVA:x}` (verified in note 13b)\n")

# Step 1: read all 19 m_impl_vtable entries
mimpl_off = MIMPL_VTABLE_RVA - rdata_rva
layer2_rvas = []
for i in range(19):
    va = read_q_at(mimpl_off + i*8)
    layer2_rvas.append(va - img_base)

sections.append("## Layer-2 → Layer-3 transition\n")
sections.append("| # | layer-2 RVA | transition | layer-3 RVA | method |")
sections.append("|---|---|---|---|---|")

layer3_map = {}
for i, l2 in enumerate(layer2_rvas):
    l3, kind, detail = follow_to_layer3(i, l2)
    layer3_map[i] = (l2, l3, kind, detail)
    l3s = f"0x{l3:x}" if l3 else "(none)"
    sections.append(f"| {i} | 0x{l2:x} | {kind} ({detail}) | {l3s} | {cdm11_methods[i]} |")

# Step 2: classify layer-3 handlers
sections.append("\n## Layer-3 handler classification\n")
sections.append("| # | layer-3 RVA | label | evidence | method | attacker-input? |")
sections.append("|---|---|---|---|---|---|")
labels = collections.Counter()
classification = {}
for i in range(19):
    _, l3, kind, _ = layer3_map[i]
    if l3 is None:
        classification[i] = ("n/a", f"{kind}", [])
        labels["n/a"] += 1
        atk = "**yes**" if i in attacker_input_slots else ("blob" if i in opaque_passthrough else "—")
        sections.append(f"| {i} | n/a | n/a | {kind} | {cdm11_methods[i]} | {atk} |")
        continue
    label, evidence, insns = classify_handler(l3)
    classification[i] = (label, evidence, insns)
    labels[label] += 1
    atk = "**yes**" if i in attacker_input_slots else ("blob" if i in opaque_passthrough else "—")
    sections.append(f"| {i} | 0x{l3:x} | **{label}** | {evidence} | {cdm11_methods[i]} | {atk} |")

sections.append(f"\n**Distribution:** {dict(labels)}\n")

# Cross-check vs note 12 (slot 3 layer-3 should be 0x21f200, obfuscated)
sections.append("## Cross-check vs note 12\n")
slot3_l3 = layer3_map[3][1]
slot3_label = classification[3][0]
if slot3_l3 == 0x21f200:
    if slot3_label in ("obfuscated", "obfuscated_lite"):
        sections.append(f"✅ Slot 3 layer-3 = 0x21f200 (matches note 12) AND classified as `{slot3_label}` (matches note 12's MBA-obfuscation finding).")
    else:
        sections.append(f"⚠️ Slot 3 layer-3 = 0x21f200 matches note 12 BUT classified as `{slot3_label}` (note 12 said obfuscated). Classifier may be too lenient.")
else:
    sections.append(f"⚠️ Slot 3 layer-3 = 0x{slot3_l3:x}, but note 12 said 0x21f200. Either wrong call extracted, or note 12 followed a deeper hop.")

# Compute final distribution finding
obf_labels = {"obfuscated", "obfuscated_lite"}
input_obf = sum(1 for i in attacker_input_slots if classification[i][0] in obf_labels)
blob_obf = sum(1 for i in opaque_passthrough if classification[i][0] in obf_labels)
input_classified = sum(1 for i in attacker_input_slots if classification[i][0] != "n/a")
blob_classified = sum(1 for i in opaque_passthrough if classification[i][0] != "n/a")

sections.append("\n## Final obfuscation-distribution finding\n")
sections.append(f"- Attacker-input slots ({len(attacker_input_slots)}, of which {input_classified} have layer-3 we classified): "
                f"{input_obf} obfuscated  → obfuscation rate among classified = "
                f"{(input_obf/max(input_classified,1))*100:.0f}%")
sections.append(f"- Opaque-passthrough slots ({len(opaque_passthrough)}, of which {blob_classified} classified): "
                f"{blob_obf} obfuscated  → obfuscation rate = "
                f"{(blob_obf/max(blob_classified,1))*100:.0f}%")

if input_obf >= input_classified * 0.5 and blob_obf == 0:
    sections.append(f"\n✅ **STRONG support for obfuscation-distribution claim at layer 3.** Reframe paper § 4.3 around the **3-layer dispatch model**: outer_vtable (clean thunks) → m_impl_vtable (clean wrappers/trampolines) → layer-3 handlers (obfuscation concentrated in attacker-input slots).")
elif input_obf == 0 and blob_obf == 0:
    sections.append(f"\n❌ **CLAIM REFUTED at layer 3 too.** Either the obfuscation is at a 4th layer, or note 12's finding was specific to slot 3 (0x21f200) and not systemic. Either way, the paper § 4.3 generalization is overreach.")
else:
    sections.append(f"\n🟡 **PARTIAL.** Refine paper wording: obfuscation present in {input_obf}/{input_classified} attacker-input slots ({100*input_obf//max(input_classified,1)}%), absent in passthrough.")

# Per-slot layer-3 disasm appendix
sections.append("\n## Per-slot layer-3 disasm (first 14 insns)\n")
for i in range(19):
    label, _, insns = classification[i]
    if not insns: continue
    l3 = layer3_map[i][1]
    sections.append(f"### slot {i} — {cdm11_methods[i]} — layer-3 `0x{l3:x}` — **{label}**\n```")
    for ins in insns[:14]:
        sections.append(f"  0x{ins.address:x}: {ins.mnemonic:8s} {ins.op_str}")
    sections.append("```\n")

with open(OUT, "w") as f: f.write("\n".join(sections))
print(f"Wrote {OUT}")
print(f"Distribution: {dict(labels)}")
print(f"Input-slot obf rate: {input_obf}/{input_classified}")
print(f"Blob-slot obf rate: {blob_obf}/{blob_classified}")
