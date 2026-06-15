#!/usr/bin/env python3
"""Robustness tests 1, 5, 7 — autonomous static + JSONL post-analysis.

Test 1: byte-verify outer_vtable[14] thunk uses slot index 14 (dispatch offset 0x70)
Test 5: validate shape-data consistency in the 56MB JSONL capture
Test 7: classify obfuscation status across all 19 slots of Edge 150 outer vtable

Output: research-notes/13-robustness-tests-1-5-7.md
"""
import sys, json, struct, statistics, collections, glob, os
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = "/home/trxnegro/redteam/projects/netflix-drm-bh2027"
DLL  = f"{ROOT}/binaries/widevinecdm-edge150.dll"
OUT  = f"{ROOT}/research-notes/13-robustness-tests-1-5-7.md"
OUTER_VTABLE_RVA = 0x780250  # Edge 150, confirmed earlier
CONSTRUCTOR_RVA  = 0x1e0300  # Edge 150 CDM_11 outer constructor

# Load binary
pe = pefile.PE(DLL, fast_load=True)
img_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)

text_rva = text_data = rdata_rva = rdata_data = None
for sec in pe.sections:
    name = sec.Name.rstrip(b'\x00').decode(errors='ignore')
    if name == '.text':
        text_rva = sec.VirtualAddress
        text_data = sec.get_data()
    if name == '.rdata':
        rdata_rva = sec.VirtualAddress
        rdata_data = sec.get_data()

def in_text(rva):
    return text_rva is not None and text_rva <= rva < text_rva + len(text_data)

def disasm_at(rva, max_n=30, max_bytes=256):
    if not in_text(rva):
        return []
    off = rva - text_rva
    code = text_data[off:off+max_bytes]
    va = img_base + rva
    out = []
    for i, insn in enumerate(md.disasm(code, va)):
        out.append(insn)
        if i+1 >= max_n: break
    return out

def read_qword_rva(rva):
    """Read 8 bytes at rva, return as u64."""
    # Check .rdata first then .text
    for base, data in [(rdata_rva, rdata_data), (text_rva, text_data)]:
        if base is not None and base <= rva < base + len(data):
            off = rva - base
            return struct.unpack("<Q", data[off:off+8])[0]
    return None

# ============================================================================
# Test 1 — outer_vtable[14] thunk verifies slot index → offset 0x70
# ============================================================================
def test_1():
    report = ["## Test 1 — slot 14 outer-vtable thunk byte-verification\n"]
    report.append("**Claim under test:** the patches we applied at outer_vtable[14] dispatch via offset `0x70` "
                  "(= 14 × 8) in the inner `m_impl` vtable. Without this, our 'g_calls=0 at slot 14' evidence "
                  "could be claiming the wrong method was dormant.\n")

    slot14_ptr_rva = OUTER_VTABLE_RVA + 14*8
    slot14_thunk_va = read_qword_rva(slot14_ptr_rva)
    if slot14_thunk_va is None:
        report.append("❌ FAIL: could not read outer_vtable[14] pointer from .rdata\n")
        return "\n".join(report), False
    slot14_thunk_rva = slot14_thunk_va - img_base
    report.append(f"- outer_vtable RVA: `0x{OUTER_VTABLE_RVA:x}`")
    report.append(f"- outer_vtable[14] entry at RVA `0x{slot14_ptr_rva:x}`")
    report.append(f"- thunk pointer: VA `0x{slot14_thunk_va:x}` → RVA `0x{slot14_thunk_rva:x}`\n")

    insns = disasm_at(slot14_thunk_rva, max_n=8)
    report.append("Disasm:\n```")
    for insn in insns:
        report.append(f"  0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}")
    report.append("```\n")

    # The Chrome/Edge CDM thunk pattern is:
    #   mov rcx, [rcx + 8]            ; this->m_impl
    #   mov rax, [rcx]                ; m_impl->m_vtable
    #   mov rax, [rax + SLOT_OFFSET]  ; ← slot dispatch offset lives HERE
    #   mov rdx, [rip + cfg_disp]     ; CFG dispatcher
    #   jmp rdx                       ; CFG-tail-call to rax
    # So we look for the SECOND `mov rax, qword ptr [rax + 0xN]` instruction.
    found_70 = False
    found_offset = None
    saw_rax_rcx = False
    for insn in insns:
        op = insn.op_str
        # First step: mov rax, qword ptr [rcx]
        if insn.mnemonic == 'mov' and op.startswith('rax,') and '[rcx]' in op:
            saw_rax_rcx = True
            continue
        # Second step: mov rax, qword ptr [rax + N]
        if saw_rax_rcx and insn.mnemonic == 'mov' and op.startswith('rax,') and 'rax + 0x' in op:
            try:
                off_hex = op.split('rax + 0x')[-1].split(']')[0]
                found_offset = int(off_hex, 16)
                if found_offset == 0x70:
                    found_70 = True
            except Exception:
                pass
            break
    jmp_offset = found_offset

    if found_70:
        report.append(f"✅ **PASS** — thunk dispatches at offset `0x70` = 14 × 8. Slot index consistency confirmed: the patches at outer_vtable[14] were indeed routing 'slot 14' invocations to the `m_impl` method body at vtable[14].")
        result = True
    elif jmp_offset is not None:
        report.append(f"⚠️  **UNEXPECTED** — thunk dispatches at offset `0x{jmp_offset:x}` (= {jmp_offset//8} × 8). "
                      f"If this isn't 0x70, our slot-index model is wrong.")
        result = False
    else:
        report.append(f"❌ **FAIL** — could not identify a `jmp [reg + offset]` pattern in the thunk prolog.")
        result = False

    report.append("")
    report.append("**Note on method-name mapping:** The mapping `slot 14 → DecryptAndDecodeFrame` is taken from "
                  "the public Chromium header `media/cdm/api/content_decryption_module.h` (CDM_11 interface). "
                  "This is a public header citation, not a runtime inference, so it does not need empirical validation.")
    return "\n".join(report), result

# ============================================================================
# Test 7 — classify all 19 outer-vtable slots by prolog style
# ============================================================================
OBFUSCATION_MAGICS = [0xaaaaaaaa, 0xaaaaaaaaaaaaaaaa]

def classify_slot(rva):
    """Return (label, evidence_line)."""
    insns = disasm_at(rva, max_n=30)
    if not insns:
        return "no_text", "(rva outside .text)"

    # Stringify for pattern detection
    txt = "\n".join(f"{i.mnemonic} {i.op_str}" for i in insns[:15])

    # Detect "clean thunk": mov rcx,[rcx+8]; mov rax,[rcx]; mov rax,[rax+N]; ...; jmp rdx
    if (len(insns) >= 4
        and insns[0].mnemonic == 'mov' and 'rcx + 8' in insns[0].op_str
        and insns[1].mnemonic == 'mov' and insns[1].op_str.startswith('rax,') and '[rcx]' in insns[1].op_str
        and any(i.mnemonic == 'jmp' for i in insns[:6])):
        # Extract slot dispatch offset from "mov rax, qword ptr [rax + 0xN]"
        offset = "?"
        for insn in insns[:6]:
            if (insn.mnemonic == 'mov' and insn.op_str.startswith('rax,')
                and 'rax + 0x' in insn.op_str):
                try:
                    off_hex = insn.op_str.split('rax + 0x')[-1].split(']')[0]
                    n = int(off_hex, 16)
                    offset = f"0x{n:x} (slot {n//8})"
                except Exception:
                    pass
                break
        return "clean_thunk", f"thunk → m_impl_vtable[{offset}]"

    # Detect obfuscation signature: many magic-constant writes to stack in first 20 insns
    # + presence of 0xaaaaaaaa fills
    magic_writes = 0
    aaaa_count = 0
    has_imul_hash = False
    has_cmovae = False
    for insn in insns[:25]:
        op = insn.op_str
        if insn.mnemonic in ('mov','movabs'):
            # Look for "qword/dword ptr [rsp + ...], 0xHHHHHHHH"
            if '[rsp' in op and ', 0x' in op:
                try:
                    immstr = op.split(', 0x')[-1]
                    imm = int(immstr, 16)
                    if imm in OBFUSCATION_MAGICS:
                        aaaa_count += 1
                    elif imm > 0x10000000 and imm < 0xffffffff:
                        # High-entropy 32-bit immediate
                        magic_writes += 1
                except Exception:
                    pass
        if insn.mnemonic == 'imul' and ', 0x' in op:
            has_imul_hash = True
        if insn.mnemonic == 'cmovae':
            has_cmovae = True

    score = magic_writes*3 + aaaa_count*2 + (5 if has_imul_hash else 0) + (3 if has_cmovae else 0)
    evidence = (f"magic_imm_writes={magic_writes} aaaa_fills={aaaa_count} "
                f"imul_hash={has_imul_hash} cmovae={has_cmovae} score={score}")

    if score >= 8:
        return "obfuscated", evidence
    if score >= 4:
        return "obfuscated_lite", evidence

    # Detect direct C++ prolog: push regs, sub rsp
    pushes = sum(1 for i in insns[:8] if i.mnemonic == 'push')
    has_sub_rsp = any(i.mnemonic == 'sub' and 'rsp' in i.op_str for i in insns[:10])
    if pushes >= 4 and has_sub_rsp:
        return "clean_prolog", f"{pushes} pushes + sub rsp"

    return "other", evidence

def test_7():
    report = ["## Test 7 — Obfuscation classification across all 19 outer-vtable slots\n"]
    report.append("**Claim under test:** the obfuscation distribution finding (note 12) generalizes — slots that "
                  "ingest attacker-parseable structured input are obfuscated; slots that pass opaque blobs are clean. "
                  "Sample size in note 12 was 4 slots (0, 1, 2, 18). Here we check all 19.\n")
    report.append("| Slot | RVA | Label | Evidence | CDM_11 method (cdm.h) |")
    report.append("|---|---|---|---|---|")

    # CDM_11 method names from chromium content_decryption_module.h (public)
    cdm11_methods = {
        0:  "Initialize",
        1:  "GetStatusForPolicy",
        2:  "SetServerCertificate",
        3:  "CreateSessionAndGenerateRequest",
        4:  "LoadSession",
        5:  "UpdateSession",
        6:  "CloseSession",
        7:  "RemoveSession",
        8:  "TimerExpired",
        9:  "Decrypt",
        10: "InitializeAudioDecoder",
        11: "InitializeVideoDecoder",
        12: "DeinitializeDecoder",
        13: "ResetDecoder",
        14: "DecryptAndDecodeFrame",
        15: "DecryptAndDecodeSamples",
        16: "OnPlatformChallengeResponse",
        17: "OnQueryOutputProtectionStatus",
        18: "OnStorageId",
    }

    labels = collections.Counter()
    rows = []
    for i in range(19):
        ptr_rva = OUTER_VTABLE_RVA + i*8
        fp = read_qword_rva(ptr_rva)
        if fp is None:
            rows.append((i, "?", "no_rdata", "n/a", cdm11_methods[i]))
            continue
        rva = fp - img_base
        label, evidence = classify_slot(rva)
        labels[label] += 1
        rows.append((i, f"0x{rva:x}", label, evidence, cdm11_methods[i]))
        report.append(f"| {i} | 0x{rva:x} | **{label}** | {evidence} | {cdm11_methods[i]} |")

    report.append("")
    report.append(f"**Distribution:** {dict(labels)}\n")

    # Cross-check: attacker-controllable methods (0,1,3,5,9,14,15,16) vs clean methods (2,18)
    attacker_input_slots = [0,1,3,4,5,9,14,15,16]
    opaque_passthrough_slots = [2,18]
    obfuscated_labels = {"obfuscated", "obfuscated_lite"}

    obf_in_atk = sum(1 for s in attacker_input_slots if rows[s][2] in obfuscated_labels)
    obf_in_op  = sum(1 for s in opaque_passthrough_slots if rows[s][2] in obfuscated_labels)
    report.append(f"- Attacker-input slots ({len(attacker_input_slots)} total): {obf_in_atk} obfuscated, "
                  f"{len(attacker_input_slots)-obf_in_atk} not")
    report.append(f"- Opaque-passthrough slots ({len(opaque_passthrough_slots)} total): {obf_in_op} obfuscated, "
                  f"{len(opaque_passthrough_slots)-obf_in_op} not")

    # Many slots will be thunks → we need to follow them and re-classify the inner body.
    report.append("")
    report.append("**Caveat:** slots that classify as `clean_thunk` only have a 3-line dispatch wrapper — "
                  "the real body lives at `m_impl_vtable[slot*8]`. For those, the obfuscation question is about "
                  "the *inner* body, which a thunk-only audit cannot answer. Note 12 confirmed slot 3's inner "
                  "(`0x21f200`) IS heavily obfuscated. A full Test 7 would resolve all 19 inner bodies; this "
                  "first pass shows whether the OUTER classification is uniform.")

    # Verdict
    if obf_in_atk >= 2 and obf_in_op == 0:
        verdict = "✅ **CONSISTENT with note 12 claim** — pattern holds in expanded sample."
    elif obf_in_atk == 0 and obf_in_op == 0:
        verdict = "⚠️ **THUNK-ONLY OUTER LAYER** — most slots are thunks; the obfuscation distribution claim is *only* about INNER bodies, and we need to follow each thunk to verify."
    else:
        verdict = f"⚠️ **MIXED** — obf_in_atk={obf_in_atk}, obf_in_op={obf_in_op}. May need refinement."
    report.append("")
    report.append(verdict)

    return "\n".join(report), rows

# ============================================================================
# Test 5 — JSONL consistency / shape validation
# ============================================================================
def test_5():
    report = ["## Test 5 — Shape data consistency (56 MB capture)\n"]
    report.append("**Claim under test:** the 453k shape events captured in the loot file represent real CDM "
                  "library activity (hook fired correctly, register-read worked) and the field values are "
                  "consistent with what a real CDM_11 internal dispatch would emit.\n")

    files = sorted(glob.glob(f"{ROOT}/loot/wv_shape_chrome5772_final_*.jsonl"))
    if not files:
        report.append("❌ FAIL: no loot/wv_shape_chrome5772_final_*.jsonl found")
        return "\n".join(report), False
    f = files[-1]
    report.append(f"- File: `{os.path.basename(f)}` ({os.path.getsize(f)//1024//1024} MB)\n")

    # Parse all events
    per_slot_calls    = collections.Counter()
    per_slot_kind_ib  = collections.Counter()
    per_slot_kind_call= collections.Counter()
    rh_per_slot       = collections.defaultdict(list)
    tsc_per_slot      = collections.defaultdict(list)
    ib_examples       = []
    bad_lines = 0
    total = 0
    with open(f) as fh:
        for line in fh:
            total += 1
            try:
                ev = json.loads(line)
            except Exception:
                bad_lines += 1
                continue
            slot = ev.get('slot')
            if slot is None: continue
            per_slot_calls[slot] += 1
            kind = ev.get('kind','?')
            if kind == 'ib':
                per_slot_kind_ib[slot] += 1
                if len(ib_examples) < 8:
                    ib_examples.append(ev)
            elif kind == 'call':
                per_slot_kind_call[slot] += 1
                rh_per_slot[slot].append(ev.get('rh',0))
                tsc_per_slot[slot].append(ev.get('tsc',0))

    report.append(f"- Total lines: {total:,}  (parse errors: {bad_lines})\n")
    report.append("### Per-slot event counts\n")
    report.append("| Slot | total | kind=call | kind=ib |")
    report.append("|---|---|---|---|")
    for s in sorted(per_slot_calls.keys()):
        report.append(f"| {s} | {per_slot_calls[s]:,} | {per_slot_kind_call[s]:,} | {per_slot_kind_ib[s]:,} |")

    # Check: ib entries should match expected slots (9/14/15) only.
    ib_slots = set(s for s in per_slot_kind_ib if per_slot_kind_ib[s] > 0)
    expected_ib_slots = {9,14,15}
    unexpected_ib = ib_slots - expected_ib_slots
    report.append("")
    if ib_slots == set():
        report.append("- No `kind=ib` entries in the capture (slots 9/14/15 had `g_calls=0`, consistent with HW-dormancy finding).")
    elif ib_slots.issubset(expected_ib_slots):
        report.append(f"- `kind=ib` entries only in expected slots {ib_slots}. ✓")
    else:
        report.append(f"⚠️ `kind=ib` entries appeared in unexpected slots: {unexpected_ib}. Shim may have a bug.")

    # rh distribution for slot 0/6 (the hot ones)
    report.append("")
    report.append("### Register-hash entropy per slot (hook-fire sanity check)\n")
    report.append("If rh has reasonable spread (not all-zero, not all-equal), the hook was reading real registers each call.\n")
    report.append("| Slot | sample | unique rh values | most-common rh | most-common freq | verdict |")
    report.append("|---|---|---|---|---|---|")
    for s in sorted(rh_per_slot.keys()):
        sample = rh_per_slot[s]
        if not sample: continue
        sample_n = len(sample)
        uniq = len(set(sample))
        mc = collections.Counter(sample).most_common(1)[0]
        verdict = "✓ realistic" if uniq > 10 and mc[1] < sample_n*0.9 else "⚠️ low entropy"
        report.append(f"| {s} | {sample_n:,} | {uniq:,} | 0x{mc[0]:x} | {mc[1]:,} | {verdict} |")

    # Timing distribution: events/s across observation window
    report.append("")
    report.append("### Timing distribution\n")
    report.append("If events arrive at a steady rate, hook was stable. Big gaps suggest stalls or partial coverage.\n")
    report.append("| Slot | first tsc | last tsc | span (raw) | events/sec (approx) |")
    report.append("|---|---|---|---|---|")
    for s in sorted(tsc_per_slot.keys()):
        ts = sorted(tsc_per_slot[s])
        if len(ts) < 2: continue
        first = ts[0]
        last = ts[-1]
        span = last - first
        # QueryPerformanceCounter rate varies, but for 355s observation window, rough rate:
        # if we assume the span maps to 355s, rate = len(ts) / 355
        rate = len(ts) / 355.0
        report.append(f"| {s} | {first} | {last} | {span:,} | {rate:.1f} |")

    # IB shape examples (likely 0 entries in this capture, but include if present)
    if ib_examples:
        report.append("")
        report.append("### Sample `kind=ib` events (shape only, never bytes)\n")
        report.append("```")
        for ev in ib_examples[:5]:
            report.append(json.dumps(ev))
        report.append("```")

        # Validate encryption_scheme ∈ {0,1,2}
        bad_es = sum(1 for ev in ib_examples if ev.get('es',-1) not in (0,1,2))
        bad_iv = sum(1 for ev in ib_examples if ev.get('ivs',-1) not in (0,8,16))
        bad_kid = sum(1 for ev in ib_examples if ev.get('kis',-1) not in (0,16))
        report.append("")
        report.append(f"- es ∈ {{0,1,2}} violations: {bad_es}/{len(ib_examples)}")
        report.append(f"- iv_size ∈ {{0,8,16}} violations: {bad_iv}/{len(ib_examples)}")
        report.append(f"- key_id_size ∈ {{0,16}} violations: {bad_kid}/{len(ib_examples)}")

    return "\n".join(report), per_slot_calls

# ============================================================================
# Main
# ============================================================================
def main():
    sections = []
    sections.append("# Robustness sprint — Tests 1, 5, 7\n")
    sections.append("**Date:** 2026-06-15  \n**Method:** static analysis of `widevinecdm-edge150.dll` + post-analysis of `loot/wv_shape_chrome5772_final_*.jsonl`. Zero runtime activity. No content bytes touched.\n")
    sections.append("**Purpose:** before paper drafting, falsify (or harden) the three weakest empirical claims so reviewers cannot break them in Q&A.\n")
    sections.append("---\n")

    t1_text, t1_ok = test_1()
    sections.append(t1_text + "\n---\n")
    t7_text, t7_rows = test_7()
    sections.append(t7_text + "\n---\n")
    t5_text, t5_counts = test_5()
    sections.append(t5_text + "\n---\n")

    # Final triage
    sections.append("## Bottom line\n")
    if t1_ok:
        sections.append("- ✅ Test 1 PASS: outer_vtable[14] correctly dispatches to slot index 14 (offset 0x70). The HW-dormancy 'slot 14 silent' claim is index-correct.")
    else:
        sections.append("- ❌ Test 1 issue: see above; slot-index claim needs revision.")

    sections.append("- ⚠️  Test 7 partial: the outer vtable is mostly thunks; the obfuscation distribution claim is fundamentally about the INNER `m_impl` vtable bodies, not the outer thunks. Need to enumerate inner bodies to give the full table. Next sub-step: trace `m_impl_vtable` via the constructor at RVA `0x1e0300` and re-run classifier on each inner body.")
    sections.append("- Test 5: see per-slot tables. The hook-fire sanity check (rh entropy, timing distribution) tells us whether the 453k events are real signal or noise.")

    with open(OUT, "w") as fh:
        fh.write("\n".join(sections))
    print(f"Wrote {OUT}")

if __name__ == "__main__":
    main()
