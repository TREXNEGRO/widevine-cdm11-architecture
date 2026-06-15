#!/usr/bin/env python3
"""cdm_arch_discover.py — generic architectural discoverer for any widevinecdm.dll.

Strategy (parameter-free):
1. Parse export table, find CreateCdmInstance
2. Disasm CreateCdmInstance, locate the CDM_11 (version 11) constructor branch
3. From the constructor, extract outer_vtable RVA (lea pattern)
4. Read the 19-entry outer vtable, decode each slot type:
   - clean thunk: identify slot index by reading the [rax + N] offset
   - direct impl: check obfuscation signature
5. From a known slot N thunk, find m_impl_vtable by reverse-search:
   - The thunk references inner via [m_impl + 0]
   - Wrappers in note 13b (Edge 150) for clean-prolog slots are direct impls
     stored at m_impl_vtable[slot]. We can pivot from slot 5 wrapper signature
     (multiple pushes + sub rsp + read [rcx + 0x10]).

Usage:
  cdm_arch_discover.py <binary.dll> [<label>]

Output: prints architectural summary; optionally writes JSON.
"""
import sys, struct, json, collections
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

if len(sys.argv) < 2:
    print("usage: cdm_arch_discover.py <binary.dll> [<label>]"); sys.exit(1)
DLL = sys.argv[1]
LABEL = sys.argv[2] if len(sys.argv) > 2 else DLL.rsplit("/",1)[-1]

pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
img_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)

text_rva = text_data = rdata_rva = rdata_data = None
for sec in pe.sections:
    name = sec.Name.rstrip(b'\x00').decode(errors='ignore')
    if name == '.text': text_rva = sec.VirtualAddress; text_data = sec.get_data()
    if name == '.rdata': rdata_rva = sec.VirtualAddress; rdata_data = sec.get_data()

def in_text(rva): return text_rva <= rva < text_rva + len(text_data)
def in_rdata(rva): return rdata_rva <= rva < rdata_rva + len(rdata_data)
def read_q_rva(rva):
    if in_rdata(rva):
        return struct.unpack_from("<Q", rdata_data, rva - rdata_rva)[0]
    if in_text(rva):
        return struct.unpack_from("<Q", text_data, rva - text_rva)[0]
    return None
def disasm(rva, n=80, b=1024):
    if not in_text(rva): return []
    off = rva - text_rva
    return list(md.disasm(text_data[off:off+b], img_base + rva))[:n]

# ============================================================================
# Step 1 — find CreateCdmInstance export
# ============================================================================
exports = {}
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if sym.name:
            exports[sym.name.decode()] = sym.address
cci_rva = exports.get("CreateCdmInstance")
if cci_rva is None:
    print("FAIL: CreateCdmInstance not found in exports"); sys.exit(1)

# ============================================================================
# Step 2 — find CDM_11 constructor. Enumerate all calls in CreateCdmInstance,
# then for each call target probe whether its body matches the CDM_11
# constructor signature: writes a vtable pointer to [rcx] near the entry.
# ============================================================================
cci_insns = disasm(cci_rva, n=400, b=8192)

# Known runtime helpers to skip (they appear in many wrappers as stack-check)
KNOWN_HELPERS = set()
# Identify them by looking for very common call targets (stack-check probes typically
# appear >= 3 times in CreateCdmInstance itself, but the ctor is called exactly once
# in the CDM_11 branch).
call_targets = collections.Counter()
for insn in cci_insns:
    if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
        try:
            tgt = int(insn.op_str, 16) - img_base
            call_targets[tgt] += 1
        except Exception:
            pass

# Helpers are called many times; the constructor is called once (or twice if version 10/11 share entry)
candidate_ctors = [tgt for tgt, cnt in call_targets.items() if cnt <= 2 and in_text(tgt)]

ctor_rva = None
outer_vtable_rva = None

def probe_ctor(tgt_rva):
    """Return outer_vtable RVA if tgt looks like the CDM_11 outer ctor, else None."""
    body = disasm(tgt_rva, n=60)
    if not body or len(body) < 5: return None
    # Look for early `lea reg, [rip + N]` followed by `mov [rcx], reg` (vtable install)
    for i, insn in enumerate(body[:40]):
        if insn.mnemonic == 'lea' and '[rip + 0x' in insn.op_str:
            try:
                # Determine destination register
                dst = insn.op_str.split(',')[0].strip()
                disp = int(insn.op_str.split('[rip + 0x')[-1].split(']')[0], 16)
                target_va = insn.address + insn.size + disp
                target_rva = target_va - img_base
                if not in_rdata(target_rva): continue
                # Check if next ~5 insns write the loaded value to a memory destination [reg]
                installed = False
                for k in range(i+1, min(i+6, len(body))):
                    nxt = body[k]
                    if nxt.mnemonic == 'mov' and nxt.op_str.startswith('qword ptr [') and dst in nxt.op_str.split(', ')[-1]:
                        installed = True
                        break
                if not installed: continue
                # Validate: the rdata location has at least 17/19 valid code pointers as a vtable
                n_valid = 0
                for slot in range(19):
                    val = read_q_rva(target_rva + slot*8)
                    if val is None: break
                    if in_text(val - img_base): n_valid += 1
                if n_valid >= 17:
                    return target_rva
            except Exception:
                pass
    return None

for tgt in candidate_ctors:
    found = probe_ctor(tgt)
    if found:
        ctor_rva = tgt
        outer_vtable_rva = found
        break

if outer_vtable_rva is None:
    print(f"PARTIAL: CreateCdmInstance@0x{cci_rva:x}, scanned {len(candidate_ctors)} candidate ctors, none yielded a valid outer vtable")
    sys.exit(2)

# ============================================================================
# Step 4 — enumerate outer vtable, decode each slot
# ============================================================================
slot_info = []
for i in range(19):
    fp_va = read_q_rva(outer_vtable_rva + i*8)
    if fp_va is None: slot_info.append(None); continue
    rva = fp_va - img_base
    insns = disasm(rva, n=20, b=160)
    # Detect thunk: mov rcx,[rcx+8]; mov rax,[rcx]; mov rax,[rax+N]; ...; jmp
    is_thunk = False
    slot_offset = None
    if (len(insns) >= 4
        and insns[0].mnemonic == 'mov' and 'rcx + 8' in insns[0].op_str
        and insns[1].mnemonic == 'mov' and '[rcx]' in insns[1].op_str):
        is_thunk = True
        for ins in insns[2:5]:
            if ins.mnemonic == 'mov' and 'rax + 0x' in ins.op_str:
                try:
                    slot_offset = int(ins.op_str.split('rax + 0x')[-1].split(']')[0], 16)
                    break
                except Exception:
                    pass
    slot_info.append({"rva": rva, "is_thunk": is_thunk, "dispatch_offset": slot_offset})

# ============================================================================
# Step 5 — find m_impl_vtable
# Strategy: for any "clean wrapper" slot (e.g. slot 5 UpdateSession identifiable
# by complex prolog), we find that wrapper's RVA. Then search .rdata for
# any QWORD whose value == img_base + wrapper_rva. The match's location minus
# 5*8 IS m_impl_vtable.
# We use: slot index 5 (which IS UpdateSession in CDM_11 per cdm.h). It's a
# thunk that dispatches at offset 0x28. We need to find what's at m_impl_vtable[5].
# Easier: use slot 14 (DecryptAndDecodeFrame) — same kind of fixed offset 0x70.
# But we don't know the inner content. Skip this; just dump the layer-1 picture.
# Layer-2 m_impl vtable discovery requires runtime peek at the m_impl object
# OR a search-by-known-signature for a slot 5 wrapper that this binary may have.
# ============================================================================

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

print(f"\n========================================================================")
print(f"Architecture map: {LABEL}")
print(f"========================================================================")
print(f"image_base       = 0x{img_base:x}")
print(f"CreateCdmInstance= 0x{cci_rva:x}")
print(f"CDM_11 ctor      = 0x{ctor_rva:x}" if ctor_rva else "CDM_11 ctor      = (not found)")
print(f"outer vtable RVA = 0x{outer_vtable_rva:x}")
print(f"\n{'slot':<6}{'method':<35}{'RVA':<12}{'type':<14}{'dispatch_offset':<18}{'slot_index_check':<8}")
ok = bad = 0
for i, info in enumerate(slot_info):
    if not info:
        print(f"{i:<6}{cdm11_methods[i]:<35}—"); continue
    if info["is_thunk"]:
        kind = "thunk"
        offset = info["dispatch_offset"]
        if offset is not None and offset == i*8:
            check = "✓"; ok += 1
        elif offset is None:
            check = "?"
        else:
            check = "✗"; bad += 1
        off_str = f"0x{offset:x}" if offset is not None else "?"
    else:
        kind = "direct"
        off_str = "(n/a)"
        check = "—"
    print(f"{i:<6}{cdm11_methods[i]:<35}0x{info['rva']:<10x}{kind:<14}{off_str:<18}{check:<8}")
print(f"\nSlot-index check: {ok}/{ok+bad} thunks have offset == slot_index*8")
print(f"Direct-impl slots (non-thunk): {sum(1 for i in slot_info if i and not i['is_thunk'])}")

# Output JSON for downstream cross-comparison
out_json = {
    "label": LABEL,
    "image_base": img_base,
    "create_cdm_instance_rva": cci_rva,
    "cdm11_ctor_rva": ctor_rva,
    "outer_vtable_rva": outer_vtable_rva,
    "slots": [{"i":i, "method": cdm11_methods[i], **(info or {})} for i, info in enumerate(slot_info)],
    "slot_index_check_passed": ok,
    "slot_index_check_failed": bad,
    "direct_impl_count": sum(1 for i in slot_info if i and not i['is_thunk']),
}
out_path = DLL.replace(".dll", "_arch.json")
with open(out_path, "w") as f: json.dump(out_json, f, indent=2)
print(f"\nWrote {out_path}")
