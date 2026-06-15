# Widevine CDM_11 architectural reverse engineering

Buchanan-style architectural reverse engineering of the Widevine
`CDM_11` dispatch as it ships in Chromium-family browsers on
Windows.  Companion source release for the paper:

> **Anatomy of the Desktop DRM Stack: A Three-Layer Dispatch Model
> in Widevine CDM\_11 and Its Hardware-Decode Dormancy on Chrome.**
> Draft, June 2026.

The paper is in `paper/main.pdf` (rendered) and `paper/main.tex`
(LaTeX source).

## What this is

A reproducible, fully open methodology for studying the dispatch
model of the modern Widevine CDM in Chromium-family browsers, plus
the empirical results obtained by applying it.  The work follows the
**Buchanan model** of DRM research: probe everything, document the
technique, publish no extraction artefact.

Specifically, the contributions are:

- A **three-layer dispatch model** for `CDM_11` in modern
  `widevinecdm.dll` (outer vtable thunks → `m_impl` intermediate
  vtable → per-slot handlers), byte-verified in two browser builds
  (Chrome 149 and Edge 150).
- A **slot-by-slot reachability map**, runtime-confirmed against both
  Netflix and a public Widevine test source.
- An **empirical demonstration of hardware-decode dormancy** of the
  user-facing per-frame CDM\_11 slots, alongside the activity
  profile of an internal singleton dispatch table.
- A **shape-only observation methodology** that captures per-slot
  dispatch metadata without ever reading content bytes, content
  keys, or IV bytes from CDM memory.

## What this is NOT

- Not a Widevine decryptor, frame ripper, or content-extraction tool.
- Not a stream-theft kit.
- Not an exploit for any specific bug in Widevine.
- Not redistributable Widevine binaries.  You must obtain
  `widevinecdm.dll` yourself by installing a stock Chromium-family
  browser; this repo contains only research code that operates on
  binaries you supply.

## Repository layout

```
paper/
  main.tex              full LaTeX source for the paper
  main.pdf              rendered PDF (~18 pages, 7 figures)

scripts/
  cdm_arch_discover.py  parameter-free architectural discoverer.
                        Given a widevinecdm.dll, locates the CDM_11
                        ctor, the outer vtable, and classifies each
                        slot (thunk vs direct impl + dispatch offset).

  wv_shim.c             Buchanan-compliant shape-only observation
                        shim. Exports 19 per-slot hooks. Logs JSONL
                        metadata only; never reads ib.data, never
                        persists key_id or IV bytes.

  wv_helper3.c          Per-slot patcher for the CDM_11 OUTER vtable.
                        Injects the shim, registers each hook in the
                        CFG bitmap with the correct page-offset math,
                        saves originals into g_pOrigSlot[N].

  wv_unit_test.c        Direct host that calls each hook with a
                        synthetic InputBuffer_2. Validates the
                        shape-extraction pipeline end-to-end without
                        any DRM target.

  robustness_tests.py
  robustness_test7_inner.py
  robustness_test7_layer3.py
                        Falsification tests run before publishing.
                        Verify slot-index correctness, validate the
                        JSONL signal vs noise, classify obfuscation
                        across all three dispatch layers.
```

## Ethics and what this code will not do

The shape-only shim (`wv_shim.c`) is designed to be incapable, by
construction, of producing the kind of artefact that would expose the
user to DMCA §1201 liability:

- The `WvHookSlotN` hooks never read `InputBuffer_2.data`
  (the ciphertext pointer).
- `key_id` and `iv` bytes are read transiently into stack-local
  buffers, collapsed to FNV-1a-32 hashes or non-zero presence flags,
  and immediately discarded.  No byte of key_id or IV ever leaves the
  function frame.
- No output `VideoFrame` or `AudioFrames` is parsed or read.
- The JSONL log fields are documented in the paper's Appendix B.
  The schema deliberately excludes every field that could materialise
  content, content keys, or key material.

For self-hosted lab use only.  Do not deploy against systems you do
not own or have explicit authorisation to instrument.

## Reproducing the paper's empirical results

1. Install a stock Chrome stable build on a Windows 11 lab VM you own.
   The paper used Chrome 149.0.7827.115.
2. Cross-compile the shim and helper from a Linux host with
   mingw-w64:
   ```
   x86_64-w64-mingw32-gcc -shared -O2 -static-libgcc \
       wv_shim.c -o wv_shim.dll -Wl,--out-implib,wv_shim.lib
   x86_64-w64-mingw32-gcc -O2 -static wv_helper3.c -o wv_helper3.exe
   ```
3. Launch Chrome with the research flags described in
   §5.1 of the paper:
   ```
   chrome.exe --disable-features=RendererCodeIntegrity --no-sandbox
   ```
4. Play any Widevine source (the public Bitmovin demo is sufficient).
5. Identify the CDM utility process PID:
   ```
   tasklist /m widevinecdm.dll
   ```
6. Install the hook:
   ```
   wv_helper3.exe wv_shim.dll <pid> --slots 3,5,14
   ```
7. Read counter state from the shim:
   ```
   read_va.exe <pid> <shim_base + 0xe04c>   ; g_callsBySlot[3]
   ```
8. Observe `C:\PublicLab\wv_shape.jsonl` for the per-slot events.

The `cdm_arch_discover.py` script reproduces the static architectural
analysis without runtime:

```
python3 cdm_arch_discover.py path/to/widevinecdm.dll "label"
```

## Licence

The research code in `scripts/` is released under the **MIT licence**
(see `LICENSE`).

The paper text in `paper/` is released under
**CC BY-NC 4.0** (Attribution, Non-Commercial) until the camera-ready
version of the venue it is submitted to has its own licence terms,
at which point the paper licence will track the venue's.

## Citation

If you build on this work, please cite the paper:

```
@misc{erazo2026widevinecdm11,
  title  = {Anatomy of the Desktop DRM Stack:
            A Three-Layer Dispatch Model in Widevine CDM\_11
            and Its Hardware-Decode Dormancy on Chrome},
  author = {Erazo, Jeremy},
  year   = {2026},
  note   = {Draft},
  url    = {https://github.com/TREXNEGRO/widevine-cdm11-architecture}
}
```

## Contact

Issues and questions: open an issue on this repo.

Coordinated-disclosure-track findings or vendor-relevant
follow-on work should be sent to the appropriate vendor security
channel (Google Chrome VRP, Widevine Security, etc.); this repo is
for the architectural research only.
