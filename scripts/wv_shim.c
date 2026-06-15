/* wv_shim.dll — Widevine CDM_11 PER-SLOT shape-only observation hooks
 *
 * Each slot gets its own exported hook function (WvHookSlot0..WvHookSlot18)
 * with its own g_pOrigSlot_N back-pointer. The helper patches each slot to
 * its dedicated hook. This avoids the single-g_pOrigDecrypt signature-mismatch
 * crash observed when patching multiple session-lifecycle slots.
 *
 * Per-slot behavior:
 *   - Slot 14 / 15 (DecryptAndDecodeFrame, DecryptAndDecodeSamples):
 *       (this, const InputBuffer_2*, VideoFrame*|AudioFrames*) -> Status
 *       Log shape from InputBuffer_2 (no bytes of data/key_id/iv).
 *   - Slot 9 (Decrypt):
 *       (this, const InputBuffer_2*, DecryptedBlock*) -> Status
 *       Log shape from InputBuffer_2.
 *   - All other slots:
 *       Just log slot number + call count + arg shape (size only of byte buffers).
 *
 * JSONL output: C:\PublicLab\wv_shape.jsonl
 * Shape contains NO bytes of payload, key_id, iv, or output.
 *
 * Build: x86_64-w64-mingw32-gcc -shared -O2 -static-libgcc wv_shim.c -o wv_shim.dll \
 *        -Wl,--out-implib,wv_shim.lib
 */
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t encryption_scheme;
    uint32_t _pad0;
    const uint8_t *data;
    uint32_t data_size;
    uint32_t _pad1;
    const uint8_t *key_id;
    uint32_t key_id_size;
    uint32_t _pad2;
    const uint8_t *iv;
    uint32_t iv_size;
    uint32_t _pad3;
    const void *subsamples;
    uint32_t num_subsamples;
    uint32_t pattern_crypt;
    uint32_t pattern_skip;
    uint32_t _pad4;
    int64_t timestamp;
} InputBuffer_2;
#pragma pack(pop)

/* Generic 3-arg signature (covers slot 9 Decrypt, slot 14 DecryptAndDecodeFrame,
 * slot 15 DecryptAndDecodeSamples). All other slots have varied signatures —
 * we just save args via register passing (rcx, rdx, r8, r9). */
typedef void* (*fn_Generic)(void *rcx, void *rdx, void *r8, void *r9, void *r10);

#define SLOT_COUNT 19

__declspec(dllexport) fn_Generic g_pOrigSlot[SLOT_COUNT] = {0};
__declspec(dllexport) volatile LONG g_initialized = 0;
__declspec(dllexport) volatile LONG g_callsBySlot[SLOT_COUNT] = {0};
__declspec(dllexport) volatile LONG g_calls = 0;     /* aggregate */
__declspec(dllexport) char g_logPath[260] = "C:\\PublicLab\\wv_shape.jsonl";
__declspec(dllexport) char g_summaryPath[260] = "C:\\PublicLab\\wv_shape_summary.log";

static CRITICAL_SECTION g_logCs;
static FILE *g_logFile = NULL;

static uint32_t fnv1a32(const uint8_t *data, size_t len) {
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 0x01000193u; }
    return h;
}

static void open_log_if_needed(void) {
    if (g_logFile) return;
    g_logFile = fopen(g_logPath, "a");
    if (g_logFile) setvbuf(g_logFile, NULL, _IOLBF, 4096);
}

static void summary_log(const char *fmt, ...) {
    FILE *f = fopen(g_summaryPath, "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fclose(f);
}

static int safe_copy(void *dst, const void *src, size_t n) {
    if (!src || !n) return 0;
    const uint8_t *p = (const uint8_t*)src;
    const uint8_t *end = p + n;
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return 0;
        if (mbi.State != MEM_COMMIT) return 0;
        DWORD prot = mbi.Protect & 0xff;
        if (prot != PAGE_READONLY && prot != PAGE_READWRITE &&
            prot != PAGE_EXECUTE_READ && prot != PAGE_EXECUTE_READWRITE &&
            prot != PAGE_WRITECOPY && prot != PAGE_EXECUTE_WRITECOPY) return 0;
        const uint8_t *regionEnd = (const uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > end) regionEnd = end;
        p = regionEnd;
    }
    memcpy(dst, src, n);
    return 1;
}

static int iv_has_nonzero(const uint8_t *iv, size_t n) {
    uint8_t local[64] = {0};
    size_t copy = n > sizeof(local) ? sizeof(local) : n;
    if (!safe_copy(local, iv, copy)) return -1;
    for (size_t i = 0; i < copy; i++) if (local[i]) return 1;
    return 0;
}

static uint32_t key_id_hash(const uint8_t *kid, size_t n) {
    uint8_t local[16] = {0};
    size_t copy = n > sizeof(local) ? sizeof(local) : n;
    if (!safe_copy(local, kid, copy)) return 0;
    return fnv1a32(local, copy);
}

/* Try to log InputBuffer_2 shape if rdx points at one. Returns 1 if shape logged. */
static int log_inputbuffer_shape(int slot, LONG callno, void *ib_ptr) {
    if (!ib_ptr) return 0;
    InputBuffer_2 local_ib = {0};
    if (!safe_copy(&local_ib, ib_ptr, sizeof(local_ib))) return 0;
    /* Sanity gate */
    if (local_ib.iv_size > 64 || local_ib.key_id_size > 64) return 0;
    if (local_ib.data_size > (16*1024*1024)) return 0;
    if (local_ib.encryption_scheme > 3) return 0;

    uint32_t kh = (local_ib.key_id && local_ib.key_id_size > 0)
                  ? key_id_hash(local_ib.key_id, local_ib.key_id_size) : 0;
    int ivnz = (local_ib.iv && local_ib.iv_size > 0)
               ? iv_has_nonzero(local_ib.iv, local_ib.iv_size) : -1;

    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);

    EnterCriticalSection(&g_logCs);
    open_log_if_needed();
    if (g_logFile) {
        fprintf(g_logFile,
            "{\"kind\":\"ib\",\"slot\":%d,\"n\":%ld,\"tsc\":%llu,"
            "\"es\":%u,\"is\":%u,\"kis\":%u,\"kh\":%u,\"ivs\":%u,\"ivnz\":%d,"
            "\"ns\":%u,\"pc\":%u,\"ps\":%u,\"mt\":%lld}\n",
            slot, callno, (unsigned long long)li.QuadPart,
            local_ib.encryption_scheme, local_ib.data_size,
            local_ib.key_id_size, kh, local_ib.iv_size, ivnz,
            local_ib.num_subsamples, local_ib.pattern_crypt,
            local_ib.pattern_skip, (long long)local_ib.timestamp);
    }
    LeaveCriticalSection(&g_logCs);
    return 1;
}

/* Log a "generic call" event when we can't interpret args as InputBuffer_2.
 * Captures only register-values (which are integers/pointers themselves, no
 * dereferences to user data). */
static void log_generic_call(int slot, LONG callno,
                              void *rcx, void *rdx, void *r8, void *r9) {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    EnterCriticalSection(&g_logCs);
    open_log_if_needed();
    if (g_logFile) {
        /* Mask register values to hash to avoid leaking address-space details
         * beyond what is needed for paper analysis. */
        uint32_t rh = fnv1a32((uint8_t*)&rcx, sizeof(rcx)) ^
                       fnv1a32((uint8_t*)&rdx, sizeof(rdx)) ^
                       fnv1a32((uint8_t*)&r8, sizeof(r8))  ^
                       fnv1a32((uint8_t*)&r9, sizeof(r9));
        fprintf(g_logFile,
            "{\"kind\":\"call\",\"slot\":%d,\"n\":%ld,\"tsc\":%llu,\"rh\":%u}\n",
            slot, callno, (unsigned long long)li.QuadPart, rh);
    }
    LeaveCriticalSection(&g_logCs);
}

/* Per-slot hook implementations. Each preserves arg registers, calls original
 * via its own g_pOrigSlot[N], logs shape, returns. */
#define DEFINE_HOOK(N) \
__declspec(dllexport) void* WvHookSlot##N(void *rcx, void *rdx, void *r8, void *r9, void *r10) { \
    LONG callno = InterlockedIncrement(&g_callsBySlot[N]); \
    InterlockedIncrement(&g_calls); \
    void *result = NULL; \
    if (g_pOrigSlot[N]) { \
        result = g_pOrigSlot[N](rcx, rdx, r8, r9, r10); \
    } \
    if (!g_initialized) return result; \
    /* Slots 9, 14, 15 take InputBuffer_2 in rdx */ \
    if ((N == 9 || N == 14 || N == 15) && rdx) { \
        if (log_inputbuffer_shape(N, callno, rdx)) return result; \
    } \
    /* Fallback: generic call log */ \
    log_generic_call(N, callno, rcx, rdx, r8, r9); \
    return result; \
}

DEFINE_HOOK(0)  DEFINE_HOOK(1)  DEFINE_HOOK(2)  DEFINE_HOOK(3)  DEFINE_HOOK(4)
DEFINE_HOOK(5)  DEFINE_HOOK(6)  DEFINE_HOOK(7)  DEFINE_HOOK(8)  DEFINE_HOOK(9)
DEFINE_HOOK(10) DEFINE_HOOK(11) DEFINE_HOOK(12) DEFINE_HOOK(13) DEFINE_HOOK(14)
DEFINE_HOOK(15) DEFINE_HOOK(16) DEFINE_HOOK(17) DEFINE_HOOK(18)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    (void)hModule; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logCs);
        InterlockedExchange(&g_initialized, 1);
        summary_log("[%lu] wv_shim per-slot attached pid=%lu log=%s\n",
                    GetTickCount(), GetCurrentProcessId(), g_logPath);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_logFile) { fclose(g_logFile); g_logFile = NULL; }
        DeleteCriticalSection(&g_logCs);
        LONG total = g_calls;
        summary_log("[%lu] wv_shim per-slot detached total_calls=%ld "
                    "byslot=[%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,"
                    "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld]\n",
                    GetTickCount(), total,
                    g_callsBySlot[0], g_callsBySlot[1], g_callsBySlot[2],
                    g_callsBySlot[3], g_callsBySlot[4], g_callsBySlot[5],
                    g_callsBySlot[6], g_callsBySlot[7], g_callsBySlot[8],
                    g_callsBySlot[9], g_callsBySlot[10], g_callsBySlot[11],
                    g_callsBySlot[12], g_callsBySlot[13], g_callsBySlot[14],
                    g_callsBySlot[15], g_callsBySlot[16], g_callsBySlot[17],
                    g_callsBySlot[18]);
    }
    return TRUE;
}
