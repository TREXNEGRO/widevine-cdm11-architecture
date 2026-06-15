/* wv_unit_test.c — direct unit test of wv_shim.dll hook function.
 *
 * Loads wv_shim.dll in OUR process, constructs a synthetic InputBuffer_2,
 * sets g_pOrigDecrypt = NULL (so hook skips orig call), invokes WvDecryptHook,
 * and verifies wv_shape.jsonl gets a log entry.
 *
 * This validates Phase 1 hook MECHANICS without needing Chrome to actually
 * exercise the dispatch path. Confirms:
 *   - shim loads cleanly
 *   - DllMain initializes
 *   - g_calls increments
 *   - safe_copy reads ib correctly
 *   - fopen + fprintf to jsonl works from this context
 *
 * Build:  x86_64-w64-mingw32-gcc -O2 -static wv_unit_test.c -o wv_unit_test.exe
 */
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Match shim's InputBuffer_2 layout exactly */
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

typedef int32_t (*fn_Hook)(void *cdm_instance, const InputBuffer_2 *ib, void *output_obj);
typedef int32_t (*fn_Orig)(void *, const InputBuffer_2 *, void *);

int main(int argc, char **argv) {
    const char *shim_path = (argc > 1) ? argv[1] : "C:\\PublicLab\\wv_shim.dll";
    printf("[*] loading %s\n", shim_path);
    HMODULE h = LoadLibraryA(shim_path);
    if (!h) {
        printf("[!] LoadLibrary failed err=%lu\n", GetLastError());
        return 1;
    }
    printf("[+] shim loaded at %p\n", (void*)h);

    fn_Hook hook = (fn_Hook)GetProcAddress(h, "WvDecryptHook");
    fn_Orig *pOrig = (fn_Orig*)GetProcAddress(h, "g_pOrigDecrypt");
    volatile LONG *gCalls = (volatile LONG*)GetProcAddress(h, "g_calls");
    volatile LONG *gInit = (volatile LONG*)GetProcAddress(h, "g_initialized");
    char *logPath = (char*)GetProcAddress(h, "g_logPath");

    if (!hook || !pOrig || !gCalls || !gInit) {
        printf("[!] missing exports: hook=%p pOrig=%p gCalls=%p gInit=%p\n",
               (void*)hook, (void*)pOrig, (void*)gCalls, (void*)gInit);
        return 1;
    }
    printf("[+] WvDecryptHook = %p\n", (void*)hook);
    printf("[+] g_initialized = %ld\n", *gInit);
    printf("[+] g_calls (pre) = %ld\n", *gCalls);
    printf("[+] g_logPath = %s\n", logPath ? logPath : "(null)");

    /* Set g_pOrigDecrypt = NULL so hook skips orig invocation */
    *pOrig = NULL;
    printf("[+] g_pOrigDecrypt = NULL (hook will skip orig call)\n");

    /* Build synthetic InputBuffer_2 */
    static const uint8_t key_id[16] = {
        0xab, 0xba, 0xcd, 0xdc, 0xef, 0xfe, 0x01, 0x10,
        0x23, 0x32, 0x45, 0x54, 0x67, 0x76, 0x89, 0x98
    };
    static const uint8_t iv[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };
    /* data_size: we set non-zero so shape logs it, but data ptr we leave NULL
     * (the shim skips data copy when ptr is NULL). Wait — the shim writes
     * to JSONL regardless of data presence. Just sets is=data_size in the line. */
    InputBuffer_2 ib;
    memset(&ib, 0, sizeof(ib));
    ib.encryption_scheme = 2;                  /* Cbcs */
    ib.data = NULL;
    ib.data_size = 12345;
    ib.key_id = key_id;
    ib.key_id_size = 16;
    ib.iv = iv;
    ib.iv_size = 16;
    ib.subsamples = NULL;
    ib.num_subsamples = 7;
    ib.pattern_crypt = 1;
    ib.pattern_skip = 9;
    ib.timestamp = 1234567890LL;

    printf("[*] Invoking WvDecryptHook 5 times to validate logging path...\n");
    for (int i = 0; i < 5; i++) {
        int32_t r = hook((void*)0xDEADBEEFCAFE0000ULL, &ib, NULL);
        printf("    call %d: returned %d, g_calls=%ld\n", i+1, r, *gCalls);
    }

    /* Force shim's FILE* to close via DllMain DETACH */
    printf("[*] FreeLibrary -> triggers DllMain DLL_PROCESS_DETACH -> closes file\n");
    FreeLibrary(h);
    Sleep(200);
    printf("\n[*] reading log %s\n", logPath);
    FILE *f = fopen(logPath, "r");
    if (!f) {
        printf("[!] log not found (fopen err)\n");
        return 1;
    }
    char buf[2048];
    int lines = 0;
    while (fgets(buf, sizeof(buf), f)) {
        printf("    line %d: %s", ++lines, buf);
        if (lines >= 10) break;
    }
    fclose(f);
    printf("[+] %d log lines\n", lines);

    return 0;
}
