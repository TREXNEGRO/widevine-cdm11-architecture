/* wv_helper3.c — per-slot patcher for Chrome 149 CDM_11 OUTER VTABLE.
 *
 * Identical to wv_helper2.c but patches outer_vtable[N] at
 * RVA 0x768fa0 (Chrome 149) instead of singleton_impl[N].
 *
 * This is the correct vtable for hooking the PUBLIC CDM_11 interface
 * (CreateSessionAndGenerateRequest, UpdateSession, DecryptAndDecodeFrame,
 * etc.). Use this when you want to observe the EME-host-facing surface,
 * NOT the internal CDM library plumbing.
 *
 * Usage: wv_helper3.exe <shim_dll> <pid> --slots <list>
 *
 * Build: x86_64-w64-mingw32-gcc -O2 -static wv_helper3.c -o wv_helper3.exe
 */
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHROME149_OUTER_VTABLE_RVA 0x768fa0

typedef BOOL (WINAPI *SPVCT_t)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);

static DWORD_PTR find_widevine_base(HANDLE hp, DWORD_PTR *sizeOut) {
    HMODULE mods[2048]; DWORD cb;
    if (!EnumProcessModulesEx(hp, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) return 0;
    int n = cb / sizeof(HMODULE);
    for (int i = 0; i < n; i++) {
        WCHAR mn[MAX_PATH];
        if (GetModuleFileNameExW(hp, mods[i], mn, MAX_PATH) &&
            wcsstr(mn, L"widevinecdm.dll")) {
            MODULEINFO mi;
            if (GetModuleInformation(hp, mods[i], &mi, sizeof(mi)))
                *sizeOut = mi.SizeOfImage;
            return (DWORD_PTR)mods[i];
        }
    }
    return 0;
}

static HMODULE inject_dll(HANDLE hp, const char *dllPath) {
    /* If shim already loaded, return existing handle */
    HMODULE mods[2048]; DWORD cb;
    if (EnumProcessModulesEx(hp, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) {
        int n = cb / sizeof(HMODULE);
        for (int i = 0; i < n; i++) {
            WCHAR name[MAX_PATH];
            if (GetModuleFileNameExW(hp, mods[i], name, MAX_PATH) && wcsstr(name, L"wv_shim.dll"))
                return mods[i];
        }
    }
    SIZE_T pathLen = strlen(dllPath) + 1;
    LPVOID alloc = VirtualAllocEx(hp, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) return NULL;
    if (!WriteProcessMemory(hp, alloc, dllPath, pathLen, NULL)) return NULL;
    LPTHREAD_START_ROUTINE pLL =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE th = CreateRemoteThread(hp, NULL, 0, pLL, alloc, 0, NULL);
    if (!th) return NULL;
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    VirtualFreeEx(hp, alloc, 0, MEM_RELEASE);
    if (!EnumProcessModulesEx(hp, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) return NULL;
    int n = cb / sizeof(HMODULE);
    for (int i = 0; i < n; i++) {
        WCHAR name[MAX_PATH];
        if (GetModuleFileNameExW(hp, mods[i], name, MAX_PATH) && wcsstr(name, L"wv_shim.dll"))
            return mods[i];
    }
    return NULL;
}

static DWORD_PTR get_export_rva(const char *localDllPath, const char *name) {
    HMODULE h = LoadLibraryExA(localDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 0;
    DWORD_PTR p = (DWORD_PTR)GetProcAddress(h, name);
    DWORD_PTR rva = p - (DWORD_PTR)h;
    FreeLibrary(h);
    return rva;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        printf("usage: %s <shim_dll> <pid> --slots <list>\n", argv[0]);
        return 1;
    }
    const char *shimPath = argv[1];
    DWORD pid = (DWORD)atoi(argv[2]);
    if (strcmp(argv[3], "--slots") != 0) { printf("expected --slots\n"); return 1; }
    int slotsToHook[32]; int numSlots = 0;
    char *tok = strtok(argv[4], ",");
    while (tok && numSlots < 32) {
        int s = atoi(tok);
        if (s >= 0 && s <= 18) slotsToHook[numSlots++] = s;
        tok = strtok(NULL, ",");
    }
    printf("[*] pid=%lu, will hook outer_vtable slots: ", pid);
    for (int i = 0; i < numSlots; i++) printf("%d ", slotsToHook[i]);
    printf("\n");

    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hp) { printf("[!] OpenProcess err=%lu\n", GetLastError()); return 1; }

    DWORD_PTR wvSize = 0;
    DWORD_PTR wvBase = find_widevine_base(hp, &wvSize);
    if (!wvBase) { printf("[!] no widevinecdm.dll in pid %lu\n", pid); return 1; }
    printf("[+] widevinecdm.dll @ 0x%llx\n", (unsigned long long)wvBase);

    DWORD_PTR outerVtable = wvBase + CHROME149_OUTER_VTABLE_RVA;
    printf("[+] outer_vtable VA = 0x%llx\n", (unsigned long long)outerVtable);

    HMODULE remoteShim = inject_dll(hp, shimPath);
    if (!remoteShim) { printf("[!] inject failed\n"); return 1; }
    printf("[+] wv_shim.dll @ %p (reused if pre-loaded)\n", (void*)remoteShim);

    char nameBuf[32]; DWORD_PTR hookRvas[19];
    for (int s = 0; s < 19; s++) {
        snprintf(nameBuf, sizeof(nameBuf), "WvHookSlot%d", s);
        hookRvas[s] = get_export_rva(shimPath, nameBuf);
        if (!hookRvas[s]) { printf("[!] export %s not found\n", nameBuf); return 1; }
    }
    DWORD_PTR gOrigSlotRva = get_export_rva(shimPath, "g_pOrigSlot");
    if (!gOrigSlotRva) { printf("[!] g_pOrigSlot not found\n"); return 1; }
    DWORD_PTR remoteShimBase = (DWORD_PTR)remoteShim;
    DWORD_PTR gOrigSlotRemote = remoteShimBase + gOrigSlotRva;

    HMODULE kbase = GetModuleHandleA("kernelbase.dll");
    SPVCT_t pSPVCT = kbase ? (SPVCT_t)GetProcAddress(kbase, "SetProcessValidCallTargets") : NULL;
    if (!pSPVCT) { printf("[!] SetProcessValidCallTargets unavailable\n"); }

    int hooked = 0;
    for (int i = 0; i < numSlots; i++) {
        int s = slotsToHook[i];
        DWORD_PTR hookVA = remoteShimBase + hookRvas[s];
        DWORD_PTR slotAddr = outerVtable + s * 8;
        DWORD_PTR origFn = 0;
        if (!ReadProcessMemory(hp, (LPCVOID)slotAddr, &origFn, 8, NULL)) {
            printf("[!] slot %d read err=%lu\n", s, GetLastError()); continue;
        }
        printf("    slot %2d: orig=0x%llx (rva 0x%llx), hook=0x%llx\n",
               s, (unsigned long long)origFn,
               (unsigned long long)(origFn - wvBase),
               (unsigned long long)hookVA);

        if (pSPVCT) {
            CFG_CALL_TARGET_INFO cti;
            cti.Offset = (DWORD)(hookVA & 0xfff);
            cti.Flags = CFG_CALL_TARGET_VALID;
            DWORD_PTR pageBase = hookVA & ~0xfffULL;
            BOOL ok = pSPVCT(hp, (PVOID)pageBase, 0x1000, 1, &cti);
            if (!ok) printf("        [!] SPVCT err=%lu\n", GetLastError());
        }

        /* Save outer_vtable[s] orig (the thunk) into g_pOrigSlot[s].
         * When WvHookSlotN calls g_pOrigSlot[N], it dispatches via the orig
         * thunk → m_impl_vtable[N] → real impl. Signature matches. */
        DWORD_PTR origSlotPtrRemote = gOrigSlotRemote + s * 8;
        if (!WriteProcessMemory(hp, (LPVOID)origSlotPtrRemote, &origFn, 8, NULL)) {
            printf("        [!] write g_pOrigSlot[%d] err=%lu\n", s, GetLastError()); continue;
        }

        DWORD oldProt = 0;
        VirtualProtectEx(hp, (LPVOID)slotAddr, 8, PAGE_READWRITE, &oldProt);
        BOOL pok = WriteProcessMemory(hp, (LPVOID)slotAddr, &hookVA, 8, NULL);
        DWORD perr = GetLastError();
        VirtualProtectEx(hp, (LPVOID)slotAddr, 8, oldProt, &oldProt);
        if (!pok) { printf("        [!] patch err=%lu\n", perr); continue; }
        printf("        [+] HOOKED outer_vtable[%d]\n", s);
        hooked++;
    }
    printf("[*] hooked: %d / %d\n", hooked, numSlots);
    CloseHandle(hp);
    return 0;
}
