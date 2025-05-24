#include <windows.h>
#include <stdio.h>
#include "structs.h"
#include "hashutils.h"

UINT32 CRC32BA(LPCSTR cString) {

    UINT32      uMask = 0x00,
        uHash = 0x0BADC0DE;
    INT         i = 0x00;

    while (cString[i] != 0) {

        uHash = uHash ^ (UINT32)cString[i];

        for (int ii = 0; ii < 8; ii++) {

            uMask = -1 * (uHash & 1);
            uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
        }

        i++;
    }
    return ~uHash;
}

HMODULE GetModuleHandleH(UINT32 uDllNameHash) {

    PPEB                    pPeb = NULL;
    PPEB_LDR_DATA           pLdrData = NULL;
    PLDR_DATA_TABLE_ENTRY   pDataTableEntry = NULL;

#ifdef _WIN64
    pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    pPeb = (PEB*)(__readfsdword(0x30));
#endif

    pLdrData = (PPEB_LDR_DATA)(pPeb->Ldr);
    pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pLdrData->InMemoryOrderModuleList.Flink);

    if (!uDllNameHash)
        return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);

    while (pDataTableEntry->FullDllName.Buffer) {

        if (pDataTableEntry->FullDllName.Length > 0x00 && pDataTableEntry->FullDllName.Length < MAX_PATH) {

            CHAR	cUprDllFileName[MAX_PATH] = { 0x00 };

            for (int i = 0; i < pDataTableEntry->FullDllName.Length; i++) {
                if (pDataTableEntry->FullDllName.Buffer[i] >= 'a' && pDataTableEntry->FullDllName.Buffer[i] <= 'z')
                    cUprDllFileName[i] = pDataTableEntry->FullDllName.Buffer[i] - 'a' + 'A';
                else
                    cUprDllFileName[i] = pDataTableEntry->FullDllName.Buffer[i];
            }

            if (CRC32BA(cUprDllFileName) == uDllNameHash)
                return (HMODULE)(pDataTableEntry->InInitializationOrderLinks.Flink);
        }

        pDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pDataTableEntry);
    }

    return NULL;
}

LPVOID GetProcAddressH(HMODULE hModule, DWORD dwProcHash) {
    if (!hModule || !dwProcHash) return NULL;

    PBYTE base = (PBYTE)hModule;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)(base + names[i]);
        if (CRC32BA(name) == dwProcHash) {
            return (PVOID)(base + functions[ordinals[i]]);
        }
    }
    return NULL;
}

