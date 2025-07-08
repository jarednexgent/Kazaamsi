#include <windows.h>
#include <stdio.h>
#include "structs.h"
#include "api.h"

UINT32 CRC32BA(LPCSTR cStringA) {
    UINT32      uMask = 0x00;
    UINT32      uHash = 0x0BADC0DE;
    INT         i = 0x00;

    while (cStringA[i] != 0) {
        uHash = uHash ^ (UINT32)cStringA[i];

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
    PPEB_LDR_DATA           pPebLdrData = NULL;
    PLDR_DATA_TABLE_ENTRY   pLdrDataTableEntry = NULL;

#ifdef _WIN64
    pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    pPeb = (PEB*)(__readfsdword(0x30));
#endif

    pPebLdrData = (PPEB_LDR_DATA)(pPeb->Ldr);
    pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)(pPebLdrData->InMemoryOrderModuleList.Flink);

    if (!uDllNameHash)
        return (HMODULE)(pLdrDataTableEntry->InInitializationOrderLinks.Flink);

    while (pLdrDataTableEntry->FullDllName.Buffer) {
        if (pLdrDataTableEntry->FullDllName.Length > 0x00 && pLdrDataTableEntry->FullDllName.Length < MAX_PATH) {
            CHAR	cUprDllFileName[MAX_PATH] = { 0x00 };

            for (int i = 0; i < pLdrDataTableEntry->FullDllName.Length; i++) {
                if (pLdrDataTableEntry->FullDllName.Buffer[i] >= 'a' && pLdrDataTableEntry->FullDllName.Buffer[i] <= 'z')
                    cUprDllFileName[i] = pLdrDataTableEntry->FullDllName.Buffer[i] - 'a' + 'A';
                else
                    cUprDllFileName[i] = pLdrDataTableEntry->FullDllName.Buffer[i];
            }

            if (CRC32BA(cUprDllFileName) == uDllNameHash)
                return (HMODULE)(pLdrDataTableEntry->InInitializationOrderLinks.Flink);
        }
        pLdrDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pLdrDataTableEntry);
    }
    return NULL;
}

LPVOID GetProcAddressH(HMODULE hModule, DWORD dwProcHash) {

    if (!hModule || !dwProcHash)
        return NULL;

    PBYTE pModBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pModBase;
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pModBase + pImgDosHdr->e_lfanew);

    DWORD dwExportRVA = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (!dwExportRVA)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pModBase + dwExportRVA);
    DWORD* pAddressOfNames = (DWORD*)(pModBase + pImgExportDir->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)(pModBase + pImgExportDir->AddressOfNameOrdinals);
    DWORD* pAddressOfFunctions = (DWORD*)(pModBase + pImgExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        char* cName = (char*)(pModBase + pAddressOfNames[i]);
        if (CRC32BA(cName) == dwProcHash) {
            return (PVOID)(pModBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

