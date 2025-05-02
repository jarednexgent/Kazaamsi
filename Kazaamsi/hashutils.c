#include <windows.h>
#include <stdio.h>
#include "structs.h"
#include "hashutils.h"

#define CRC32_POLY 0xEDB88320

static char CharToUpper(char c) {
    return (c >= 'a' && c <= 'z') ? (c - 'a' + 'A') : c;
}

VOID CharBufToUpper(char* dst, const char* src, size_t maxLen) {
    for (size_t i = 0; i < maxLen && src[i] != '\0'; i++) {
        dst[i] = CharToUpper(src[i]);
    }
    dst[maxLen - 1] = '\0';
}

// CRC32 hash function
DWORD CRC32(const char* str) {
    DWORD crc = 0xFFFFFFFF;
    while (*str) {
        char c = *str++;
        if (c >= 'a' && c <= 'z') c -= 32;  // convert to uppercase
        crc ^= c;
        for (int i = 0; i < 8; i++) {
            DWORD mask = -(int)(crc & 1);
            crc = (crc >> 1) ^ (CRC32_POLY & mask);
        }
    }
    return ~crc;
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
        if (CRC32(name) == dwProcHash) {
            return (PVOID)(base + functions[ordinals[i]]);
        }
    }
    return NULL;
}

HMODULE GetModuleHandleH(DWORD dwModuleHash) {
    
    CHAR            modNameA[MAX_PATH]   = { 0 };
    DWORD           modNameHash;
    
    PPEB            pPeb                 =   (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA   pPebLdrData          =   pPeb->Ldr;
    PLIST_ENTRY     pListEntry           =   &pPebLdrData->InMemoryOrderModuleList;

    for (PLIST_ENTRY pEntry = pListEntry->Flink; pEntry != pListEntry; pEntry = pEntry->Flink) {
       
        PLDR_DATA_TABLE_ENTRY pDte = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (!pDte->BaseDllName.Buffer || pDte->BaseDllName.Length == 0 || pDte->BaseDllName.Length > 512) 
            continue;
        
        WCHAR* wideStr = pDte->BaseDllName.Buffer;
        int wcharLen = pDte->BaseDllName.Length / sizeof(WCHAR);
        if (wcharLen <= 0 || wcharLen >= MAX_PATH) 
            continue;
        
        WideCharToMultiByte(CP_ACP, 0, pDte->BaseDllName.Buffer, -1, modNameA, MAX_PATH, NULL, NULL);
        for (int j = 0; modNameA[j]; j++) {
            if (modNameA[j] >= 'a' && modNameA[j] <= 'z')
                modNameA[j] -= 32;
        }      

        modNameHash = CRC32(modNameA);
        if (modNameHash == dwModuleHash)
            return (HMODULE)pDte->DllBase;
    }
    return NULL;
}
