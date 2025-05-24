#pragma once
#include <windows.h>

#ifndef HASH_UTILS_H
#define HASH_UTILS_H

DWORD CRC32BA(LPCSTR cString);

HMODULE GetModuleHandleH(UINT32 uDllNameHash);

LPVOID GetProcAddressH(HMODULE hModule, DWORD dwProcHash);

#define LoadLibraryA_CRC32					0x713C5123
#define VirtualProtectEx_CRC32				0x6022B086
#define WriteProcessMemory_CRC32			0x8F62A3DE
#define CreateToolhelp32Snapshot_CRC32		0x8EF931AC
#define Module32FirstW_CRC32				0xBE0DD30F
#define Module32NextW_CRC32					0x93BEF919
#define CloseHandle_CRC32					0x49FCEF16
#define OpenProcess_CRC32					0x2648ABA9
#define AmsiScanBuffer_CRC32				0xD2961CC0
#define KERNEL32_CRC32						0xD776BFB0
#define AMSI_CRC32							0xF9ED5173

#endif 
