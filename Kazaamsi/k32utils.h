#pragma once
#include <windows.h>
#include <tlhelp32.h>

#ifndef K32_UTILS_H
#define K32_UTILS_H


typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef BOOL(WINAPI* pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* pModule32FirstW)(HANDLE, LPMODULEENTRY32W);
typedef BOOL(WINAPI* pModule32NextW)(HANDLE, LPMODULEENTRY32W);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);

extern pLoadLibraryA             fnLoadLibraryA;
extern pVirtualProtectEx         fnVirtualProtectEx;
extern pWriteProcessMemory       fnWriteProcessMemory;
extern pCreateToolhelp32Snapshot fnCreateToolhelp32Snapshot;
extern pModule32FirstW           fnModule32FirstW;
extern pModule32NextW            fnModule32NextW;
extern pCloseHandle              fnCloseHandle;
extern pOpenProcess              fnOpenProcess;

#endif