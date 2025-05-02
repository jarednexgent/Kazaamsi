#pragma once
#include <windows.h>

#ifndef HASH_UTILS_H
#define HASH_UTILS_H

static char CharToUpper(char c);
VOID CharBufToUpper(char* dst, const char* src, size_t maxLen);
DWORD CRC32(const char* str);
LPVOID GetProcAddressH(HMODULE hModule, DWORD dwProcHash);
HMODULE GetModuleHandleH(DWORD dwModuleHash);

#endif 
