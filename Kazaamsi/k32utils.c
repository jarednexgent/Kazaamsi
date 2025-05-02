#include "k32utils.h"   

// function pointer declarations
pLoadLibraryA                 fnLoadLibraryA				= NULL;
pVirtualProtectEx             fnVirtualProtectEx			= NULL;
pWriteProcessMemory           fnWriteProcessMemory			= NULL;
pCreateToolhelp32Snapshot     fnCreateToolhelp32Snapshot    = NULL;
pModule32FirstW               fnModule32FirstW				= NULL;
pModule32NextW                fnModule32NextW				= NULL;
pCloseHandle                  fnCloseHandle					= NULL;
pOpenProcess                  fnOpenProcess					= NULL;
