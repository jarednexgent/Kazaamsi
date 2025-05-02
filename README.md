# Kazaamsi

#### Remote AMSI Bypass via AmsiScanBuffer Patching

Kazaamsi is a lightweight tool for disabling Windows Antimalware Scan Interface (AMSI) in remote processes by directly patching the `AmsiScanBuffer` function. 

Operates out-of-process, allowing you to neutralize AMSI protections in arbitrary targets, such as injected PowerShell or CLR hosts.

---

### Features 

- In-memory patching (no DLL injection or file drops)
- Targets remote processes by PID
- Extracts the `AmsiScanBuffer` function offset dynamically by parsing the in-memory `amsi.dll`
- Overwrites it with a clean `xor eax, eax; ret` stub, setting the [Common HRESULT Value](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) to `S_OK`
- Performs hash-based API resolution to evade static imports and reduce signature exposure

---

### Build Instructions

**Visual Studio**
1. Open Solution File `Kazaamsi.sln` in Visual Studio

2. Configure Build:
    - `Configuration: Release`
    - `Platform: x64`
	
3. Configure Project Properties:
	- C/C++ → Code Generation:
    `Runtime Library: Multi-threaded (/MT)`
    `Enable C++ Exceptions: No`

	- C/C++ → Optimization:
    `Whole Program Optimization: No`

	- Linker → Debugging:
    `Generate Debug Info: No`

	- Linker → Manifest:
    `Generate Manifest: No`
	
4. Select `Build` → `Build Solution`

### Usage

```cmd
Kazaamsi.exe <PID> [-v]
```

[![kazaamsi.png](https://i.postimg.cc/7h5N4cnv/kazaamsi.png)](https://postimg.cc/SYp97gPV)
