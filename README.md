# Kazaamsi

[![kazaamsi-logo.png](https://i.postimg.cc/1zSBCgkM/kazaamsi-logo.png)](https://postimg.cc/v4P5DmH6)

#### Remote AMSI Bypass via AmsiScanBuffer Patching

Kazaamsi is a lightweight tool for disabling the Windows Antimalware Scan Interface (AMSI) in remote processes by directly patching the `AmsiScanBuffer` function. It operates out of process, allowing you to neutralize AMSI protections in arbitrary targets—such as injected PowerShell or CLR hosts.

---

### Features 

- In-memory patching (no DLL injection or file drops)
- Targets remote processes by PID
- Extracts the `AmsiScanBuffer` function offset dynamically by parsing the in-memory `amsi.dll`
- Overwrites it with a clean `xor eax, eax; ret` stub, setting the [Common HRESULT Value](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) to `S_OK`
- Performs hash-based API resolution to evade static imports and reduce signature exposure

---

### Usage

```cmd
Kazaamsi.exe <PID> [-v]
```

[![kazaamsi.png](https://i.postimg.cc/kGpvGPDS/kazaamsi.png)](https://postimg.cc/CnbqrtGM)

---

### Build

**Visual Studio**  
1. Open `Kazaamsi.sln` in Visual Studio  
2. Set **Configuration** to `Release` and **Platform** to `x64`  
3. Project Properties → C/C++ → Code Generation  
   - Runtime Library: Multi-threaded (/MT)  
   - Enable C++ Exceptions: No  
4. C/C++ → Optimization → Whole Program Optimization: No  
5. Linker → Debugging → Generate Debug Info: No  
6. Linker → Manifest → Generate Manifest: No  
7. Build the solution
---


