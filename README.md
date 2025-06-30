# Kazaamsi

[![kazaamsi-logo.png](https://i.postimg.cc/y62mP6yP/kazaamsi-logo.png)](https://postimg.cc/V5B0s8Tr)

#### Remote AMSI Bypass via AmsiScanBuffer Patching

Kazaamsi is a specialized utility designed to disable the Windows Antimalware Scan Interface (AMSI) in remote processes. It achieves this by directly patching the `AmsiScanBuffer` function, thereby neutralizing AMSI protections in arbitrary targets—such as injected PowerShell or CLR hosts.

---

### Features 

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
3. Go to **Project → Properties** and configure:  
   - **C/C++ → Code Generation**  
     - Runtime Library: Multi-threaded (/MT)  
     - Enable C++ Exceptions: No  
   - **C/C++ → Optimization → Whole Program Optimization:** No  
   - **Linker → Debugging → Generate Debug Info:** No  
   - **Linker → Manifest → Generate Manifest:** No  
4. Build the solution.

---
