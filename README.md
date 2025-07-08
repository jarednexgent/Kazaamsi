# Kazaamsi

[![kazaamsi-logo.png](https://i.postimg.cc/y62mP6yP/kazaamsi-logo.png)](https://postimg.cc/V5B0s8Tr)

#### Remote AMSI Bypass via AmsiScanBuffer Patching

Kazaamsi is a minimal AMSI bypass tool built for remote processes. It locates and patches the `AmsiScanBuffer` function in memory, effectively disabling AMSI in environments like injected PowerShell or CLR hosts.

---

### Features 

- Targets remote processes by PID
- Calculates the address of `AmsiScanBuffer` using offset math
- Overwrites the function with a `xor eax, eax; ret` assembly stub, forcing it to return an `S_OK` [HRESULT](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values)
- Performs hash-based API resolution

---

### Usage

Run Kazaamsi against a target process by specifying its PID. Use `-v` for verbose output.

```cmd
Kazaamsi.exe <PID> [-v]
```

[![kazaamsi-demo.gif](https://i.postimg.cc/0rRWNKY7/kazaamsi-demo.gif)](https://postimg.cc/m1jNXD6r)

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
