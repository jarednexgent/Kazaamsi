# Kazaamsi

[![kazaamsi-logo.png](https://i.postimg.cc/y62mP6yP/kazaamsi-logo.png)](https://postimg.cc/V5B0s8Tr)

Kazaamsi is a minimal AMSI bypass tool built for remote processes. It locates and patches the `AmsiScanBuffer` function in memory, effectively disabling AMSI in environments like injected PowerShell or CLR hosts.

## Features 

- Targets remote processes by PID
- Calculates the address of `AmsiScanBuffer` using offset math
- Overwrites the function with a `xor eax, eax; ret` assembly stub, forcing it to return an `S_OK` [HRESULT](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values)
- Performs hash-based API resolution

## Usage

Run Kazaamsi against a target process by specifying its PID. Use `-v` for verbose output.

```cmd
Kazaamsi.exe <PID> [-v]
```

[![kazaamsi-demo.gif](https://i.postimg.cc/0rRWNKY7/kazaamsi-demo.gif)](https://postimg.cc/m1jNXD6r)


## Build

### Visual Studio 2022

1. Open `Kazaamsi.sln`
2. Set configuration to `Release` and platform to `x64`
3. On the menu bar choose `Build` → `Build Solution`

### Developer Command Prompt for VS 2022

```cmd
msbuild Kazaamsi.sln /m /p:Configuration=Release;Platform=x64
```



