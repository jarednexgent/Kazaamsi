# Kazaamsi

Kazaamsi is a specialized AMSI bypass tool built for remote processes. It works by finding the target's `amsi.dll` module, computing the offset to `AmsiScanBuffer`, and patching the function so it returns a benign result at runtime.

## Usage

Run `Kazaamsi.exe` against a target process by providing its PID. Use `-v` for verbose output.

```
Kazaamsi.exe <PID> [-v]
```

[![kazaamsi-demo.gif](https://i.postimg.cc/8Ckwp6BZ/kazaamsi-demo.gif)](https://postimg.cc/QFPcSVz7)

## Build

### Visual Studio 2022

1. Open the `Kazaamsi.sln` solution file in Visual Studio
2. Set the configuration to `Release` and the platform to `x64`
3. Go to `Build` → `Build Solution` to compile the executable

### MSBuild

If you prefer building from the command line, you can compile the project using MSBuild.

```
msbuild Kazaamsi.sln /m /p:Configuration=Release;Platform=x64
```
