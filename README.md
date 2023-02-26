<h1 align="center">.Net Security Library</h1>

![net security library github banner](https://user-images.githubusercontent.com/116961227/221432116-1e85a8bd-797b-4eb5-96b1-c7f0c32c991d.png)

<p align="center">
  <img src="https://img.shields.io/badge/c%23-%23239120.svg?style=for-the-badge&logo=c-sharp&logoColor=white" alt="C# Badge"/>
  <img src="https://img.shields.io/badge/.NET-5C2D91?style=for-the-badge&logo=.net&logoColor=white" alt=".NET Badge"/>
</p>

# 📖 Project Overview
.Net Security Library is a collection of basic anti-debug measures implemented as static methods in C#. These methods can be used to protect .NET applications from being reverse engineered, tampered with, or otherwise exploited. However, it is important to note that these measures are relatively simple and can be easily bypassed by skilled attackers. They should be used as one part of a comprehensive security strategy, rather than as a complete solution on their own.

## 🚀 Getting Started
1. Open the solution file (.sln).
2. Build the project in Realese (x86) or Release (x64).

## ✔️ Methods
- (bool) AntiDebug()
- (bool) Sandboxie()
- (bool) DetectVM()
- (void) EraseSection(IntPtr address, int size)
- (bool) WebSniffers()
- (bool) Emulation()
- (bool) AntiDump()
- (bool) CheckDnSpyInstallation()
- (bool) CheckIDAProInstallation()
- (bool) DisableDebugger()

## 🧪 Usage

```
IntPtr address = new IntPtr(0x12345678);
int size = 512;
Protect.EraseSection(address, size);
```
## Demonstration
https://user-images.githubusercontent.com/116961227/221431141-66e97ad0-db5e-46b4-9415-fe9f275046db.mp4
