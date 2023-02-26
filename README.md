<h1 align="center">.Net Security Library</h1>

![process scanner github banner](https://user-images.githubusercontent.com/116961227/221389858-d7c6b97c-973d-4682-a850-a232e197d44b.png)  

<p align="center">
  <img src="https://camo.githubusercontent.com/24a30795e82acbe97d52679bad22f606eb8e81723c08bc271dbd6d9ff0ea7022/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f6c616e67756167652d432532422532422d2532336633346237642e7376673f7374796c653d666f722d7468652d6261646765266c6f676f3d6170707665796f72">
  <img src="https://camo.githubusercontent.com/84f42f3d8ef4a6099b5607c98cbb247321215894bf3ac2e4fb6ee15b3eed619d/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f706c6174666f726d2d57696e646f77732d3030373864372e7376673f7374796c653d666f722d7468652d6261646765266c6f676f3d6170707665796f72">
  <img src="https://camo.githubusercontent.com/5ea2ccf2a2704626d0f780740a4eed86dc5abb7cb150191b16a20a6b6162751d/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f617263682d7836342d677265656e2e7376673f7374796c653d666f722d7468652d6261646765266c6f676f3d6170707665796f72">
  <img src="https://camo.githubusercontent.com/4caf9d14d59a3f73a89fd007854441d3869e6f725cc7363a41d6775a804b3a8f/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f617263682d7838362d7265642e7376673f7374796c653d666f722d7468652d6261646765266c6f676f3d6170707665796f72">
</p>

# 📖 Project Overview
.Net Security Library is a collection of methods for detecting potential security risks in .NET applications. It includes features such as anti-debugging, anti-dumping, and virtual machine detection, and can be used for identifying software dependencies or analyzing system security. The library is designed for use by developers who want to improve the security of their .NET applications or by security researchers who want to analyze and evaluate the security of .NET applications. With a simple and intuitive interface, the .Net Security Library is easy to use and provides powerful security features to protect against various security threats.

## 🚀 Getting Started
1. Open the solution file (.sln).
2. Build the project in Realese (x86) or Release (x64).

## 🧪 Usage

```
IntPtr address = new IntPtr(0x12345678);
int size = 512;
Protect.EraseSection(address, size);
```
