# EDR-XDR-AV-Bypass-Shellcode-Loader
- CURRENTLY BYPASSES CROWDSTRIKE & SENTINEL ONE RUNTIME.
- SCROLL DOWN TO FIND DETECTIONS (RUNTIME & STATIC TIME ANALYSIS)
---
- Want paid version? contact me at : https://t.me/codepulze
- <a href="https://t.me/pulzetools"><img src="https://img.shields.io/badge/Join%20my%20Telegram%20group-2CA5E0?style=for-the-badge&logo=telegram&labelColor=db44ad&color=5e2775"></a>
- [Join our Discord server!](https://discord.gg/NRTdwYUtdQ)

---

## Overview
This project provides an advanced shellcode loader capable of bypassing major EDRs (Endpoint Detection and Response), XDRs, and AV (Antivirus) systems. The shellcode is executed in a staged manner with techniques such as memory protection manipulation, VEH (Vectored Exception Handling), and system calls to evade detection.

## Features
- **Staged Shellcode Execution**: Downloads and executes shellcode in multiple steps to minimize detection.
- **Custom Memory Protection**: Evading modern AntiVirus memory scanners by encrypting a function during runtime, then decrypting it when the function needs to be executed, then re-encrypting the function once the function has finished executing
- **Vectored Exception Handling (VEH)**: Handles memory access violations and redirects execution flow.
- **Encrypted Shellcode**: Shellcode is encrypted during download and decrypted in-memory before execution.
- Custom ```GetProcessAddress``` & ```GetModuleHandleW```
## Prerequisites
- Windows Operating System (x64)
- Visual Studio or compatible C++ compiler
- Internet connection (for staged shellcode download)

## Usage

### Build
1. Clone the repository:
2. Open the project in Visual Studio or your preferred C++ environment (i use vsc).
3. Compile the project in Release mode for a production-ready executable.

### Execution
1. Host the shellcode binary on a remote server (e.g., Discord, AWS, or any public URL, works best with domain fronting).
2. Update the shellcode URL in the `main` function:
   ```cpp
   std::wstring url = L"https://your-hosted-url/shellcode.bin";
   ```
3. Run the executable:
   ```bash
   hack.exe
   ```

## DETECTIONS (scanner.to / kleenscan)
![image](https://github.com/user-attachments/assets/0afe46a9-9aa7-450c-9ec1-85e898ae4487)
![image](https://github.com/user-attachments/assets/b8d4a182-e35e-46f0-a052-04e488674069)
![image](https://github.com/user-attachments/assets/0a3b4308-014e-4dc3-ae99-6faf52b77fc6)

## Disclaimer
This tool is intended for educational and research purposes only. Misuse of this tool for malicious purposes is strictly prohibited and against the law. The author does not condone or support any illegal activity.
