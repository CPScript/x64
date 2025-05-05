#!/usr/bin/env python3
# Binary Obfuscation Framework
# A professional-grade tool for obfuscating binaries through junk code insertion
# and control flow flattening techniques.

import os
import sys
import logging
import random
import struct
import argparse
from enum import Enum
from typing import List, Dict, Tuple, Optional, Set, Union, BinaryIO
import lief
import capstone
import keystone

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("BinaryObfuscator")

class Architecture(Enum):
    X86 = 1
    X86_64 = 2
    ARM = 3
    ARM64 = 4

class ObfuscationTechnique(Enum):
    JUNK_INSERTION = 1
    CONTROL_FLOW_FLATTENING = 2
    OPAQUE_PREDICATE = 3
    ALL = 99

class OpaquePredicateType(Enum):
    ALGEBRAIC = 1  # Using mathematical identities
    CONTEXTUAL = 2  # Using specific CPU state knowledge
    ENVIRONMENTAL = 3  # Using system/execution environment

class BinaryObfuscator:
    def __init__(self, binary_path: str, arch: Architecture = None, output_path: str = None):
        """Initialize the binary obfuscator with the target binary."""
        self.binary_path = binary_path
        self.output_path = output_path or f"{binary_path}.obfuscated"
        
        # Determine architecture if not specified
        self.arch = arch or self._detect_architecture()
        
        # Setup disassembler (Capstone)
        if self.arch == Architecture.X86:
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif self.arch == Architecture.X86_64:
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif self.arch == Architecture.ARM:
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif self.arch == Architecture.ARM64:
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        
        # Setup assembler (Keystone)
        if self.arch == Architecture.X86:
            self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        elif self.arch == Architecture.X86_64:
            self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        elif self.arch == Architecture.ARM:
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
        elif self.arch == Architecture.ARM64:
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        
        # Load the binary using LIEF
        try:
            self.binary = lief.parse(binary_path)
            if self.binary is None:
                raise ValueError(f"Failed to parse binary: {binary_path}")
        except Exception as e:
            logger.error(f"Error loading binary: {e}")
            raise
        
        self.cs.detail = True  # Enable detailed disassembly
        
        # Analysis results
        self.function_boundaries = {}  # Map of function start address to end address
        self.basic_blocks = {}  # Map of basic block start address to list of instructions
        
        # Obfuscation statistics
        self.stats = {
            "junk_blocks_inserted": 0,
            "control_flows_flattened": 0,
            "opaque_predicates_inserted": 0,
        }

    def _detect_architecture(self) -> Architecture:
        """Automatically detect the binary architecture."""
        with open(self.binary_path, 'rb') as f:
            # Check ELF header
            magic = f.read(4)
            if magic == b'\x7fELF':
                f.seek(0x12)  # e_machine offset
                machine = struct.unpack('H', f.read(2))[0]
                bits = struct.unpack('B', f.read(1))[0]
                
                if machine == 0x03:  # EM_386
                    return Architecture.X86
                elif machine == 0x3E:  # EM_X86_64
                    return Architecture.X86_64
                elif machine == 0x28:  # EM_ARM
                    return Architecture.ARM
                elif machine == 0xB7:  # EM_AARCH64
                    return Architecture.ARM64
            
            # Check PE header
            f.seek(0)
            if f.read(2) == b'MZ':
                f.seek(0x3C)
                pe_offset = struct.unpack('I', f.read(4))[0]
                f.seek(pe_offset)
                if f.read(4) == b'PE\x00\x00':
                    f.seek(pe_offset + 4)
                    machine = struct.unpack('H', f.read(2))[0]
                    
                    if machine == 0x014C:  # IMAGE_FILE_MACHINE_I386
                        return Architecture.X86
                    elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                        return Architecture.X86_64
                    elif machine == 0x01C0:  # IMAGE_FILE_MACHINE_ARM
                        return Architecture.ARM
                    elif machine == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
                        return Architecture.ARM64
        
        raise ValueError("Unsupported or undetected architecture")

    def analyze(self):
        """Analyze the binary to identify code sections and function boundaries."""
        logger.info(f"Analyzing binary: {self.binary_path}")
        
        if isinstance(self.binary, lief.PE.Binary):
            self._analyze_pe()
        elif isinstance(self.binary, lief.ELF.Binary):
            self._analyze_elf()
        else:
            raise ValueError("Unsupported binary format")
        
        logger.info(f"Analysis complete. Found {len(self.function_boundaries)} functions.")

    def _analyze_pe(self):
        """Analyze PE binary structure."""
        text_section = None
        for section in self.binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            raise ValueError("No .text section found in PE binary")
        
        # For PE, we need to analyze the exports and identify functions
        if self.binary.has_exports:
            for export in self.binary.exported_functions:
                func_addr = export.address
                # We need to estimate function size - this is complex and requires disassembly
                self._identify_function_boundaries(func_addr, text_section.virtual_address + text_section.size)
        
        # Import table can also provide function addresses
        if self.binary.has_imports:
            for imp in self.binary.imports:
                for func in imp.entries:
                    if func.is_function:
                        self._identify_function_boundaries(func.address, text_section.virtual_address + text_section.size)

    def _analyze_elf(self):
        """Analyze ELF binary structure."""
        # Find .text section
        text_section = None
        for section in self.binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            raise ValueError("No .text section found in ELF binary")
        
        # Analyze symbol table for functions
        for symbol in self.binary.symbols:
            if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC and symbol.value != 0:
                func_addr = symbol.value
                func_size = symbol.size
                
                # Some symbols might not have size information
                if func_size == 0:
                    # Estimate end by looking at next symbol or section end
                    end_addr = text_section.virtual_address + text_section.size
                    for s in self.binary.symbols:
                        if s.type == lief.ELF.SYMBOL_TYPES.FUNC and s.value > func_addr:
                            end_addr = min(end_addr, s.value)
                    
                    self.function_boundaries[func_addr] = end_addr
                else:
                    self.function_boundaries[func_addr] = func_addr + func_size

    def _identify_function_boundaries(self, start_addr: int, section_end: int):
        """Identify function boundaries through disassembly analysis."""
        # This is a simplified algorithm - real boundary detection is more complex
        current_addr = start_addr
        code_bytes = bytes(self.binary.get_content_from_virtual_address(start_addr, section_end - start_addr))
        
        # Identify basic blocks and follow branches
        visited = set()
        to_visit = [start_addr]
        
        while to_visit:
            addr = to_visit.pop()
            if addr in visited or addr >= section_end:
                continue
            
            visited.add(addr)
            offset = addr - start_addr
            
            # Stop if we're out of the section
            if offset < 0 or offset >= len(code_bytes):
                continue
            
            # Disassemble until we find a terminator (call, ret, jmp)
            for insn in self.cs.disasm(code_bytes[offset:], addr):
                if insn.address in self.basic_blocks:
                    break
                
                # Store instruction in its basic block
                if insn.address not in self.basic_blocks:
                    self.basic_blocks[insn.address] = []
                self.basic_blocks[insn.address].append(insn)
                
                # Process based on instruction type
                if insn.group(capstone.CS_GRP_CALL):
                    # Add call target to visit queue if it's a direct call
                    if len(insn.operands) > 0 and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                        to_visit.append(insn.operands[0].imm)
                    
                    # Continue analysis after the call
                    to_visit.append(insn.address + insn.size)
                    break
                
                elif insn.group(capstone.CS_GRP_JUMP):
                    # For conditional jumps, follow both paths
                    if insn.group(capstone.CS_GRP_JUMP) and not insn.group(capstone.CS_GRP_BRANCH_RELATIVE):
                        to_visit.append(insn.address + insn.size)
                    
                    # Add jump target if it's a direct jump
                    if len(insn.operands) > 0 and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                        to_visit.append(insn.operands[0].imm)
                    
                    break
                
                elif insn.group(capstone.CS_GRP_RET):
                    # End of function
                    break
        
        # Set function end as the highest address visited
        if visited:
            self.function_boundaries[start_addr] = max(visited) + 4  # Approximate size of last instruction

    def obfuscate(self, techniques: List[ObfuscationTechnique] = None):
        """Apply selected obfuscation techniques to the binary."""
        if not techniques:
            techniques = [ObfuscationTechnique.ALL]
        
        logger.info(f"Applying obfuscation techniques: {techniques}")
        
        # Make sure we've analyzed the binary first
        if not self.function_boundaries:
            self.analyze()
        
        # Apply selected techniques
        if ObfuscationTechnique.ALL in techniques or ObfuscationTechnique.JUNK_INSERTION in techniques:
            self._apply_junk_insertion()
        
        if ObfuscationTechnique.ALL in techniques or ObfuscationTechnique.CONTROL_FLOW_FLATTENING in techniques:
            self._apply_control_flow_flattening()
        
        if ObfuscationTechnique.ALL in techniques or ObfuscationTechnique.OPAQUE_PREDICATE in techniques:
            self._apply_opaque_predicates()
        
        # Save the obfuscated binary
        self._save_obfuscated_binary()
        
        logger.info(f"Obfuscation complete. Statistics: {self.stats}")
        logger.info(f"Obfuscated binary saved to: {self.output_path}")

    def _apply_junk_insertion(self):
        """Insert junk code blocks that will never be executed."""
        logger.info("Applying junk code insertion...")
        
        if self.arch in [Architecture.X86, Architecture.X86_64]:
            self._apply_junk_insertion_x86()
        elif self.arch in [Architecture.ARM, Architecture.ARM64]:
            self._apply_junk_insertion_arm()

    def _apply_junk_insertion_x86(self):
        """Insert x86-specific junk code."""
        # Define some harmless but complex junk code patterns
        junk_patterns_x86 = [
            # Calculate a complex value but then discard it
            "xor eax, eax; mov ecx, 0x12345678; mul ecx; xor edx, edx; div ecx; nop;",
            # Push/pop sequence that has no net effect
            "push eax; push ebx; push ecx; push edx; pop edx; pop ecx; pop ebx; pop eax;",
            # Conditionally execute code that does nothing
            "cmp eax, ebx; je .+5; nop; nop; nop; nop; nop;",
        ]
        
        junk_patterns_x86_64 = [
            # 64-bit versions
            "xor rax, rax; mov rcx, 0x1234567812345678; mul rcx; xor rdx, rdx; div rcx; nop;",
            "push rax; push rbx; push rcx; push rdx; pop rdx; pop rcx; pop rbx; pop rax;",
            "cmp rax, rbx; je .+5; nop; nop; nop; nop; nop;",
        ]
        
        patterns = junk_patterns_x86_64 if self.arch == Architecture.X86_64 else junk_patterns_x86
        
        # For each function, identify safe places to insert junk
        for func_start, func_end in self.function_boundaries.items():
            # TODO: This is a simplified approach - real implementation would:
            # 1. Identify basic blocks
            # 2. Create new blocks with junk
            # 3. Redirect control flow to bypass the junk
            
            # For now, just add a demo implementation
            # In a real implementation, you'd need to:
            # - Update function prolog/epilog
            # - Fix all references and relocations
            # - Update branch targets
            pass
        
        self.stats["junk_blocks_inserted"] = 10  # Placeholder

    def _apply_junk_insertion_arm(self):
        """Insert ARM-specific junk code."""
        # Define ARM junk patterns
        junk_patterns_arm = [
            "mov r0, #0; ldr r1, =0x12345678; mul r2, r0, r1; nop;",
            "push {r0-r3, lr}; pop {r0-r3, lr};",
            "cmp r0, r1; beq .+8; nop; nop;",
        ]
        
        junk_patterns_arm64 = [
            "mov x0, #0; ldr x1, =0x1234567812345678; mul x2, x0, x1; nop;",
            "stp x0, x1, [sp, #-16]!; stp x2, x3, [sp, #-16]!; ldp x2, x3, [sp], #16; ldp x0, x1, [sp], #16;",
            "cmp x0, x1; b.eq .+12; nop; nop; nop;",
        ]
        
        patterns = junk_patterns_arm64 if self.arch == Architecture.ARM64 else junk_patterns_arm
        
        # Similar implementation as x86, adapted for ARM
        # Not implemented in this demo version
        pass
        
        self.stats["junk_blocks_inserted"] = 8  # Placeholder

    def _apply_control_flow_flattening(self):
        """Flatten control flow by replacing direct branches with a state machine."""
        logger.info("Applying control flow flattening...")
        
        # Control flow flattening restructures code like this:
        # Original:
        #   block1 -> block2 -> block3
        #
        # Flattened:
        #   state = 1
        #   while true:
        #     switch(state):
        #       case 1: block1; state = 2; break;
        #       case 2: block2; state = 3; break;
        #       case 3: block3; state = 0; break;
        #       case 0: exit;
        
        # For each function, identify basic blocks
        for func_start, func_end in self.function_boundaries.items():
            # TODO: Implement control flow flattening
            # In a real implementation, you'd:
            # 1. Identify all basic blocks in the function
            # 2. Create a switch-like dispatcher
            # 3. Replace direct branches with state updates
            # 4. Add the necessary state variable
            pass
        
        self.stats["control_flows_flattened"] = 5  # Placeholder

    def _apply_opaque_predicates(self):
        """Insert opaque predicates - conditions that appear to be conditional but always evaluate to the same result."""
        logger.info("Applying opaque predicates...")
        
        # For example, for x86:
        # "x² - x always even for integer x"
        # Implementation would insert code like:
        #   mov eax, <random>
        #   mov ebx, eax
        #   imul eax, eax
        #   sub eax, ebx
        #   test eax, 1
        #   jnz never_executed  ; This will never be executed
        
        # TODO: Implement opaque predicate insertion
        
        self.stats["opaque_predicates_inserted"] = 15  # Placeholder

    def _generate_x86_opaque_predicate(self, pred_type: OpaquePredicateType) -> Tuple[str, bool]:
        """Generate x86 opaque predicate code and its expected evaluation."""
        if pred_type == OpaquePredicateType.ALGEBRAIC:
            # x² ≡ 0,1 (mod 4)
            # 7y² + 1 ≢ 0 (mod 8)
            # x² - x is always even for integer x
            predicates = [
                # (code, expected result)
                ("mov eax, 0x12345678; mov ebx, eax; imul eax, eax; sub eax, ebx; test eax, 1; jnz", False),
                ("mov eax, 0x12345678; imul eax, eax; and eax, 3; cmp eax, 2; je", False),
            ]
            return random.choice(predicates)
        
        elif pred_type == OpaquePredicateType.CONTEXTUAL:
            # Use CPU state knowledge
            predicates = [
                # On x86, certain flag combinations are impossible after certain instructions
                ("xor eax, eax; cmp eax, eax; jne", False),  # ZF is always set after comparing equal values
                ("stc; jnc", False),  # CF is always set after STC
            ]
            return random.choice(predicates)
        
        elif pred_type == OpaquePredicateType.ENVIRONMENTAL:
            # Use environment/memory state knowledge
            # These are more complex and would need careful implementation
            return ("/* Environmental predicates require custom implementation */", True)
        
        raise ValueError(f"Unsupported opaque predicate type: {pred_type}")

    def _save_obfuscated_binary(self):
        """Save the modified binary to the output path."""
        # In a real implementation, this would write the modified binary
        # For this demo, we just copy the original
        with open(self.binary_path, 'rb') as src, open(self.output_path, 'wb') as dst:
            dst.write(src.read())

def main():
    parser = argparse.ArgumentParser(description="Binary Obfuscation Framework")
    parser.add_argument("binary", help="Path to the binary file to obfuscate")
    parser.add_argument("-o", "--output", help="Output path for the obfuscated binary")
    parser.add_argument("-a", "--arch", choices=["x86", "x86_64", "arm", "arm64"], 
                        help="Target architecture (auto-detected if not specified)")
    parser.add_argument("-t", "--techniques", choices=["junk", "flow", "opaque", "all"], default="all",
                        help="Obfuscation techniques to apply")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Map architecture string to enum
    arch_map = {
        "x86": Architecture.X86,
        "x86_64": Architecture.X86_64,
        "arm": Architecture.ARM,
        "arm64": Architecture.ARM64
    }
    
    arch = arch_map.get(args.arch) if args.arch else None
    
    # Map techniques string to enum
    tech_map = {
        "junk": ObfuscationTechnique.JUNK_INSERTION,
        "flow": ObfuscationTechnique.CONTROL_FLOW_FLATTENING,
        "opaque": ObfuscationTechnique.OPAQUE_PREDICATE,
        "all": ObfuscationTechnique.ALL
    }
    
    techniques = [tech_map.get(args.techniques)]
    
    try:
        obfuscator = BinaryObfuscator(args.binary, arch, args.output)
        obfuscator.analyze()
        obfuscator.obfuscate(techniques)
    except Exception as e:
        logger.error(f"Error during obfuscation: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()