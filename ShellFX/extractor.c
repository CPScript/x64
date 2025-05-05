#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>

/**
 * extract_shellcode - Extracts shellcode from an ELF binary
 * filename: Path to the ELF binary
 * output: Path for the shellcode output (or NULL for stdout)
 * 
 * Returns: 0 on success, -1 on failure
 */
int extract_shellcode(const char *filename, const char *output) {
    int fd, out_fd = -1;
    uint8_t *elf_data = NULL;
    off_t file_size;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    char *shstrtab = NULL;
    uint8_t *text_section = NULL;
    uint64_t text_size = 0;
    int ret = -1;
    
    // Open the input file
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open input file");
        return -1;
    }
    
    // Get file size
    file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    
    // Map the file into memory
    elf_data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_data == MAP_FAILED) {
        perror("Failed to map file");
        close(fd);
        return -1;
    }
    
    // Check ELF header
    ehdr = (Elf64_Ehdr *)elf_data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        goto cleanup;
    }
    
    // Locate section header string table
    shdr = (Elf64_Shdr *)(elf_data + ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize);
    shstrtab = (char *)(elf_data + shdr->sh_offset);
    
    // Find .text section
    shdr = (Elf64_Shdr *)(elf_data + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++, shdr = (Elf64_Shdr *)((uint8_t *)shdr + ehdr->e_shentsize)) {
        char *section_name = shstrtab + shdr->sh_name;
        if (strcmp(section_name, ".text") == 0) {
            text_section = elf_data + shdr->sh_offset;
            text_size = shdr->sh_size;
            break;
        }
    }
    
    if (!text_section || !text_size) {
        fprintf(stderr, "No .text section found\n");
        goto cleanup;
    }
    
    // Open output file or use stdout
    if (output) {
        out_fd = open(output, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (out_fd < 0) {
            perror("Failed to open output file");
            goto cleanup;
        }
    } else {
        out_fd = STDOUT_FILENO;
    }
    
    // Output shellcode in C array format
    dprintf(out_fd, "unsigned char shellcode[] = {\n    ");
    for (uint64_t i = 0; i < text_size; i++) {
        dprintf(out_fd, "0x%02x", text_section[i]);
        if (i < text_size - 1) {
            dprintf(out_fd, ", ");
        }
        if ((i + 1) % 12 == 0 && i < text_size - 1) {
            dprintf(out_fd, "\n    ");
        }
    }
    dprintf(out_fd, "\n};\n");
    dprintf(out_fd, "unsigned int shellcode_len = %lu;\n", text_size);
    
    ret = 0;  // Success
    
cleanup:
    if (elf_data != MAP_FAILED && elf_data != NULL) {
        munmap(elf_data, file_size);
    }
    if (fd >= 0) {
        close(fd);
    }
    if (out_fd >= 0 && out_fd != STDOUT_FILENO) {
        close(out_fd);
    }
    
    return ret;
}

// Check if shellcode contains NULL bytes and other common bad characters
void analyze_shellcode(const uint8_t *shellcode, size_t length) {
    printf("Shellcode Analysis:\n");
    printf("Total size: %zu bytes\n", length);
    
    // Check for NULL bytes
    int null_bytes = 0;
    for (size_t i = 0; i < length; i++) {
        if (shellcode[i] == 0x00) {
            null_bytes++;
        }
    }
    printf("NULL bytes: %d\n", null_bytes);
    
    // Check for other common bad characters
    int bad_chars = 0;
    const uint8_t common_bad[] = {0x0a, 0x0d, 0x20, 0x09, 0x0b, 0x0c, 0xff};
    const char *bad_names[] = {"\\n", "\\r", "space", "\\t", "\\v", "\\f", "0xff"};
    
    printf("Bad characters found:\n");
    for (size_t j = 0; j < sizeof(common_bad); j++) {
        int count = 0;
        for (size_t i = 0; i < length; i++) {
            if (shellcode[i] == common_bad[j]) {
                count++;
            }
        }
        if (count > 0) {
            printf("  0x%02x (%s): %d occurrences\n", common_bad[j], bad_names[j], count);
            bad_chars += count;
        }
    }
    
    if (null_bytes == 0 && bad_chars == 0) {
        printf("Shellcode is clean! No NULL bytes or common bad characters found.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <elf_file> [output_file]\n", argv[0]);
        return 1;
    }
    
    const char *input_file = argv[1];
    const char *output_file = (argc == 3) ? argv[2] : NULL;
    
    return extract_shellcode(input_file, output_file);
}