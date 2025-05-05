/*
 * HWInfo - Comprehensive Hardware Inspection Kernel Module
 *
 * This module implements direct hardware introspection capabilities
 * by utilizing kernel-level privileged instructions to access:
 *  - CPU Registers (CR0, CR3, CR4)
 *  - Model Specific Registers (MSRs)
 *  - Memory Maps and ACPI Tables
 *  - PCI Configuration Space
 *  - CPU Cache and TLB Information
 *  - Virtualization and Security Features
 *
 * Usage:
 *  - Load module: insmod hwinfo.ko
 *  - Access data: cat /proc/hwinfo/[component]
 *  - Unload module: rmmod hwinfo
 *
 * WARNING: This module performs direct hardware access with privileged
 * instructions. Use with caution in production environments.
 */

 #include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/init.h>
 #include <linux/proc_fs.h>
 #include <linux/seq_file.h>
 #include <linux/uaccess.h>
 #include <linux/cpufeature.h>
 #include <linux/pci.h>
 #include <linux/io.h>
 #include <linux/acpi.h>
 #include <linux/mm.h>
 #include <linux/slab.h>
 #include <linux/delay.h>
 #include <linux/version.h>
 #include <asm/msr.h>
 #include <asm/processor.h>
 #include <asm/special_insns.h>
 #include <asm/io.h>
 #include <asm/pgtable.h>
 #include <asm/segment.h>
 
 #define MODULE_NAME "hwinfo"
 #define HWINFO_PROCFS_ROOT "hwinfo"
 
 /* Module metadata */
 MODULE_LICENSE("GPL");
 MODULE_AUTHOR("Hardware Inspector Developer");
 MODULE_DESCRIPTION("Comprehensive hardware inspection module with direct register access");
 MODULE_VERSION("1.0");
 
 /* Supported MSRs for inspection */
 #define MSR_IA32_APIC_BASE 0x1B
 #define MSR_IA32_FEATURE_CONTROL 0x3A
 #define MSR_IA32_SMM_MONITOR_CTL 0x9B
 #define MSR_IA32_MTRRCAP 0xFE
 #define MSR_IA32_SYSENTER_CS 0x174
 #define MSR_IA32_SYSENTER_ESP 0x175
 #define MSR_IA32_SYSENTER_EIP 0x176
 #define MSR_IA32_MCG_CAP 0x179
 #define MSR_IA32_PERF_STATUS 0x198
 #define MSR_IA32_MISC_ENABLE 0x1A0
 #define MSR_IA32_EFER 0xC0000080
 #define MSR_IA32_STAR 0xC0000081
 #define MSR_IA32_LSTAR 0xC0000082
 #define MSR_IA32_SMRR_PHYSBASE 0x1F2
 #define MSR_IA32_SMRR_PHYSMASK 0x1F3
 
 /* PCI configuration space access */
 #define PCI_CONFIG_ADDRESS 0xCF8
 #define PCI_CONFIG_DATA 0xCFC
 
 /* Global procfs directory */
 static struct proc_dir_entry *hwinfo_proc_root;
 
 /* Forward declarations for proc handlers */
 static int cpu_info_show(struct seq_file *m, void *v);
 static int registers_show(struct seq_file *m, void *v);
 static int msrs_show(struct seq_file *m, void *v);
 static int memory_show(struct seq_file *m, void *v);
 static int pci_show(struct seq_file *m, void *v);
 static int cache_show(struct seq_file *m, void *v);
 static int security_show(struct seq_file *m, void *v);
 
 /* Proc file operations */
 static int hwinfo_proc_open(struct inode *inode, struct file *file)
 {
     return single_open(file, PDE_DATA(inode), NULL);
 }
 
 /* Proc file operations structure */
 static const struct proc_ops hwinfo_proc_fops = {
     .proc_open = hwinfo_proc_open,
     .proc_read = seq_read,
     .proc_lseek = seq_lseek,
     .proc_release = single_release,
 };
 
 /* Buffer for CPU vendor and brand strings */
 static char cpu_vendor_string[16];
 static char cpu_brand_string[64];
 
 /*
  * Helper function to safely read control registers
  * in a way compatible with kernel protections
  */
 static inline unsigned long read_cr0(void)
 {
     return native_read_cr0();
 }
 
 static inline unsigned long read_cr3(void)
 {
     return __native_read_cr3();
 }
 
 static inline unsigned long read_cr4(void)
 {
     return native_read_cr4();
 }
 
 /* Helper function to safely read a MSR value */
 static int safe_rdmsr(unsigned int msr, u32 *low, u32 *high)
 {
     u64 val;
     int err;
 
     err = rdmsrl_safe(msr, &val);
     if (err)
         return err;
 
     *low = (u32)val;
     *high = (u32)(val >> 32);
     return 0;
 }
 
 /* Parse CPU flags, returning a human-readable string */
 static void parse_cr0_flags(unsigned long cr0, char *buf, size_t buflen)
 {
     snprintf(buf, buflen, "%s%s%s%s%s%s%s%s%s",
         (cr0 & X86_CR0_PE) ? "PE " : "",        /* Protected Mode Enable */
         (cr0 & X86_CR0_MP) ? "MP " : "",        /* Monitor Coprocessor */
         (cr0 & X86_CR0_EM) ? "EM " : "",        /* Emulation */
         (cr0 & X86_CR0_TS) ? "TS " : "",        /* Task Switched */
         (cr0 & X86_CR0_ET) ? "ET " : "",        /* Extension Type */
         (cr0 & X86_CR0_NE) ? "NE " : "",        /* Numeric Error */
         (cr0 & X86_CR0_WP) ? "WP " : "",        /* Write Protect */
         (cr0 & X86_CR0_PG) ? "PG " : "",        /* Paging */
         (cr0 & X86_CR0_CD) ? "CD " : "");       /* Cache Disable */
 }
 
 static void parse_cr4_flags(unsigned long cr4, char *buf, size_t buflen)
 {
     snprintf(buf, buflen, "%s%s%s%s%s%s%s%s%s",
         (cr4 & X86_CR4_VME) ? "VME " : "",      /* Virtual 8086 Mode Extensions */
         (cr4 & X86_CR4_PVI) ? "PVI " : "",      /* Protected-Mode Virtual Interrupts */
         (cr4 & X86_CR4_TSD) ? "TSD " : "",      /* Time Stamp Disable */
         (cr4 & X86_CR4_DE) ? "DE " : "",        /* Debugging Extensions */
         (cr4 & X86_CR4_PSE) ? "PSE " : "",      /* Page Size Extensions */
         (cr4 & X86_CR4_PAE) ? "PAE " : "",      /* Physical Address Extension */
         (cr4 & X86_CR4_MCE) ? "MCE " : "",      /* Machine Check Exception */
         (cr4 & X86_CR4_PGE) ? "PGE " : "",      /* Page Global Enable */
         (cr4 & X86_CR4_OSXSAVE) ? "OSXSAVE " : ""); /* XSAVE and Processor Extended States Enable */
 }
 
 static void parse_efer_flags(u64 efer, char *buf, size_t buflen)
 {
     snprintf(buf, buflen, "%s%s%s%s",
         (efer & EFER_SCE) ? "SCE " : "",        /* System Call Extensions */
         (efer & EFER_LME) ? "LME " : "",        /* Long Mode Enable */
         (efer & EFER_LMA) ? "LMA " : "",        /* Long Mode Active */
         (efer & EFER_NX) ? "NX " : "");         /* No-Execute Enable */
 }
 
 /* Get CPU vendor and brand strings */
 static void get_cpu_info(void)
 {
     unsigned int eax, ebx, ecx, edx;
     int i;
 
     /* Get vendor string */
     cpuid(0, &eax, &ebx, &ecx, &edx);
     memcpy(cpu_vendor_string, &ebx, 4);
     memcpy(cpu_vendor_string + 4, &edx, 4);
     memcpy(cpu_vendor_string + 8, &ecx, 4);
     cpu_vendor_string[12] = '\0';
 
     /* Check if processor brand string is supported */
     cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
     if (eax >= 0x80000004) {
         unsigned int *brand = (unsigned int *)cpu_brand_string;
 
         for (i = 0; i < 3; i++) {
             cpuid(0x80000002 + i, &eax, &ebx, &ecx, &edx);
             brand[i * 4 + 0] = eax;
             brand[i * 4 + 1] = ebx;
             brand[i * 4 + 2] = ecx;
             brand[i * 4 + 3] = edx;
         }
         cpu_brand_string[48] = '\0';
         
         /* Trim leading spaces */
         i = 0;
         while (cpu_brand_string[i] == ' ')
             i++;
             
         if (i > 0)
             memmove(cpu_brand_string, cpu_brand_string + i, 48 - i);
     } else {
         strcpy(cpu_brand_string, "Unknown");
     }
 }
 
 /* CPU Information Proc Handler */
 static int cpu_info_show(struct seq_file *m, void *v)
 {
     unsigned int eax, ebx, ecx, edx;
     unsigned int family, model, stepping;
     
     /* Get CPU info strings if not already populated */
     if (cpu_vendor_string[0] == '\0')
         get_cpu_info();
         
     /* Output basic CPU information */
     seq_printf(m, "=== CPU Information ===\n");
     seq_printf(m, "Vendor: %s\n", cpu_vendor_string);
     seq_printf(m, "Brand: %s\n", cpu_brand_string);
     
     /* Get family/model/stepping */
     cpuid(1, &eax, &ebx, &ecx, &edx);
     family = ((eax >> 8) & 0xf) + ((eax >> 20) & 0xff);
     model = ((eax >> 4) & 0xf) | ((eax >> 12) & 0xf0);
     stepping = eax & 0xf;
     
     seq_printf(m, "Family: 0x%x, Model: 0x%x, Stepping: 0x%x\n", 
                family, model, stepping);
     
     /* Feature flags */
     seq_puts(m, "\nFeature Flags:\n");
     seq_printf(m, "EDX: 0x%08x - ", edx);
     if (edx & (1 << 0))  seq_puts(m, "FPU ");
     if (edx & (1 << 4))  seq_puts(m, "TSC ");
     if (edx & (1 << 5))  seq_puts(m, "MSR ");
     if (edx & (1 << 6))  seq_puts(m, "PAE ");
     if (edx & (1 << 8))  seq_puts(m, "CX8 ");
     if (edx & (1 << 11)) seq_puts(m, "SEP ");
     if (edx & (1 << 15)) seq_puts(m, "CMOV ");
     if (edx & (1 << 23)) seq_puts(m, "MMX ");
     if (edx & (1 << 25)) seq_puts(m, "SSE ");
     if (edx & (1 << 26)) seq_puts(m, "SSE2 ");
     if (edx & (1 << 28)) seq_puts(m, "HTT ");
     seq_puts(m, "\n");
     
     seq_printf(m, "ECX: 0x%08x - ", ecx);
     if (ecx & (1 << 0))  seq_puts(m, "SSE3 ");
     if (ecx & (1 << 9))  seq_puts(m, "SSSE3 ");
     if (ecx & (1 << 19)) seq_puts(m, "SSE4.1 ");
     if (ecx & (1 << 20)) seq_puts(m, "SSE4.2 ");
     if (ecx & (1 << 21)) seq_puts(m, "x2APIC ");
     if (ecx & (1 << 23)) seq_puts(m, "POPCNT ");
     if (ecx & (1 << 25)) seq_puts(m, "AES ");
     if (ecx & (1 << 28)) seq_puts(m, "AVX ");
     if (ecx & (1 << 31)) seq_puts(m, "HYPERVISOR ");
     seq_puts(m, "\n");
     
     /* Extended features */
     cpuid(7, &eax, &ebx, &ecx, &edx);
     seq_printf(m, "EBX (Leaf 7): 0x%08x - ", ebx);
     if (ebx & (1 << 0))  seq_puts(m, "FSGSBASE ");
     if (ebx & (1 << 3))  seq_puts(m, "BMI1 ");
     if (ebx & (1 << 4))  seq_puts(m, "HLE ");
     if (ebx & (1 << 5))  seq_puts(m, "AVX2 ");
     if (ebx & (1 << 8))  seq_puts(m, "BMI2 ");
     if (ebx & (1 << 16)) seq_puts(m, "AVX512F ");
     if (ebx & (1 << 18)) seq_puts(m, "RDSEED ");
     if (ebx & (1 << 19)) seq_puts(m, "ADX ");
     if (ebx & (1 << 29)) seq_puts(m, "SHA ");
     seq_puts(m, "\n");
     
     /* Processor topology if available */
     if (cpuid_get_max_func() >= 0xB) {
         unsigned int level_type;
         unsigned int level_shift;
         unsigned int processors = 1;
         
         seq_puts(m, "\nProcessor Topology:\n");
         
         for (ecx = 0; ecx < 4; ecx++) {
             cpuid_count(0xB, ecx, &eax, &ebx, &ecx, &edx);
             if (ebx == 0)
                 break;
                 
             level_shift = eax & 0x1F;
             level_type = ecx & 0xFF00;
             
             switch (level_type) {
             case 0x100:
                 seq_printf(m, "Thread level: %d threads per core\n", 
                            ebx & 0xFFFF);
                 break;
             case 0x200:
                 seq_printf(m, "Core level: %d cores per package\n", 
                            ebx & 0xFFFF);
                 processors = 1 << level_shift;
                 break;
             }
         }
         
         seq_printf(m, "Total logical processors: %d\n", processors);
     }
     
     return 0;
 }
 
 /* Control Registers Proc Handler */
 static int registers_show(struct seq_file *m, void *v)
 {
     unsigned long cr0, cr3, cr4;
     char flags_buf[256];
     
     /* Read control registers */
     cr0 = read_cr0();
     cr3 = read_cr3();
     cr4 = read_cr4();
     
     seq_printf(m, "=== Control Registers ===\n");
     
     /* CR0 - Contains system control flags */
     parse_cr0_flags(cr0, flags_buf, sizeof(flags_buf));
     seq_printf(m, "CR0: 0x%016lx (%s)\n", cr0, flags_buf);
     
     /* CR3 - Contains page directory base */
     seq_printf(m, "CR3: 0x%016lx (Page Directory Base)\n", cr3);
     
     /* CR4 - Contains various architecture extensions/features */
     parse_cr4_flags(cr4, flags_buf, sizeof(flags_buf));
     seq_printf(m, "CR4: 0x%016lx (%s)\n", cr4, flags_buf);
     
     /* Segment Registers */
     seq_puts(m, "\n=== Segment Registers ===\n");
     
     /* We can't directly read segment registers from C in the kernel
      * but we can report the kernel segments values */
     seq_printf(m, "CS: 0x%04x (Kernel Code Segment)\n", __KERNEL_CS);
     seq_printf(m, "DS: 0x%04x (Kernel Data Segment)\n", __KERNEL_DS);
     seq_printf(m, "GS Base (kernel): 0x%016lx\n", native_read_msr(MSR_GS_BASE));
     seq_printf(m, "GS Base (user): 0x%016lx\n", native_read_msr(MSR_KERNEL_GS_BASE));
     
     return 0;
 }
 
 /* MSR Proc Handler */
 static int msrs_show(struct seq_file *m, void *v)
 {
     u32 low, high;
     u64 efer = 0;
     char flags_buf[256];
     int err;
     
     seq_printf(m, "=== Model Specific Registers (MSRs) ===\n");
     
     /* IA32_APIC_BASE - APIC Base Address */
     if (!safe_rdmsr(MSR_IA32_APIC_BASE, &low, &high)) {
         seq_printf(m, "IA32_APIC_BASE (0x%x): 0x%08x%08x\n", 
                    MSR_IA32_APIC_BASE, high, low);
         seq_printf(m, "  APIC Base: 0x%08x%08x\n", high, low & 0xFFFFF000);
         seq_printf(m, "  BSP: %s\n", (low & (1 << 8)) ? "Yes" : "No");
         seq_printf(m, "  APIC Global Enable: %s\n", (low & (1 << 11)) ? "Yes" : "No");
     } else {
         seq_printf(m, "IA32_APIC_BASE (0x%x): Failed to read\n", MSR_IA32_APIC_BASE);
     }
     
     /* IA32_EFER - Extended Feature Enable Register */
     err = safe_rdmsr(MSR_IA32_EFER, &low, &high);
     if (!err) {
         efer = ((u64)high << 32) | low;
         parse_efer_flags(efer, flags_buf, sizeof(flags_buf));
         seq_printf(m, "IA32_EFER (0x%x): 0x%08x%08x (%s)\n", 
                    MSR_IA32_EFER, high, low, flags_buf);
     } else {
         seq_printf(m, "IA32_EFER (0x%x): Failed to read\n", MSR_IA32_EFER);
     }
     
     /* IA32_FEATURE_CONTROL - Feature Control */
     if (!safe_rdmsr(MSR_IA32_FEATURE_CONTROL, &low, &high)) {
         seq_printf(m, "IA32_FEATURE_CONTROL (0x%x): 0x%08x%08x\n", 
                    MSR_IA32_FEATURE_CONTROL, high, low);
         seq_printf(m, "  Lock: %s\n", (low & 1) ? "Enabled" : "Disabled");
         seq_printf(m, "  VMX in SMX: %s\n", (low & (1 << 1)) ? "Enabled" : "Disabled");
         seq_printf(m, "  VMX outside SMX: %s\n", (low & (1 << 2)) ? "Enabled" : "Disabled");
     } else {
         seq_printf(m, "IA32_FEATURE_CONTROL (0x%x): Failed to read\n", MSR_IA32_FEATURE_CONTROL);
     }
     
     /* IA32_SYSENTER_CS, ESP, EIP - Fast system call MSRs */
     if (!safe_rdmsr(MSR_IA32_SYSENTER_CS, &low, &high)) {
         seq_printf(m, "IA32_SYSENTER_CS (0x%x): 0x%08x%08x\n", 
                    MSR_IA32_SYSENTER_CS, high, low);
     }
     
     if (!safe_rdmsr(MSR_IA32_SYSENTER_ESP, &low, &high)) {
         seq_printf(m, "IA32_SYSENTER_ESP (0x%x): 0x%08x%08x\n", 
                    MSR_IA32_SYSENTER_ESP, high, low);
     }
     
     if (!safe_rdmsr(MSR_IA32_SYSENTER_EIP, &low, &high)) {
         seq_printf(m, "IA32_SYSENTER_EIP (0x%x): 0x%08x%08x\n", 
                    MSR_IA32_SYSENTER_EIP, high, low);
     }
     
     /* IA32_MISC_ENABLE - Miscellaneous Features */
     if (!safe_rdmsr(MSR_IA32_MISC_ENABLE, &low, &high)) {
         seq_printf(m, "IA32_MISC_ENABLE (0x%x): 0x%08x%08x\n", 
                    MSR_IA32_MISC_ENABLE, high, low);
         seq_printf(m, "  Fast String: %s\n", (low & (1 << 0)) ? "Enabled" : "Disabled");
         seq_printf(m, "  TCC: %s\n", (low & (1 << 1)) ? "Disabled" : "Enabled");
         seq_printf(m, "  Performance Monitoring: %s\n", (low & (1 << 7)) ? "Disabled" : "Enabled");
         seq_printf(m, "  Branch Trace Storage: %s\n", (low & (1 << 11)) ? "Disabled" : "Enabled");
         seq_printf(m, "  Precise Event Based Sampling: %s\n", (low & (1 << 12)) ? "Disabled" : "Enabled");
         seq_printf(m, "  SpeedStep: %s\n", (low & (1 << 16)) ? "Enabled" : "Disabled");
         seq_printf(m, "  TM2: %s\n", (low & (1 << 13)) ? "Enabled" : "Disabled");
     } else {
         seq_printf(m, "IA32_MISC_ENABLE (0x%x): Failed to read\n", MSR_IA32_MISC_ENABLE);
     }
     
     /* Try to read SMM MSRs - May fail if not available */
     if (!safe_rdmsr(MSR_IA32_SMRR_PHYSBASE, &low, &high)) {
         seq_printf(m, "IA32_SMRR_PHYSBASE (0x%x): 0x%08x%08x\n", 
                    MSR_IA32_SMRR_PHYSBASE, high, low);
         seq_printf(m, "  SMM Base: 0x%08x\n", low & 0xFFFFF000);
         seq_printf(m, "  Type: %d\n", low & 0xFF);
     }
     
     if (!safe_rdmsr(MSR_IA32_SMRR_PHYSMASK, &low, &high)) {
         seq_printf(m, "IA32_SMRR_PHYSMASK (0x%x): 0x%08x%08x\n", 
                    MSR_IA32_SMRR_PHYSMASK, high, low);
         seq_printf(m, "  Valid: %s\n", (low & (1 << 11)) ? "Yes" : "No");
         seq_printf(m, "  Mask: 0x%08x\n", low & 0xFFFFF000);
     }
     
     /* Long mode syscall MSRs */
     if (!safe_rdmsr(MSR_IA32_STAR, &low, &high)) {
         seq_printf(m, "STAR (0x%x): 0x%08x%08x\n", MSR_IA32_STAR, high, low);
     }
     
     if (!safe_rdmsr(MSR_IA32_LSTAR, &low, &high)) {
         seq_printf(m, "LSTAR (0x%x): 0x%08x%08x\n", MSR_IA32_LSTAR, high, low);
     }
     
     return 0;
 }
 
 /* Memory Layout Proc Handler */
 static int memory_show(struct seq_file *m, void *v)
 {
     struct resource *res;
     phys_addr_t start, end;
     
     seq_printf(m, "=== System Memory Map ===\n");
     
     /* Iterate through iomem_resource to get memory layout */
     seq_printf(m, "Memory Regions:\n");
     for (res = iomem_resource.child; res; res = res->sibling) {
         start = res->start;
         end = res->end;
         
         seq_printf(m, "  [0x%016llx - 0x%016llx] %s\n", 
                    (unsigned long long)start, 
                    (unsigned long long)end,
                    res->name ? res->name : "unknown");
                    
         /* List subregions (one level only) */
         if (res->child) {
             struct resource *sub_res;
             for (sub_res = res->child; sub_res; sub_res = sub_res->sibling) {
                 seq_printf(m, "    [0x%016llx - 0x%016llx] %s\n", 
                            (unsigned long long)sub_res->start, 
                            (unsigned long long)sub_res->end,
                            sub_res->name ? sub_res->name : "unknown");
             }
         }
     }
     
     /* Display kernel memory layout */
     seq_printf(m, "\nKernel Memory Layout:\n");
     seq_printf(m, "  Text Begin: 0x%px\n", _text);
     seq_printf(m, "  Text End: 0x%px\n", _etext);
     seq_printf(m, "  Initialized Data Begin: 0x%px\n", _sdata);
     seq_printf(m, "  Initialized Data End: 0x%px\n", _edata);
     seq_printf(m, "  BSS Begin: 0x%px\n", __bss_start);
     seq_printf(m, "  BSS End: 0x%px\n", __bss_stop);
     seq_printf(m, "  Init Begin: 0x%px\n", __init_begin);
     seq_printf(m, "  Init End: 0x%px\n", __init_end);
     
     /* Display kernel page table info */
     seq_printf(m, "\nKernel Page Tables:\n");
     seq_printf(m, "  Page Global Directory: 0x%016lx\n", read_cr3());
     
     /* ACPI Tables */
 #ifdef CONFIG_ACPI
     seq_printf(m, "\nACPI Tables:\n");
     
     if (acpi_disabled) {
         seq_printf(m, "  ACPI disabled\n");
     } else {
         seq_printf(m, "  ACPI RSDP: 0x%llx\n", 
                    (unsigned long long)acpi_os_get_root_pointer());
                    
         /* List some common ACPI tables if available */
         if (acpi_gbl_FADT.header.revision) {
             seq_printf(m, "  FADT: 0x%llx (rev %d)\n", 
                        (unsigned long long)(uintptr_t)&acpi_gbl_FADT,
                        acpi_gbl_FADT.header.revision);
         }
         
         /* Other ACPI tables could be listed here */
     }
 #else
     seq_printf(m, "\nACPI: Not compiled in kernel\n");
 #endif
     
     return 0;
 }
 
 /* PCI Configuration Space Proc Handler */
 static int pci_show(struct seq_file *m, void *v)
 {
     struct pci_dev *dev = NULL;
     int i;
     
     seq_printf(m, "=== PCI Devices ===\n");
     
     for_each_pci_dev(dev) {
         seq_printf(m, "[%04x:%02x:%02x.%d] %04x:%04x %s\n",
                    pci_domain_nr(dev->bus), dev->bus->number,
                    PCI_SLOT(dev->devfn), PCI_FUNC(dev->devfn),
                    dev->vendor, dev->device,
                    pci_name(dev));
                    
         /* Print the first 64 bytes of PCI config space */
         seq_printf(m, "  Config Space: ");
         for (i = 0; i < 64; i++) {
             u8 value;
             
             if (i % 16 == 0 && i > 0)
                 seq_printf(m, "\n                ");
                 
             pci_read_config_byte(dev, i, &value);
             seq_printf(m, "%02x ", value);
         }
         seq_printf(m, "\n");
         
         /* Print BARs */
         for (i = 0; i < 6; i++) {
             if (dev->resource[i].start) {
                 seq_printf(m, "  BAR%d: 0x%016llx-0x%016llx [%s%s]\n", i,
                            (unsigned long long)dev->resource[i].start,
                            (unsigned long long)dev->resource[i].end,
                            (dev->resource[i].flags & IORESOURCE_IO) ? "IO" : "MEM",
                            (dev->resource[i].flags & IORESOURCE_PREFETCH) ? " PREFETCH" : "");
             }
         }
         
         /* Print IRQ */
         if (dev->irq)
             seq_printf(m, "  IRQ: %d\n", dev->irq);
             
         seq_printf(m, "\n");
     }
     
     /* System I/O Port Information */
     seq_printf(m, "\n=== Common I/O Ports ===\n");
     
     /* Read some common I/O ports with inb/inw */
     seq_printf(m, "  PIC Master Command (0x20): 0x%02x\n", inb(0x20));
     seq_printf(m, "  PIC Master Mask (0x21): 0x%02x\n", inb(0x21));
     seq_printf(m, "  PIC Slave Command (0xA0): 0x%02x\n", inb(0xA0));
     seq_printf(m, "  PIC Slave Mask (0xA1): 0x%02x\n", inb(0xA1));
     seq_printf(m, "  PIT Counter 0 (0x40): 0x%02x\n", inb(0x40));
     
     return 0;
 }
 
 /* Cache & TLB Information Proc Handler */
 static int cache_show(struct seq_file *m, void *v)
 {
     int i, j, count;
     unsigned int eax, ebx, ecx, edx;
     
     seq_printf(m, "=== Cache & TLB Information ===\n");
     
     /* Check if deterministic cache info is supported */
     cpuid(0, &eax, &ebx, &ecx, &edx);
     if (eax >= 4) {
         unsigned int cache_type;
         unsigned int cache_level;
         unsigned int cache_size;
         unsigned int ways, partitions, line_size, sets;
         
         seq_printf(m, "Deterministic Cache Info (Leaf 4):\n");
         
         /* Iterate through all cache levels */
         for (i = 0; ; i++) {
             cpuid_count(4, i, &eax, &ebx, &ecx, &edx);
             cache_type = eax & 0x1F;
             
             /* Break if no more caches */
             if (cache_type == 0)
                 break;
                 
             cache_level = (eax >> 5) & 0x7;
             
             /* Calculate cache size */
             ways = ((ebx >> 22) & 0x3FF) + 1;
             partitions = ((ebx >> 12) & 0x3FF) + 1;
             line_size = (ebx & 0xFFF) + 1;
             sets = ecx + 1;
             cache_size = ways * partitions * line_size * sets;
             
             seq_printf(m, "  L%d ", cache_level);
             
             switch (cache_type) {
             case 1:
                 seq_printf(m, "Data Cache: ");
                 break;
             case 2:
                 seq_printf(m, "Instruction Cache: ");
                 break;
             case 3:
                 seq_printf(m, "Unified Cache: ");
                 break;
             default:
                 seq_printf(m, "Unknown Cache: ");
                 break;
             }
             
             seq_printf(m, "%d KB, %d-way, %d byte line size\n", 
                        cache_size / 1024, ways, line_size);
             seq_printf(m, "    Sets: %d, Partitions: %d\n", sets, partitions);
             seq_printf(m, "    WBINVD: %s, Inclusive: %s\n",
                        (eax & (1 << 24)) ? "Yes" : "No",
                        (eax & (1 << 9)) ? "Yes" : "No");
         }
     } else {
         /* Fall back to legacy cache descriptors */
         seq_printf(m, "Legacy Cache Descriptors:\n");
         cpuid(2, &eax, &ebx, &ecx, &edx);
         count = eax & 0xFF;
         
         /* Decode cache descriptors */
         for (i = 0; i < count; i++) {
             u32 *reg_ptr[4] = {&eax, &ebx, &ecx, &edx};
             for (j = (i == 0) ? 1 : 0; j < 4; j++) {
                 u32 reg = *reg_ptr[j];
                 int k;
                 
                 /* Skip registers marked as reserved (0) */
                 if (reg == 0)
                     continue;
                     
                 /* Examine each byte */
                 for (k = 0; k < 4; k++) {
                     unsigned char desc = (reg >> (k * 8)) & 0xFF;
                     if (desc == 0)
                         continue;
                         
                     /* Decode descriptor - this is a very incomplete list */
                     switch (desc) {
                     case 0x06:
                         seq_printf(m, "  L1 I-Cache: 8KB, 4-way, 32 byte line\n");
                         break;
                     case 0x08:
                         seq_printf(m, "  L1 I-Cache: 16KB, 4-way, 32 byte line\n");
                         break;
                     case 0x0A:
                         seq_printf(m, "  L1 D-Cache: 8KB, 2-way, 32 byte line\n");
                         break;
                     case 0x0C:
                         seq_printf(m, "  L1 D-Cache: 16KB, 4-way, 32 byte line\n");
                         break;
                     case 0x41:
                         seq_printf(m, "  L2 Unified Cache: 128KB, 4-way, 32 byte line\n");
                         break;
                     case 0x42:
                         seq_printf(m, "  L2 Unified Cache: 256KB, 4-way, 32 byte line\n");
                         break;
                     case 0x43:
                         seq_printf(m, "  L2 Unified Cache: 512KB, 4-way, 32 byte line\n");
                         break;
                     case 0x44:
                         seq_printf(m, "  L2 Unified Cache: 1MB, 4-way, 32 byte line\n");
                         break;
                     case 0x45:
                         seq_printf(m, "  L2 Unified Cache: 2MB, 4-way, 32 byte line\n");
                         break;
                     case 0x78:
                         seq_printf(m, "  L2 Unified Cache: 1MB, 4-way, 64 byte line\n");
                         break;
                     case 0x79:
                         seq_printf(m, "  L2 Unified Cache: 128KB, 8-way, 64 byte line\n");
                         break;
                     case 0x7A:
                         seq_printf(m, "  L2 Unified Cache: 256KB, 8-way, 64 byte line\n");
                         break;
                     case 0x7B:
                         seq_printf(m, "  L2 Unified Cache: 512KB, 8-way, 64 byte line\n");
                         break;
                     case 0x7C:
                         seq_printf(m, "  L2 Unified Cache: 1MB, 8-way, 64 byte line\n");
                         break;
                     default:
                         seq_printf(m, "  Unknown descriptor: 0x%02x\n", desc);
                         break;
                     }
                 }
             }
         }
     }
     
     /* TLB information */
     seq_printf(m, "\nTLB Information:\n");
     
     /* Modern CPUs - check for leaf 0x18 support */
     cpuid(0, &eax, &ebx, &ecx, &edx);
     if (eax >= 0x18) {
         seq_printf(m, "  Deterministic TLB Info (Leaf 0x18):\n");
         
         /* Enumerate all TLB structures */
         for (i = 0; i < 4; i++) {
             cpuid_count(0x18, i, &eax, &ebx, &ecx, &edx);
             if (!(eax & 0x1F))  /* Check if valid level */
                 continue;
                 
             seq_printf(m, "  TLB Level %d:\n", i);
             seq_printf(m, "    4K Page Entries: %d\n", eax & 0xFFF);
             seq_printf(m, "    2M/4M Page Entries: %d\n", (eax >> 12) & 0xFFF);
             seq_printf(m, "    1G Page Entries: %d\n", (eax >> 24) & 0xFFF);
             
             seq_printf(m, "    Ways: %d, Sets: %d\n", 
                        ((ebx >> 16) & 0xFFFF) + 1, (ecx & 0xFFFF) + 1);
         }
     } else {
         /* Report some TLB info for older CPUs using descriptor method */
         seq_printf(m, "  Legacy TLB Info (Limited):\n");
         
         /* Check for extended leaf 0x80000006 TLB info */
         cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
         if (eax >= 0x80000006) {
             cpuid(0x80000006, &eax, &ebx, &ecx, &edx);
             
             /* L2 TLB information */
             seq_printf(m, "  L2 TLB 2M/4M Pages: %d entries, %d-way\n",
                        (eax >> 16) & 0xFFF, (eax >> 28) & 0xF);
             seq_printf(m, "  L2 TLB 4K Pages: %d entries, %d-way\n",
                        eax & 0xFFF, (eax >> 12) & 0xF);
         }
     }
     
     return 0;
 }
 
 /* Security Features Proc Handler */
 static int security_show(struct seq_file *m, void *v)
 {
     unsigned int eax, ebx, ecx, edx;
     unsigned int max_leaf;
     u32 low, high;
     int vmx_available = 0;
     int smx_available = 0;
     
     seq_printf(m, "=== Security Features ===\n");
     
     /* Check processor security features */
     cpuid(0, &max_leaf, &ebx, &ecx, &edx);
     
     /* Virtualization support */
     if (max_leaf >= 1) {
         cpuid(1, &eax, &ebx, &ecx, &edx);
         vmx_available = (ecx & (1 << 5)) ? 1 : 0;  /* VMX bit */
         smx_available = (ecx & (1 << 6)) ? 1 : 0;  /* SMX bit */
         
         seq_printf(m, "Virtualization Support:\n");
         seq_printf(m, "  VMX (Intel VT-x): %s\n", vmx_available ? "Supported" : "Not Supported");
         seq_printf(m, "  SMX (Intel TXT): %s\n", smx_available ? "Supported" : "Not Supported");
         
         /* Check if running under hypervisor */
         seq_printf(m, "  Hypervisor Present: %s\n", (ecx & (1 << 31)) ? "Yes" : "No");
         
         if (ecx & (1 << 31)) {
             /* Get hypervisor information */
             cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
             
             /* Print hypervisor vendor ID if available */
             char vendor[13];
             memcpy(vendor, &ebx, 4);
             memcpy(vendor + 4, &ecx, 4);
             memcpy(vendor + 8, &edx, 4);
             vendor[12] = '\0';
             
             seq_printf(m, "  Hypervisor Vendor: %s\n", vendor);
             seq_printf(m, "  Hypervisor Max Leaf: 0x%08x\n", eax);
         }
     }
     
     /* SGX Support (Intel Software Guard Extensions) */
     if (max_leaf >= 7) {
         cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
         seq_printf(m, "SGX (Software Guard Extensions): %s\n", 
                    (ebx & (1 << 2)) ? "Supported" : "Not Supported");
                    
         if (ebx & (1 << 2)) {
             /* SGX details via leaf 0x12 */
             if (max_leaf >= 0x12) {
                 cpuid_count(0x12, 0, &eax, &ebx, &ecx, &edx);
                 
                 seq_printf(m, "  SGX1: %s\n", (eax & 0x1) ? "Yes" : "No");
                 seq_printf(m, "  SGX2: %s\n", (eax & 0x2) ? "Yes" : "No");
                 seq_printf(m, "  SGX EPC Base: 0x%llx\n", 
                            (unsigned long long)((edx & 0xFFFFF000) | ((unsigned long long)(ecx & 0xFFFFF) << 32)));
                 seq_printf(m, "  SGX EPC Size: %llu KB\n", 
                            (unsigned long long)((ebx & 0xFFFFF000) | ((unsigned long long)(eax & 0xF) << 32)) / 1024);
             }
         }
     }
     
     /* Memory Protection Extensions */
     if (max_leaf >= 7) {
         cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
         seq_printf(m, "MPX (Memory Protection Extensions): %s\n", 
                    (ebx & (1 << 14)) ? "Supported" : "Not Supported");
     }
     
     /* Check if SMEP/SMAP is enabled */
     unsigned long cr4 = read_cr4();
     seq_printf(m, "SMEP (Supervisor Mode Execution Prevention): %s\n", 
                (cr4 & X86_CR4_SMEP) ? "Enabled" : "Disabled");
     seq_printf(m, "SMAP (Supervisor Mode Access Prevention): %s\n", 
                (cr4 & X86_CR4_SMAP) ? "Enabled" : "Disabled");
     
     /* Check if NX bit is enabled (via EFER.NXE) */
     if (!safe_rdmsr(MSR_IA32_EFER, &low, &high)) {
         u64 efer = ((u64)high << 32) | low;
         seq_printf(m, "NX (No-Execute) Bit: %s\n", 
                    (efer & EFER_NX) ? "Enabled" : "Disabled");
     }
     
     /* ASLR Status */
     seq_printf(m, "ASLR (Address Space Layout Randomization): ");
     #ifdef CONFIG_RANDOMIZE_BASE
         seq_printf(m, "Enabled (Kernel)\n");
     #else
         seq_printf(m, "Disabled (Kernel)\n");
     #endif
     
     return 0;
 }
 
 /* Module initialization */
 static int __init hwinfo_init(void)
 {
     struct proc_dir_entry *cpu_entry;
     struct proc_dir_entry *reg_entry;
     struct proc_dir_entry *msr_entry;
     struct proc_dir_entry *mem_entry;
     struct proc_dir_entry *pci_entry;
     struct proc_dir_entry *cache_entry;
     struct proc_dir_entry *security_entry;
     
     /* Create /proc/hwinfo directory */
     hwinfo_proc_root = proc_mkdir(HWINFO_PROCFS_ROOT, NULL);
     if (!hwinfo_proc_root) {
         pr_err("Failed to create /proc/%s directory\n", HWINFO_PROCFS_ROOT);
         return -ENOMEM;
     }
     
     /* Create proc entries for each component */
     cpu_entry = proc_create_data("cpu", 0444, hwinfo_proc_root, &hwinfo_proc_fops, cpu_info_show);
     if (!cpu_entry) {
         pr_err("Failed to create /proc/%s/cpu\n", HWINFO_PROCFS_ROOT);
         goto remove_proc_root;
     }
     
     reg_entry = proc_create_data("registers", 0444, hwinfo_proc_root, &hwinfo_proc_fops, registers_show);
     if (!reg_entry) {
         pr_err("Failed to create /proc/%s/registers\n", HWINFO_PROCFS_ROOT);
         goto remove_cpu;
     }
     
     msr_entry = proc_create_data("msrs", 0444, hwinfo_proc_root, &hwinfo_proc_fops, msrs_show);
     if (!msr_entry) {
         pr_err("Failed to create /proc/%s/msrs\n", HWINFO_PROCFS_ROOT);
         goto remove_reg;
     }
     
     mem_entry = proc_create_data("memory", 0444, hwinfo_proc_root, &hwinfo_proc_fops, memory_show);
     if (!mem_entry) {
         pr_err("Failed to create /proc/%s/memory\n", HWINFO_PROCFS_ROOT);
         goto remove_msr;
     }
     
     pci_entry = proc_create_data("pci", 0444, hwinfo_proc_root, &hwinfo_proc_fops, pci_show);
     if (!pci_entry) {
         pr_err("Failed to create /proc/%s/pci\n", HWINFO_PROCFS_ROOT);
         goto remove_mem;
     }
     
     cache_entry = proc_create_data("cache", 0444, hwinfo_proc_root, &hwinfo_proc_fops, cache_show);
     if (!cache_entry) {
         pr_err("Failed to create /proc/%s/cache\n", HWINFO_PROCFS_ROOT);
         goto remove_pci;
     }
     
     security_entry = proc_create_data("security", 0444, hwinfo_proc_root, &hwinfo_proc_fops, security_show);
     if (!security_entry) {
         pr_err("Failed to create /proc/%s/security\n", HWINFO_PROCFS_ROOT);
         goto remove_cache;
     }
     
     /* Get CPU info for later use */
     get_cpu_info();
     
     pr_info("HWInfo: Module loaded successfully\n");
     pr_info("HWInfo: Access hardware information at /proc/%s/\n", HWINFO_PROCFS_ROOT);
     
     return 0;
     
     /* Error handling */
 remove_cache:
     proc_remove(proc_create_data("cache", 0444, hwinfo_proc_root, &hwinfo_proc_fops, NULL));
 remove_pci:
     proc_remove(proc_create_data("pci", 0444, hwinfo_proc_root, &hwinfo_proc_fops, NULL));
 remove_mem:
     proc_remove(proc_create_data("memory", 0444, hwinfo_proc_root, &hwinfo_proc_fops, NULL));
 remove_msr:
     proc_remove(proc_create_data("msrs", 0444, hwinfo_proc_root, &hwinfo_proc_fops, NULL));
 remove_reg:
     proc_remove(proc_create_data("registers", 0444, hwinfo_proc_root, &hwinfo_proc_fops, NULL));
 remove_cpu:
     proc_remove(proc_create_data("cpu", 0444, hwinfo_proc_root, &hwinfo_proc_fops, NULL));
 remove_proc_root:
     proc_remove(hwinfo_proc_root);
     return -ENOMEM;
 }
 
 /* Module cleanup */
 static void __exit hwinfo_exit(void)
 {
     /* Remove all proc entries */
     proc_remove(hwinfo_proc_root);
     
     pr_info("HWInfo: Module unloaded\n");
 }
 
 module_init(hwinfo_init);
 module_exit(hwinfo_exit);