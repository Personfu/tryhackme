# Reverse Engineering Cheatsheet

> Binary analysis, Ghidra, GDB, radare2, malware unpacking.
> FLLC 2026 — FU PERSON

---

## Ghidra

### Setup
```bash
# Launch Ghidra
ghidraRun

# Import binary: File -> Import File
# Auto-analyze: Yes to all when prompted
```

### Key Windows

| Window | Purpose |
|--------|---------|
| Listing | Disassembly view |
| Decompiler | Pseudo-C output |
| Symbol Tree | Functions, imports, exports |
| Data Type Manager | Struct/type definitions |
| Function Graph | Visual control flow |

### Navigation
| Shortcut | Action |
|----------|--------|
| `G` | Go to address |
| `L` | Rename label/function |
| `T` | Retype variable |
| `;` | Add comment |
| `Ctrl+Shift+E` | Show references to |
| `Ctrl+Shift+F` | Find references from |

### Common Tasks
```
# Find main function: Look for __libc_start_main cross-reference
# Find strings: Window -> Defined Strings
# Find crypto: Search -> For Scalars -> common constants (0x67452301 = MD5)
# Patch bytes: Right-click -> Patch Instruction
```

---

## GDB

### Basic Commands
```bash
gdb ./binary

# Breakpoints
b main                 # Break at main
b *0x401234           # Break at address
b function_name       # Break at function
info b                # List breakpoints
d 1                   # Delete breakpoint 1

# Execution
r                     # Run
r arg1 arg2           # Run with args
c                     # Continue
n                     # Next (step over)
s                     # Step (step into)
ni                    # Next instruction
si                    # Step instruction
finish                # Run until return

# Examination
x/10x $rsp            # 10 hex words at RSP
x/s 0x401234          # String at address
x/10i $rip            # 10 instructions at RIP
p $rax                # Print register
p/x $rax              # Print hex
info registers        # All registers
bt                    # Backtrace

# Memory
vmmap                 # Memory map (pwndbg)
search-pattern "flag" # Search memory
```

### GDB + pwndbg/GEF
```bash
# Install pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# pwndbg features
checksec              # Security features (NX, PIE, canary)
rop                   # ROP gadget finder
heap                  # Heap analysis
got                   # GOT table
plt                   # PLT entries
```

---

## radare2

```bash
# Analyze binary
r2 -A ./binary

# Common commands
afl                   # List functions
pdf @main             # Disassemble main
axt @sym.func         # Cross-references to function
iz                    # List strings
iS                    # List sections
ii                    # List imports
ie                    # Entry point
s main                # Seek to main
VV                    # Visual graph mode
V                     # Visual mode (press p to cycle)

# Search
/ flag{               # Search string
/x 90909090           # Search hex bytes

# Write (patching)
wa nop @0x401234      # Write NOP
wx 9090 @0x401234     # Write hex bytes
```

---

## File Analysis

```bash
# Identify file type
file binary
binwalk binary         # Embedded files/firmware

# Strings
strings binary
strings -n 8 binary    # Min 8 chars
strings -e l binary    # Wide strings (UTF-16)

# ELF analysis
readelf -h binary      # ELF header
readelf -l binary      # Program headers
readelf -S binary      # Section headers
readelf -d binary      # Dynamic section

# PE analysis
objdump -x binary.exe  # Headers
peframe binary.exe     # PE analysis

# Checksec
checksec --file=binary
```

---

## Anti-Reversing Techniques

| Technique | Description | Counter |
|-----------|-------------|---------|
| Packing | UPX, Themida, VMProtect | upx -d, manual unpack |
| Obfuscation | Control flow flattening | Trace execution, symbolic execution |
| Anti-debug | IsDebuggerPresent, ptrace | Patch checks, LD_PRELOAD hooks |
| Anti-VM | CPUID checks, MAC checks | Modify VM config |
| String encryption | Runtime decryption | Break on decryption function |
| Junk code | Dead code insertion | Trace only executed paths |

---

## Malware Unpacking

```bash
# UPX packed
upx -d packed.exe -o unpacked.exe

# Manual unpack workflow
1. Find OEP (Original Entry Point)
2. Set breakpoint at OEP
3. Dump memory at OEP
4. Fix IAT (Import Address Table)
5. Rebuild PE headers

# Tools: x64dbg, Scylla (IAT fixing), PE-bear
```

---

**FLLC 2026** — FU PERSON by PERSON FU
