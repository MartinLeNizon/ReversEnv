# Capstone Python working reference for AI-assisted disassembly

## Summary — read this first

**Capstone** decodes machine-code bytes into instructions and structured metadata.
The Python distribution and import are both **`capstone`**. It does not load
ELF/PE/Mach-O files, discover all functions, assemble code, execute instructions,
or prove that decoded instructions are reachable.

**Version:** ReversEnv pins **capstone==5.0.9**, but its installed environment has
**Python binding 5.0.7** with native API **5.0** (`cs_version() == (5, 0, 1280)`).
This reference was tested with **5.0.7, CPython 3.12.14, Linux x86-64, 2026-09-26**.
The third `cs_version()` number encodes the API version; it is not a patch-version
identifier. **5.0.9 was not executed**, and no repository pin was changed.

Normal workflow: obtain the correct file-backed code bytes → determine architecture,
mode, byte order, and address mapping → configure `Cs` → decode with a bounded
scope → inspect structured metadata → measure decoded coverage → report unresolved
bytes/control flow and verify important conclusions independently.

Essential rules:

1. Create `Cs(architecture, mode)` from the **target**, not the host CPU. Wrong modes
   often produce plausible instructions instead of errors.
2. Pass raw bytes and the correct start **address** to `disasm(code, offset, count=0)`.
   Despite the Python parameter name `offset`, it sets instruction addresses; it
   does not seek into a file or skip bytes in `code`.
3. `count` counts instructions, not bytes; default `0` means no instruction limit.
   An invalid/truncated encoding normally ends iteration without an exception.
4. `detail` defaults to `False`. Set `md.detail = True` **before** decoding if you
   need operands, groups, or register effects. Do not toggle options while consuming
   a generator or inspecting objects created with that handle.
5. Analyze instruction IDs and structured operands; use `mnemonic` and `op_str`
   for presentation. Syntax, aliases, and formatting are not semantic contracts.
6. `regs_read` / `regs_write` and `reg_read` / `reg_write` describe **implicit**
   register effects. `regs_access()` includes explicit and implicit effects where
   the backend supports them. Neither is a complete executable semantics model.
7. `skipdata` defaults to `False`. With it enabled, records with `id == 0` are data
   placeholders, not instructions; querying instruction detail on them can raise.
8. Decoding every byte does not prove it is code. Successful disassembly, an empty
   iterator, or an unresolved branch must not become an unsupported reachability
   or absence claim.
9. File offsets, linked VAs, RVAs, and runtime addresses are different domains.
   Direct branch targets and PC-relative references depend on the chosen address.
10. Preserve input bytes, architecture/mode/options, versions, coverage, and known
    limits in every analysis result. Reload/redecode after any binary modification.

## Task index — retrieve only what you need

| Question / API | Section |
| --- | --- |
| Install; check binding/native versions and backend support | [S01](#s01) |
| Minimal `Cs` / `disasm` / `disasm_lite` example | [S02](#s02) |
| x86 16/32/64, ARM/Thumb/AArch64, endianness, syntax | [S03](#s03) |
| Generator behavior, `count`, invalid bytes, exact coverage | [S04](#s04) |
| `CsInsn`, operands, registers, access flags, RIP-relative memory | [S05](#s05) |
| Calls/jumps/returns, immediate targets, unresolved transfers | [S06](#s06) |
| `skipdata`, id-zero records, custom skip callback | [S07](#s07) |
| Runnable ARM, Thumb, ARM64, MIPS, RISC-V fixtures | [S08](#s08) |
| Map executable file bytes with LIEF; complete ELF example | [S09](#s09) |
| Bounded instruction traversal and completeness accounting | [S10](#s10) |
| Flags, widths, implicit effects, and semantic limitations | [S11](#s11) |
| Performance, native allocation, chunk boundaries, handle lifetime | [S12](#s12) |
| `CsError`, version mismatch, absent details, wrong output | [S13](#s13) |
| Reverse-engineering decision workflow and result record | [S14](#s14) |
| Reproduce examples; tested and untested scope | [S15](#s15) |
| Primary sources and version migration | [S16](#s16) |

Each section has a stable explicit anchor. **Runnable example** blocks are complete
with imports, input bytes, and assertions; they are independent unless a stated
external tool is required. **Doctest** shows exact interactive checks.
**Fragment/recipe** needs the described context. Mnemonic spelling is asserted only
for small fixtures on the tested version; it is not promised across releases.

<a id="s01"></a>
## [S01] Installation and capability checks

Use ReversEnv's environment to avoid loading a different Python binding or native
library. **Fragment/recipe — from the project root:**

```sh
.venv/bin/python -c 'import capstone; print(capstone.__version__); print(capstone.cs_version()); print(capstone.__file__); print(capstone.debug())'
```

For an independent environment, install the desired release there; do not silently
upgrade the shared environment. The package includes Python bindings and a native
engine. A system library or custom library search path can make their versions
incompatible. `Cs(...)` can raise `CsError(CS_ERR_VERSION)` for an API mismatch;
API major/minor agreement alone does not identify the exact native patch release.

`cs_support(arch_constant) -> bool` checks whether a backend is compiled in.
`cs_support(CS_SUPPORT_DIET)` detects a reduced-information build; diet builds may
lack names, groups, and register-access metadata. `CS_SUPPORT_X86_REDUCE` indicates
a reduced x86 backend. Presence of a Python constant does not guarantee native
support. The tested build is non-diet and supports all architectures in the labs.

**Doctest — inspect this environment's expected API without patch-version claims:**

```pycon
>>> import capstone as cs
>>> cs.cs_version()[:2]
(5, 0)
>>> cs.cs_support(cs.CS_ARCH_X86)
True
>>> cs.cs_support(cs.CS_SUPPORT_DIET)
False
>>> decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
>>> decoder.detail, decoder.skipdata
(False, False)
>>> decoder.syntax == cs.CS_OPT_SYNTAX_INTEL
True
```

See [official Python guide](https://www.capstone-engine.org/lang_python.html).
Its examples span earlier releases; the installed 5.0.7 binding source is the
primary contract for the signatures below.

<a id="s02"></a>
## [S02] Minimal disassembly

**Runnable example — x86-64 function-shaped byte sequence, no input file required:**

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_INS_MOV, X86_INS_RET

code = bytes.fromhex('b82a000000c3')  # mov eax, 42; ret
base = 0x401000
md = Cs(CS_ARCH_X86, CS_MODE_64)
instructions = list(md.disasm(code, base))
assert [ins.id for ins in instructions] == [X86_INS_MOV, X86_INS_RET]
assert [ins.size for ins in instructions] == [5, 1]
assert [ins.address for ins in instructions] == [base, base + 5]
assert b''.join(bytes(ins.bytes) for ins in instructions) == code
rows = list(md.disasm_lite(code, base))
assert rows == [(ins.address, ins.size, ins.mnemonic, ins.op_str)
                for ins in instructions]
for address, size, mnemonic, operands in rows:
    print(f'{address:#x}: {mnemonic} {operands}'.rstrip())
```

This verifies decoding and byte coverage. It does not execute a function, establish
its calling convention, or prove the bytes are an actual function in a larger
binary. For structured register/immediate values, enable detail as in [S05](#s05).

<a id="s03"></a>
## [S03] Architecture, mode, byte order, and display syntax

`Cs(arch: int, mode: int)` opens a decoder and returns a handle object. Architecture
constants select the instruction family; mode flags select its variant. Modes
from unrelated architectures are not interchangeable even if integer values
coincide. Invalid combinations can raise `CsError`.

| Target | Constructor arguments | Interpretation notes |
| --- | --- | --- |
| x86 real/16-bit code | `CS_ARCH_X86, CS_MODE_16` | Operand/address-size overrides still affect individual instructions. |
| x86 32-bit | `CS_ARCH_X86, CS_MODE_32` | Same bytes can have different boundaries from x86-64. |
| x86-64 | `CS_ARCH_X86, CS_MODE_64` | Little-endian instruction encodings; do not use a host pointer size to choose mode. |
| ARM A32 | `CS_ARCH_ARM, CS_MODE_ARM \| CS_MODE_LITTLE_ENDIAN` | Fixed 4-byte instruction width. |
| ARM Thumb | `CS_ARCH_ARM, CS_MODE_THUMB \| CS_MODE_LITTLE_ENDIAN` | 2- or 4-byte instructions; add `CS_MODE_MCLASS` for the appropriate M-profile decoder. |
| AArch64 | `CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN` | Capstone 5 name is ARM64; do not assume newer AARCH64 API names. Fixed 4-byte instructions. |
| MIPS32 big-endian | `CS_ARCH_MIPS, CS_MODE_MIPS32 \| CS_MODE_BIG_ENDIAN` | Delay slots and variant selection matter to control flow. |
| RISC-V 64 with compressed extension | `CS_ARCH_RISCV, CS_MODE_RISCV64 \| CS_MODE_RISCVC` | Compressed instructions can change boundaries to 2-byte units. |

`CS_MODE_LITTLE_ENDIAN` is zero; a zero flag does not mean unspecified behavior.
Use instruction byte order, which need not follow every data access in a target's
execution environment. Special ARM BE8 or mixed-mode inputs require separate
format/architecture reasoning; this guide does not validate them.

For ARM function pointers whose low bit encodes Thumb state, separate the state
bit from the actual aligned code address (`pointer & ~1`) before slicing bytes.
Setting an odd disassembly address alone does not select Thumb mode. Interworking
instructions can switch mode; a single linear decoder will not infer all switches.

For x86, `md.syntax` defaults to `CS_OPT_SYNTAX_INTEL`; setting
`CS_OPT_SYNTAX_ATT` changes text and operand presentation. Keep one fixed syntax
for structured analysis and validate operand roles, rather than switching display
settings mid-analysis. `md.mode` is mutable, but separate handles make mode-specific
records easier to interpret. Configure options before starting a generator.

**Runnable example — the same bytes under 32- and 64-bit x86 modes:**

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OPT_SYNTAX_ATT
from capstone.x86_const import X86_INS_DEC, X86_INS_MOV

code = bytes.fromhex('4889c8')
x64 = Cs(CS_ARCH_X86, CS_MODE_64)
x32 = Cs(CS_ARCH_X86, CS_MODE_32)
a, b = list(x64.disasm(code, 0x1000)), list(x32.disasm(code, 0x1000))
assert [i.id for i in a] == [X86_INS_MOV]
assert [i.size for i in a] == [3]
assert [i.id for i in b] == [X86_INS_DEC, X86_INS_MOV]
assert [i.size for i in b] == [1, 2]
att = Cs(CS_ARCH_X86, CS_MODE_64)
att.syntax = CS_OPT_SYNTAX_ATT
shown = list(att.disasm(code, 0x1000))
assert shown[0].id == a[0].id
assert bytes(shown[0].bytes) == code
assert shown[0].op_str != a[0].op_str
print('Mode boundaries and syntax checks passed')
```

<a id="s04"></a>
## [S04] Decoder contracts, partial results, and strict coverage

| Call | Parameters and result |
| --- | --- |
| `md.disasm(code, offset, count=0)` | `code` is bytes-like; `offset` is starting instruction address; `count` is maximum instruction records, zero for no cap. Returns a generator of `CsInsn`. |
| `md.disasm_lite(code, offset, count=0)` | Same decoding inputs; yields `(address: int, size: int, mnemonic: str, op_str: str)` tuples. No detail objects or instruction IDs in each tuple. |
| `md.errno()` | Current native handle error code; not a completeness certificate for a partial decode. |
| `CsError.errno` | Integer error code on a raised engine/binding exception. Catch around iteration too, because calls are lazy at the Python generator boundary. |

Use a nonnegative address fitting the native 64-bit address field and a
nonnegative count. Do not depend on implicit conversion/wrapping of negative
Python integers. Prefer immutable `bytes`; do not mutate a buffer during native
consumption. No symbols, relocations, or page mappings are supplied automatically.

Without skipdata, decoding generally stops at the first invalid or incomplete
instruction. Remaining bytes can be data, unsupported encodings, a mode mistake,
or a truncated instruction. Normal termination alone does not distinguish these.
`count=1` also intentionally leaves bytes. Sum sizes and inspect the remaining
suffix, while reporting why your caller requested a bound.

**Runnable example — strict contiguous decoding distinguishes coverage failure
from a successful prefix:**

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def decode_exact(code, base):
    md = Cs(CS_ARCH_X86, CS_MODE_64)  # skipdata remains disabled
    rows = list(md.disasm(code, base))
    used = 0
    for ins in rows:
        assert ins.address == base + used and ins.size > 0
        assert bytes(ins.bytes) == code[used:used + ins.size]
        used += ins.size
    if used != len(code):
        raise ValueError(f'Unconsumed bytes at {base + used:#x}: {code[used:].hex()}')
    return rows

assert len(decode_exact(b'\x90\xc3', 0x1000)) == 2
md = Cs(CS_ARCH_X86, CS_MODE_64)
partial = list(md.disasm(b'\x90\x0f', 0x1000))
assert len(partial) == 1 and partial[0].size == 1
try:
    decode_exact(b'\x90\x0f', 0x1000)
except ValueError as error:
    assert '0x1001' in str(error)
else:
    raise AssertionError('Truncated suffix was accepted as fully decoded')
assert len(list(md.disasm(b'\x90\xc3', 0x1000, count=1))) == 1
assert list(md.disasm(b'', 0x1000)) == []
print('Exact coverage, truncation, count limit and empty input passed')
```

Exact byte coverage is a syntactic property under the chosen mode. Arbitrary data
can decode completely, especially on x86. See [S14](#s14) before treating it as a
function or CFG.

<a id="s05"></a>
## [S05] Instruction detail, operands, and register access

Set `md.detail = True` before decoding. The `CsInsn` record's basic properties are
`id` (architecture-specific instruction ID), `address`, `size` (bytes), `bytes`
(a `bytearray` copy in tested 5.0.7), `mnemonic`, and `op_str`. Use `bytes(ins.bytes)`
for immutable records. Do not persist raw numeric IDs as a cross-version schema;
store architecture, version, names, and original bytes as well.

| Detail API | Return / interpretation |
| --- | --- |
| `ins.operands` | Architecture-specific operand list; discriminate on `operand.type` before reading its union field. |
| `ins.groups` / `ins.group(group_id)` | Integer group IDs / membership boolean; `CS_GRP_JUMP`, `CS_GRP_CALL`, `CS_GRP_RET` are useful common groups. |
| `ins.regs_read`, `ins.regs_write` | Lists of implicitly read/written register IDs. |
| `ins.reg_read(id)`, `ins.reg_write(id)` | Tests of those implicit lists, not all explicit operands. |
| `ins.regs_access()` | `(read_ids, written_ids)` including explicit and implicit effects where supported; can raise for unsupported detail/backend. |
| `ins.reg_name(id)`, `ins.insn_name()`, `ins.group_name(id)` | Human-readable names or an absent/default result. The handle also has name lookup methods. |
| `ins.op_count(type)` | Number of matching operands. |
| `ins.op_find(type, position)` | Matching operand at **one-based** position, or `None` when absent. Do not pass position 0. |

For x86, import constants from `capstone.x86_const`: `X86_OP_REG`, `X86_OP_IMM`,
`X86_OP_MEM`, `X86_REG_RIP`, and instruction/register IDs. `operand.size` is bytes.
`operand.access` contains `CS_AC_READ` / `CS_AC_WRITE` bit flags when available;
zero is not a general proof of “no effect.” Operand unions contain `.reg`, `.imm`,
or `.mem`; memory has `.segment`, `.base`, `.index`, `.scale`, `.disp`.

**Runnable example — x86 RIP-relative memory and explicit/implicit register effects:**

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_READ, CS_AC_WRITE
from capstone.x86_const import (
    X86_OP_REG, X86_OP_MEM, X86_REG_RAX, X86_REG_RBX, X86_REG_RIP, X86_REG_EFLAGS)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
code = bytes.fromhex('488b05100000004801d8')
load, add = list(md.disasm(code, 0x1000))
assert load.operands[0].type == X86_OP_REG
assert load.operands[0].reg == X86_REG_RAX
memory = load.operands[1]
assert memory.type == X86_OP_MEM and memory.size == 8
assert memory.mem.base == X86_REG_RIP and memory.mem.disp == 0x10
reference = load.address + load.size + memory.mem.disp
assert reference == 0x1017
assert memory.access & CS_AC_READ
reads, writes = add.regs_access()
assert {X86_REG_RAX, X86_REG_RBX} <= set(reads)
assert {X86_REG_RAX, X86_REG_EFLAGS} <= set(writes)
assert X86_REG_RBX not in add.regs_read  # Explicit operand, not implicit metadata.
assert add.operands[0].access & CS_AC_READ
assert add.operands[0].access & CS_AC_WRITE
assert load.op_count(X86_OP_MEM) == 1
assert load.op_find(X86_OP_MEM, 1).mem.base == X86_REG_RIP
assert load.op_find(X86_OP_MEM, 2) is None
print('Operand, RIP-relative and register-access checks passed')
```

`0x1017` is the computed reference, not a memory read or proof that the address is
mapped. For general x86 effective addresses, runtime registers, segment bases
(FS/GS), address-size rules, and wrapping can matter. RIP-relative addresses use
the end of the instruction. `LEA` computes an address without dereferencing it;
a memory-shaped operand is not automatically a memory access.

<a id="s06"></a>
## [S06] Direct targets, indirect transfers, and groups

Groups classify instructions; they do not produce a complete CFG. On the tested
x86 decoder, a direct relative call/jump has an `X86_OP_IMM` operand containing the
resolved target address for the supplied base. Do not add the instruction address
to that operand again. The raw encoded displacement is a different quantity.

An indirect `call rax` or `jmp [rip+disp]` needs runtime state or additional data
analysis. The RIP-relative address of an indirect jump's pointer slot is **not**
the final jump destination. Returns need stack state; system calls and exceptions
have environment-specific transitions. A call's next instruction is a potential
return continuation, not a guaranteed successor (the callee might never return).

**Runnable example — x86 direct and indirect call distinction:**

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86_const import X86_OP_IMM, X86_OP_REG

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
# Direct call +5, conditional branch +2, return, NOP, return, indirect call rax.
code = bytes.fromhex('e8050000007502c390c3ffd0')
rows = list(md.disasm(code, 0x2000))
direct, conditional, ret = rows[:3]
assert direct.group(CS_GRP_CALL)
assert direct.operands[0].type == X86_OP_IMM
assert direct.operands[0].imm == 0x200a
assert conditional.group(CS_GRP_JUMP)
assert conditional.operands[0].imm == 0x2009
assert ret.group(CS_GRP_RET)
indirect = rows[-1]
assert indirect.group(CS_GRP_CALL)
assert indirect.operands[0].type == X86_OP_REG
assert sum(i.size for i in rows) == len(code)
print('Direct target arithmetic and unresolved indirect call passed')
```

Targets outside the supplied bytes are not automatically invalid; they may be
another function, a PLT stub, or an unmapped/error path. Record them as external
or unresolved until the relevant mapping and semantics are known. Relocations in
object files can leave branch operands as placeholders; consult the object loader.

<a id="s07"></a>
## [S07] Skip-data mode and pseudo-instructions

`md.skipdata = True` asks the engine to step over undecodable regions and continue.
It does not infer all embedded data: bytes that happen to be valid instructions
will still decode as instructions. Default skip width depends on the architecture;
it is one byte for the x86 example below. A skipped record has **`id == 0`** and
usually mnemonic `.byte`; do not count it as decoded code.

**Runnable example — distinguish decoded instructions from skipped bytes:**

```python
from capstone import Cs, CsError, CS_ARCH_X86, CS_MODE_64, CS_ERR_SKIPDATA

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True
md.skipdata_setup = ('data', None, None)  # Rename display; keep default skip behavior.
code = b'\x90\x0f'
records = list(md.disasm(code, 0x1000))
assert len(records) == 2
real, skipped = records
assert real.id != 0 and real.mnemonic == 'nop'
assert skipped.id == 0 and skipped.mnemonic == 'data'
assert bytes(skipped.bytes) == b'\x0f'
assert real.size + skipped.size == len(code)
try:
    _ = skipped.groups
except CsError as error:
    assert error.errno == CS_ERR_SKIPDATA
else:
    raise AssertionError('Data placeholder exposed instruction groups')
print('Skip-data accounting and detail rejection passed')
```

`md.skipdata_setup = (mnemonic, callback, user_data)` configures display and an
optional native callback. The callback receives `(code_pointer, code_size, offset,
user_data_pointer)` and returns a byte count to skip; zero requests stopping.
The pointer and sizes refer to the buffer passed by the engine. Read no bytes
outside its reported bounds, return no more than the available suffix, and keep
callback/user data alive for native use. `user_data` is a pointer-compatible value,
not an arbitrary Python object. A Python callback exception is not a sound native
error protocol; handle errors explicitly and return zero when uncertain.

Custom callbacks are not exercised here. Only use them when a real format rule
identifies the data length. A permissive callback that skips errors makes coverage
look better while discarding evidence. See
[official skip-data guide](https://www.capstone-engine.org/skipdata.html).

<a id="s08"></a>
## [S08] Small multi-architecture fixtures

Each architecture has its own constants and operand structure: `arm_const`,
`arm64_const`, `mips_const`, and `riscv_const` are not interchangeable with
`x86_const`. ARM operands also encode shifts and condition information; AArch64
operands can have extensions and vector arrangements. RISC-V aliases such as
`ret` are presentation choices; retain bytes and IDs when comparing tools.

**Runnable example — ARM, Thumb, ARM64, big-endian MIPS32, and RISC-V64.**
The expected mnemonics are tiny 5.0.7 fixture checks, not a universal disassembly
serialization format. Missing backend support fails explicitly instead of silently
counting a skipped test as a pass.

```python
import capstone as cs

fixtures = [
    ('ARM', cs.CS_ARCH_ARM, cs.CS_MODE_ARM,
     '010080e21eff2fe1', [4, 4], ['add', 'bx']),
    ('Thumb', cs.CS_ARCH_ARM, cs.CS_MODE_THUMB,
     '01207047', [2, 2], ['movs', 'bx']),
    ('ARM64', cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN,
     '200080d2c0035fd6', [4, 4], ['mov', 'ret']),
    ('MIPS32-BE', cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN,
     '2402000103e0000800000000', [4, 4, 4], ['addiu', 'jr', 'nop']),
    ('RISC-V64', cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64,
     '1305100067800000', [4, 4], ['addi', 'ret']),
]
for name, arch, mode, encoded, sizes, mnemonics in fixtures:
    assert cs.cs_support(arch), f'Missing backend: {name}'
    code = bytes.fromhex(encoded)
    md = cs.Cs(arch, mode)
    rows = list(md.disasm(code, 0x8000))
    assert [i.size for i in rows] == sizes, name
    assert [i.mnemonic for i in rows] == mnemonics, name
    assert b''.join(bytes(i.bytes) for i in rows) == code, name
    assert rows[-1].address + rows[-1].size == 0x8000 + len(code), name
print('Five architecture fixtures passed')
```

The MIPS `nop` following `jr` demonstrates bytes in a delay-slot position, not a
branch-emulation result. Capstone does not execute the delay slot or infer that a
particular branch executes it. ARM PC-relative arithmetic also differs from x86:
architectural PC bias/alignment and state must be handled using the instruction's
actual architecture rules, not a copied RIP-relative formula.

<a id="s09"></a>
## [S09] Executable files: extract bytes and preserve address mappings

Capstone accepts bytes, not a complete executable loading specification. Feeding
an ELF or PE file from byte zero disassembles headers as if they were code. Use a
loader/parser such as LIEF to locate relevant file-backed ranges first. No file
parsing dependency is needed for any other Capstone example in this reference.

| Input domain | Mapping needed before decoding |
| --- | --- |
| ELF linked code | Use a VA and its enclosing file-backed load segment; compute file offset. `.o` symbols can be section-relative instead. |
| PE code | Section virtual address is an RVA; map RVA to file offset. Choose RVA or preferred/runtime VA deliberately as the displayed base. |
| Mach-O | Choose the correct architecture slice and translate its VM address; distinguish slice offsets from universal-container offsets. |
| Runtime dump | Preserve mapping base, holes, permissions, architecture/mode, and memory changes. Original-file bytes may differ after relocations. |

**Runnable example — compile a local ELF, extract one function with LIEF, decode.**
Requires Linux x86-64, `cc` on PATH, and LIEF (tested 1.0.0). Creates only temporary
files and never executes the generated target. No missing companion source is
required; the entire fixture is below.

```python
from pathlib import Path
import subprocess
import tempfile
import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_RET

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source, executable = root/'sample.c', root/'sample'
    source.write_text('int answer(void) { return 42; }\nint main(void) { return answer(); }\n')
    subprocess.run(['cc', '-O0', '-fno-pie', '-no-pie', str(source),
                    '-o', str(executable)], check=True)
    binary = lief.ELF.parse(executable)
    assert binary is not None
    symbol = binary.get_symbol('answer')
    assert symbol is not None and symbol.size > 0
    address, length = symbol.value, symbol.size
    mappings = [segment for segment in binary.segments
                if segment.type == lief.ELF.Segment.TYPE.LOAD
                and segment.virtual_address <= address
                and address + length <= segment.virtual_address + segment.physical_size]
    assert len(mappings) == 1
    offset = binary.virtual_address_to_offset(address)
    assert not isinstance(offset, lief.lief_errors)
    image = executable.read_bytes()
    assert 0 <= offset <= len(image) - length
    code = image[offset:offset + length]
    assert code == bytes(binary.get_content_from_virtual_address(address, length))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    rows = list(md.disasm(code, address))
    assert rows and rows[0].address == address
    assert sum(i.size for i in rows) == length
    assert b''.join(bytes(i.bytes) for i in rows) == code
    assert any(i.group(CS_GRP_RET) for i in rows)
    print(f'ELF function: {len(rows)} instructions, {length} bytes')
```

The fixture's symbol size supplies a trusted range for this test. Real symbols can
be absent, zero-sized, overlap, or not identify full function boundaries. Compiler
output varies; the test deliberately avoids a fixed instruction count.

<a id="s10"></a>
## [S10] Bounded instruction traversal with explicit unresolved cases

Linear decoding and control-flow traversal answer different questions. The former
interprets consecutive bytes; the latter follows candidate successors from an
entry. A full traversal must handle indirect targets, calls, exceptions, mode
changes, overlapping instructions, and target-specific semantics. Capstone does
not perform those analyses for you.

**Runnable example — deliberately small x86 instruction graph.** This complete
lab supports only NOP, JE, JMP, and RET in a single range. It explores both sides
of JE without evaluating flags. Unknown instructions/transfers and resource limits
are recorded, never silently treated as terminal success. It is not a general CFG
recovery algorithm or a proof of feasible execution paths.

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_INS_NOP, X86_INS_JE, X86_INS_JMP, X86_INS_RET, X86_OP_IMM

def traverse(code, base, max_instructions=32):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    pending, seen, edges, unresolved = [base], {}, {}, []
    while pending and len(seen) < max_instructions:
        address = pending.pop()
        if address in seen:
            continue
        offset = address - base
        if not 0 <= offset < len(code):
            unresolved.append((address, 'outside supplied bytes'))
            continue
        ins = next(md.disasm(code[offset:], address, count=1), None)
        if ins is None:
            unresolved.append((address, 'undecodable'))
            continue
        seen[address] = (ins.id, ins.size)
        successors = []
        if ins.id == X86_INS_RET:
            pass  # Exit from this local graph; caller return target is outside scope.
        elif ins.id == X86_INS_NOP:
            successors = [address + ins.size]
        elif ins.id in (X86_INS_JE, X86_INS_JMP):
            if ins.operands[0].type != X86_OP_IMM:
                unresolved.append((address, 'indirect target'))
            else:
                successors.append(ins.operands[0].imm)
                if ins.id == X86_INS_JE:
                    successors.append(address + ins.size)
        else:
            unresolved.append((address, 'instruction outside lab semantics'))
        edges[address] = set(successors)
        pending.extend(target for target in successors if target not in seen)
    remaining = set(pending) - set(seen)
    return seen, edges, unresolved, remaining

base = 0x1000
code = bytes.fromhex('740390eb0190c3')
seen, edges, unresolved, remaining = traverse(code, base)
assert set(seen) == {0x1000, 0x1002, 0x1003, 0x1005, 0x1006}
assert edges[0x1000] == {0x1002, 0x1005}
assert edges[0x1003] == {0x1006}
assert not unresolved and not remaining
assert traverse(code, base, max_instructions=1)[3]  # Budget is incomplete work.
assert traverse(bytes.fromhex('ffe0'), base)[2] == [(base, 'indirect target')]
loop_seen, _, loop_unknown, loop_pending = traverse(bytes.fromhex('ebfe'), base)
assert set(loop_seen) == {base} and not loop_unknown and not loop_pending
print('Bounded graph, unresolved indirect jump, loop and budget checks passed')
```

“No pending nodes” here means closure under the lab's syntactic successor rules,
not semantic reachability or termination. The infinite-jump fixture illustrates
that graph enumeration can finish even when a program loop would not terminate.
For conditional paths, emulator/symbolic-engine state and environment assumptions
are necessary to reason about feasibility.

<a id="s11"></a>
## [S11] Widths, signedness, flags, and semantic boundaries

Python integers are concrete and unbounded. Capstone's native operand fields use
fixed-width integer representations; interpretation depends on architecture and
instruction. An immediate field may be sign-extended; its printed form can differ
from the exact encoded byte width. Do not convert every immediate to an unsigned
pointer or use host endianness to reconstruct it.

For x86 detail, `ins.encoding` and fields such as `imm_offset`, `imm_size`,
`disp_offset`, and `disp_size` describe locations within instruction bytes. Offsets
and sizes are bytes; a zero size denotes absent encoding in the relevant field.
Some instructions have multiple immediates or implicit constants: do not assume
one offset pair is a complete generic patch plan. Decode and independently verify
after modification; changing length affects later branch displacements.

`ins.eflags` contains metadata flags such as `X86_EFLAGS_MODIFY_ZF`, not a computed
runtime EFLAGS value. `operand.access` is a bitmask, not an actual trace. Register
aliases and partial writes matter: writing EAX zero-extends into RAX in x86-64,
while writing AL has a different effect. A simplistic set of register names is
not complete dataflow. ARM condition codes, shifts, writeback, and AArch64
extensions also affect semantics beyond an operand's register ID.

The API does not lift instructions to a sound intermediate representation,
resolve memory aliasing, infer calling conventions, or calculate runtime effects.
Use appropriate architecture semantics, an emulator, or an analysis engine for
those tasks, and report unsupported instructions and environment assumptions.

<a id="s12"></a>
## [S12] Performance, chunking, and lifetime

Use `disasm_lite` when only presentation tuples are required; avoid `detail=True`
for a plain listing. Do not quote a universal speedup: it depends on input, build,
architecture, and allocation costs. Keep `count` and input ranges bounded when
only a small result is needed.

Although Python exposes a generator, the tested binding invokes native
`cs_disasm` to decode a batch before yielding Python records. Breaking a loop after
one record is not equivalent to `count=1` for allocation or native work. Likewise,
`disasm_lite` reduces Python object overhead but still uses the native batch API.
Large inputs can allocate a large result array. For hostile or unusually large
inputs, bound file sizes and run decoding in a resource-limited process.

Chunking must preserve instruction boundaries. x86 instructions can be up to 15
bytes; a chunk can end in an incomplete instruction, but incomplete and invalid
suffixes are not automatically distinguished. Retain the undecoded suffix, append
more bytes, and retry from its original address under an explicit maximum-buffer
policy. Do not skip arbitrary bytes to make progress while claiming exact decode.
For Thumb/RISC-V compressed code, widths vary too. Never concatenate bytes across
unmapped regions as if addresses were contiguous.

The 5.0.7 Python binding copies instruction records and available detail into
`CsInsn` objects and retains a reference to their `Cs` handle. It frees the batch
allocation when the generator finishes/closes. Keep handles and live generators
scoped, and close an abandoned generator if deterministic release matters. This
binding exposes no documented `with Cs(...)` context-manager contract. Do not call
private native close functions behind still-live instruction objects.

Engine configuration is mutable and some property checks consult current handle
options. Use a fixed configuration throughout a decode/result lifetime. For
parallel work use separate decoder handles rather than assuming arbitrary shared
handle mutation is thread-safe. Convert results into plain immutable records for
long-term storage or interprocess transfer.

<a id="s13"></a>
## [S13] Errors and troubleshooting

`CsError` is the binding's engine exception. Catch it around both construction and
iteration; inspect `.errno` and the error message. Empty or partial iteration often
is **not** an exception. Test coverage separately as in [S04](#s04).

| Symptom / code | Meaning or likely cause | Next action |
| --- | --- | --- |
| Import/native library failure | Binding/core library unavailable, local `capstone.py` shadowing, or mismatched platform | Check interpreter, `capstone.__file__`, installed wheel, and library paths. |
| `CS_ERR_VERSION` | Binding/native API mismatch | Record both versions and repair the environment; do not suppress the exception. |
| `CS_ERR_ARCH`, `CS_ERR_MODE` | Unsupported backend or invalid mode | Check `cs_support` and target-specific mode table. |
| `CS_ERR_OPTION` | Option unsupported for this build/backend | Check release and backend; do not force an x86 syntax on unrelated architectures. |
| `CS_ERR_DETAIL` | Detail absent / not enabled when needed | Enable before decoding, then decode again; toggling later cannot recreate missing data. |
| `CS_ERR_DIET` | Build omits requested metadata | Use an appropriate full build or explicitly reduce the analysis claim. |
| `CS_ERR_SKIPDATA` | Metadata requested from id-zero pseudo-record | Separate skipped data from instructions before accessing details. |
| Partial/empty iterator with no exception | Invalid/truncated bytes, wrong mode, count limit, or empty input | Inspect consumed size, options, suffix, and input mapping. |
| Plausible nonsense output | Wrong bitness/endian/mode or data interpreted as code | Verify target headers, symbols, entrypoints, and known bytes. |
| Direct targets shifted by a constant | Wrong base address domain | Correct the disassembly base; it is not a file-seek argument. |
| `.regs_read` lacks an operand register | Property is implicit-only | Use operands and `regs_access`, with backend limits. |
| Thumb code decoded as ARM | State bit/mode confusion | Align the code address and explicitly select Thumb. |
| Memory use jumps despite generator | Native batch allocation | Bound input/count; use planned chunking and separate processes as needed. |
| Text comparison changes across versions | Aliases/syntax/formatting differ | Compare bytes, IDs/structured fields within a recorded version, and semantics where needed. |

If a native crash occurs, record a minimal byte sequence, options, architecture,
and both version reports. It is not evidence that the bytes are impossible on the
real processor. Preserve the failure as an unresolved analysis result.

<a id="s14"></a>
## [S14] Practical analysis workflow and reporting

Before disassembling, answer: Where did the bytes come from? What selects this
architecture/mode? Which address does byte zero represent? Is this a complete
mapped range or an excerpt? Which structures are code versus data, and how is that
known? What byte/instruction/time budget is permitted?

After decoding, distinguish these outcomes:

| Observation | Supported conclusion | Unsupported leap |
| --- | --- | --- |
| All input bytes decoded without skipdata | Complete syntactic decoding of that range in that mode | Every byte is reachable code. |
| Some bytes left | Decoder/caller stopped before full coverage | Remainder cannot be executable on any configuration. |
| Skipdata consumed the entire range | Listing accounts for bytes including placeholders | Every byte decoded as an instruction. |
| Direct target falls inside range | Static reference can be mapped locally | A feasible execution necessarily reaches it. |
| No indirect target resolved | Available information is insufficient | There are no successors. |
| Worklist budget exhausted | Traversal incomplete | Unvisited code is unreachable. |
| Two tools agree | Corroborating decode evidence | Proof of all runtime behavior or absence of shared bugs. |

Record input identity/hash, exact bytes/range, architecture/mode/endian, linked or
runtime base, binding/native API versions, detail/syntax/skipdata options, consumed
bytes, data placeholders, unresolved references, stopping condition, and any
independent verification. For patched binaries, reread output bytes and regenerate
the decode. Reuse of cached instruction objects does not validate a new binary.

Capstone complements LIEF for file mapping, Unicorn for concrete emulation, and
angr for lifted/symbolic analysis. None of those integrations automatically makes
an incomplete CFG or inaccurate environment model sound.

<a id="s15"></a>
## [S15] Validation and self-contained reproduction

Checked environment: **CPython 3.12.14**, **capstone binding 5.0.7**, native API
**(5, 0, 1280)**, Linux x86-64, non-diet build. Project pin is **5.0.9**, which was
not installed or executed for these checks. S09 additionally uses **LIEF
1.0.0-d05b3499b** and the host `cc`; no target executable is run.

Executed successfully: **9 Runnable examples**, **7 doctest statements**,
all explicit internal anchor links, and Markdown fence checks. They cover decoding/lite equivalence, modes/syntax,
coverage/truncation/count, x86 operands/register metadata, direct/indirect targets,
skip-data behavior, five non-x86 architecture fixtures, ELF mapping, and bounded
traversal with unresolved and budget cases.

Not tested: Capstone 5.0.9, Capstone 6 APIs, native Windows/macOS, diet/reduced builds,
custom skip callbacks, big-endian ARM, compressed RISC-V instructions, 16-bit x86,
all ISA extensions, all register/flag metadata, concurrency, adversarial-input
robustness, exhaustive CFG recovery, emulation, or performance benchmarks.
Architecture-table entries describe configurations; only the explicitly listed
fixtures count as executed tests.

**Fragment/recipe — maintenance harness.** Save as `validate_capstone_reference.py` outside this document and run with
`.venv/bin/python` from ReversEnv. Do not name the script `capstone.py`, which
would shadow the installed package. It executes only this trusted file's explicitly
labeled Runnable example blocks, each in a separate process.

```python
from pathlib import Path
import doctest
import re
import subprocess
import sys
import tempfile

path = Path('doc/capstone-doc.md')
text = path.read_text()
sections = re.split(r'^<a id="s\d+"></a>\s*$', text, flags=re.M)
count = 0
with tempfile.TemporaryDirectory() as directory:
    for section in sections:
        if not re.search(r'^\*\*Runnable example', section, re.M):
            continue
        blocks = re.findall(r'^```python\n(.*?)^```\s*$', section, re.M | re.S)
        assert len(blocks) == 1
        script = Path(directory)/f'example_{count}.py'
        script.write_text(blocks[0])
        subprocess.run([sys.executable, str(script)], check=True, timeout=60)
        count += 1
assert count == 9
interactive = '\n\n'.join(re.findall(r'^```pycon\n(.*?)^```\s*$', text, re.M | re.S))
runner = doctest.DocTestRunner()
runner.run(doctest.DocTestParser().get_doctest(interactive, {}, str(path), str(path), 0))
result = runner.summarize()
assert result.failed == 0 and result.attempted == 7
anchors = re.findall(r'<a id="([^"]+)"></a>', text)
assert len(anchors) == len(set(anchors))
assert set(re.findall(r'\]\(#([^)]*)\)', text)) <= set(anchors)
opened = False
for line in text.splitlines():
    if line.startswith('```'):
        if opened:
            assert line == '```'
        opened = not opened
assert not opened
print(f'{count} runnable examples, {result.attempted} doctests, links/fences passed')
```

<a id="s16"></a>
## [S16] Primary sources and version migration

Sources consulted **2026-09-26**. All prose and lab fixtures here are original.
The installed binding implementation was inspected to resolve signatures,
allocation/lifetime behavior, default options, and explicit versus implicit
register metadata. Online guides are useful context but can describe older APIs.

| Primary source | Use |
| --- | --- |
| Installed `capstone/__init__.py` and `x86.py`, architecture constants | Directly inspected 5.0.7 Python contracts and structures; runtime tests above. |
| [Official Python guide](https://www.capstone-engine.org/lang_python.html) | Decoder setup, detail, modes, basic/lite APIs. |
| [Official skip-data guide](https://www.capstone-engine.org/skipdata.html) | Pseudo-instructions and callback design. |
| [Official Capstone repository](https://github.com/capstone-engine/capstone) | Native engine and versioned binding source. |

When updating this reference, first record both binding and native versions,
inspect the installed signatures, rerun fixtures, and investigate any changed
IDs, aliases, operands, or coverage. Preserve the stable anchors. Do not rename
ARM64 constants to future-release spellings without validating that migration in
the repository's intended environment.
