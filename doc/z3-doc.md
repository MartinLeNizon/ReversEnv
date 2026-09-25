# LIEF Python documentation for AI-assisted binary analysis

## Summary — read this first

**Subject: LIEF, not Z3.** This reference intentionally lives at `doc/z3-doc.md`
as requested. The Python distribution and import are both **`lief`**. LIEF parses,
inspects, edits, and rebuilds executable file formats. It is not a symbolic
executor, constraint solver, operating-system loader, or proof of program behavior.

**Version:** ReversEnv pins `lief==1.0.0`. This guide was checked against installed
LIEF **1.0.0-d05b3499b**, CPython **3.12.14**, Linux x86-64, on **2026-09-25**.
The installed package is the standard build (`lief.__extended__ == False`).
The normal workflow is **identify input → parse → inspect format and addresses →
make a bounded edit → write to a new path → reparse → verify the intended change →
test behavior in the target environment when required**.

Essential rules:

1. Check parse results for `None` and the expected concrete format. A partially
   parsed malformed file is not necessarily usable just because parsing returned.
2. Distinguish file offsets, relative virtual addresses (RVAs), link-time virtual
   addresses (VAs), and runtime addresses. Sizes and offsets here are **bytes**.
3. Use explicit `lief.Binary.VA_TYPES.RVA` or `.VA` for PE reads and patches;
   `AUTO` is the default and can hide an address-domain mistake.
4. Copy native views with `bytes(...)` when retaining content. Keep parent binary
   objects alive; reacquire sections and symbols after structural mutations.
5. Validate the whole patch range is file-backed. Zero-filled memory such as BSS
   does not automatically have bytes in the file that can be patched.
6. Editing changes the in-memory model. `write()` rebuilds it and can move data.
   Recompute addresses and offsets from the output, not from the old model.
7. PE import/export edits require corresponding builder options; in 1.0.0,
   `config.imports` and `config.exports` default to `False`.
8. Use `lief.MachO.parse()` for universal binaries: it returns a `FatBinary`,
   including for a thin input. Select an architecture deliberately.
9. Empty tables can mean stripped data, disabled parsing, or incomplete recovery.
   They are not proof that a program has no imports, symbols, or relevant behavior.
10. Reparse success checks structure, not runtime correctness. Editing signed
    content can invalidate signatures; copying signature bytes does not re-sign it.

## Task index — retrieve only what you need

| Question / API | Section |
| --- | --- |
| Install, check version, inspect an unfamiliar method | [S01 Installation](#s01) |
| First working parse; `lief.parse`, `bytes(section.content)` | [S02 Quick start](#s02) |
| Choose parser; `ParserConfig`; `None`, errors, ownership | [S03 Parsing and object model](#s03) |
| VA vs RVA vs file offset; ASLR; BSS; integer encoding | [S04 Addresses and bytes](#s04) |
| Sections, segments, symbols, imports, relocations | [S05 Inspection](#s05) |
| `patch_address`, `write`, builder configuration, verification | [S06 Editing contract](#s06) |
| ELF symbols, dependencies, RUNPATH, section insertion | [S07 ELF](#s07) |
| PE imports, exports, resources, Authenticode | [S08 PE](#s08) |
| Mach-O slices, load commands, dylibs, signing | [S09 Mach-O](#s09) |
| Complete ELF patch with native replay | [S10 ELF lab](#s10) |
| Complete PE rebuild with imports and a section | [S11 PE lab](#s11) |
| Complete Mach-O object inspection | [S12 Mach-O lab](#s12) |
| Debug parser failures or a broken rebuilt file | [S13 Troubleshooting](#s13) |
| Large inputs, specialized formats, angr integration, limits | [S14 Advanced boundaries](#s14) |
| Reproduce checks; tested / untested scope; primary references | [S15 Validation and sources](#s15) |

Every section has a stable explicit anchor. Code labeled **Runnable example** is
complete with its stated external requirements. **Fragment/recipe** needs the
specified input or surrounding objects. **Doctest** is executable interactive
Python. Printed symbol names, table order, addresses, and binary hashes are not
portable expected output unless explicitly asserted for a constructed fixture.

<a id="s01"></a>
## [S01] Installation and version discipline

Use ReversEnv's environment from the project root. The shell below is a
**Fragment/recipe** for an existing checkout; it does not create an environment:

```sh
.venv/bin/python -c 'import sys, lief; print(sys.version); print(lief.__version__); print(lief.__extended__)'
```

For an independent environment, this **Fragment/recipe** requires Python's `venv`
and package-index access:

```sh
python3 -m venv /tmp/lief-reference-env
/tmp/lief-reference-env/bin/python -m pip install 'lief==1.0.0'
```

Do not upgrade the project or replace its pins to run an example. Native wheel
availability depends on interpreter, OS, and architecture; a source build has
additional compiler/build requirements. No installation was necessary for this
reference. See [official installation guidance](https://lief.re/doc/stable/installation.html).

Check `help(lief.PE.Binary.write)` or a method's `.__doc__` against the installed
release before adapting old code. Current enums are nested, for example
`lief.ELF.Section.TYPE.PROGBITS` and `lief.ELF.Segment.TYPE.LOAD`. Old tutorials can
use removed top-level enums or obsolete PE builders. Never infer a Python call
signature from a C++ overload alone.

**Doctest — byte encoding and installed API defaults (1.0.0):**

```pycon
>>> import lief
>>> lief.__version__.split('-')[0]
'1.0.0'
>>> lief.PE.Builder.config_t().imports
False
>>> lief.PE.Builder.config_t().exports
False
>>> list((0x1234).to_bytes(2, 'little', signed=False))
[52, 18]
>>> int.from_bytes(b'\xff\xff', 'little', signed=True)
-1
```

<a id="s02"></a>
## [S02] Minimal working parse

**Runnable example — Linux only; uses the running Python executable as input.**
No external binary or compiler is required. This reads, but never edits, Python.

```python
import sys
from pathlib import Path
import lief

path = Path(sys.executable).resolve()
binary = lief.parse(path)
assert isinstance(binary, lief.ELF.Binary), 'This example requires an ELF Python'
section = binary.get_section('.text')
assert section is not None and section.size > 0
content = bytes(section.content)
assert len(content) == section.size
assert 0 <= section.offset <= path.stat().st_size - len(content)
assert path.read_bytes()[section.offset:section.offset + len(content)] == content
again = lief.parse(path.read_bytes())
assert isinstance(again, lief.ELF.Binary)
assert again.entrypoint == binary.entrypoint
print(type(binary).__name__, hex(binary.entrypoint), len(content))
```

`get_section(name)` can return `None`, including for stripped or unusual inputs.
The `.text` assumption belongs to this fixture, not every ELF. A content view is
not a snapshot until copied. See [S03](#s03) for ownership and [S04](#s04) before
using addresses from another analysis tool.

<a id="s03"></a>
## [S03] Parsing, object model, and failures

The following contracts were inspected in the installed Python bindings.

| Call | Return and important behavior |
| --- | --- |
| `lief.parse(obj)` | Concrete supported format object or `None`; dispatches by input. No parser configuration argument. |
| `lief.ELF.parse(obj, config=...)` | `lief.ELF.Binary` or `None`. |
| `lief.PE.parse(obj, config=...)` | `lief.PE.Binary` or `None`. |
| `lief.MachO.parse(obj, config=...)` | `lief.MachO.FatBinary` or `None`, even for one architecture. |

`obj` accepts a path (`str` or `os.PathLike`), raw `bytes`, `list[int]`, or supported
`io.IOBase` input. Bytes mean file content, not an encoded filename. For explicit,
repeatable stream behavior, read the desired data and pass `bytes`. Raw input must
be a supported file image; a memory dump is not automatically the same layout.

The generic parser in this build also lists OAT and COFF returns. Its Mach-O return
is a single `MachO.Binary`; use the format parser when preserving slices matters.
Other specialized formats have their own APIs; do not assume all inherit the same
editing capabilities.

**Fragment/recipe — configurable ELF parse; replace the input path:**

```python
import lief
config = lief.ELF.ParserConfig()
config.parse_relocations = True
config.parse_dyn_symbols = True
binary = lief.ELF.parse('input.elf', config)
if binary is None:
    raise ValueError('ELF parser did not return a binary')
```

Observed defaults in 1.0.0:

| Config | Relevant defaults |
| --- | --- |
| `ELF.ParserConfig()` | Dynamic and symtab symbols, relocations, notes, overlay, symbol versions enabled; `page_size=0` leaves size selection to the parser. |
| `PE.ParserConfig()` | Imports, exports, relocations, resources, signatures enabled; exceptions and alternative ARM64X binary parsing disabled. |
| `MachO.ParserConfig()` | Dyld bindings, exports, rebases enabled. `quick` and `deep` presets also exist; choose deliberately. |

Disabling work can improve inspection performance but produces an intentionally
incomplete model. Do not rewrite from a reduced model without verifying that the
skipped structures survive correctly. Create a fresh config rather than mutating
a shared preset object in place.

Failure reporting is API-specific: parsers may return `None` and emit diagnostics;
lookups return `None`; some methods return `lief.lief_errors`; type conversion or
I/O can raise exceptions. There is no universal “all failures raise” rule.
Capture diagnostics and distinguish unsupported input from a valid empty table.
For untrusted or very large files, parse in a resource-limited subprocess; Python
exception handling does not contain a native crash or excessive memory use.

Binary objects own native structures. Iterators and child objects should not be
used after the parent is discarded or a structural edit invalidates them. Do not
remove items while traversing a native iterator. Snapshot names/addresses first,
then perform mutations and reacquire the native objects.

References: [binary abstraction](https://lief.re/doc/stable/api/binary_abstraction/python.html),
[ELF parser](https://lief.re/doc/stable/formats/elf/python.html),
[PE parser](https://lief.re/doc/stable/formats/pe/python.html),
[Mach-O parser](https://lief.re/doc/stable/formats/macho/python.html).

<a id="s04"></a>
## [S04] Address domains, widths, and file-backed bytes

Python integers are concrete, arbitrary-precision values. LIEF converts them to
bounded native fields; negative or oversized values can fail conversion. There
are no symbolic expressions or solver constraints here. Validate ranges yourself.
Read machine type, bitness, and byte order from the target, not the host Python.

| Domain | Meaning and correct conversion |
| --- | --- |
| File offset | Byte index in the on-disk image. Not an argument to `patch_address`. |
| ELF linked VA | Address described by ELF load segments. For a file-backed `PT_LOAD`: `offset = segment.file_offset + (va - segment.virtual_address)`. |
| PE RVA | Address relative to the image base; section `virtual_address` is an RVA. Use `rva_to_offset(rva)`. |
| PE preferred VA | `optional_header.imagebase + rva`; use `va_to_offset(va)`. |
| Mach-O VA | Segment VM address domain; translate with `virtual_address_to_offset(va)`. |
| Runtime address | Includes loader relocation / ASLR. Subtract the known load bias or slide before converting to the original file's VA domain. |

For PE runtime addresses, first compute `rva = runtime_va - actual_loaded_base`.
For ELF PIE, `runtime_va = linked_va + load_bias`; do not blindly subtract the first
mapping address, which can include a nonzero file offset. For Mach-O fat files,
distinguish offsets within a slice from positions in the enclosing universal file.

`ELF.Binary.virtual_address_to_offset(va)` and the Mach-O counterpart return
`int | lief.lief_errors`. Check for `lief.lief_errors` before treating the result
as an offset. `PE.Binary.rva_to_offset(rva)` returns an integer; a numerical result
alone does not establish that the full range is valid or backed by file data.
Validate the section/header region and file length separately.

A range `[va, va+n)` must fit the file-backed part of the containing mapping.
ELF uses `segment.physical_size` for file bytes and `virtual_size` for memory size.
An ELF `NOBITS` section, PE virtual tail, or Mach-O zero-fill section can exist in
memory without corresponding file bytes. Reading a shorter result is not success.
Reject ambiguous overlapping mappings unless you deliberately model loader rules.

| Operation | Contract |
| --- | --- |
| `binary.get_content_from_virtual_address(address, size, va_type=VA_TYPES.AUTO)` | Returns a `memoryview`; `size` is bytes. Copy with `bytes(...)`, then check length. Explicit VA/RVA selection is particularly important for PE. |
| `section.content` | Native byte view on read; use a sequence of byte integers for assignment. `bytes(section.content)` creates an independent snapshot. |
| `value.to_bytes(width, byteorder, signed=False)` | Python encoding; width is bytes, byte order is `'little'` or `'big'`. Raises on out-of-range values. |
| `int.from_bytes(data, byteorder, signed=False)` | Python decoding; signedness is your explicit interpretation. |

Prefer explicitly encoded byte sequences for integer patches, so endian and width
choices are reviewable. ELF symbol values in relocatable `.o` files can be
section-relative; undefined symbols, TLS symbols, and absolute symbols require
special handling. Do not treat every `symbol.value` as an executable VA.

<a id="s05"></a>
## [S05] Inspect sections, symbols, imports, and relocations

Inspect the concrete type first. Generic `sections`, `symbols`, `entrypoint`,
`imported_functions`, `exported_functions`, and `libraries` provide useful summaries,
but format-specific tables retain details that the common view cannot express.
The entrypoint is a header entry, not necessarily `main`; initializers, TLS
callbacks, or loader behavior can execute other code first.

| Question | Format-specific starting points | Interpretation trap |
| --- | --- | --- |
| What is mapped? | ELF `segments`; PE `sections` plus headers; Mach-O `segments` | Section names do not determine loader permissions. |
| Where is a symbol? | ELF `symtab_symbols`, `dynamic_symbols`, `get_symbol(name)` / `get_dynamic_symbol(name)` | Stripping, symbol versions, duplicates, undefined and TLS symbols matter. |
| What does PE import? | `binary.imports`; each import has `name`, `entries` | Check `entry.is_ordinal` before using `entry.name`; delay imports are separate. |
| What does PE export? | `binary.get_export()` then `.entries` | It can return `None`; forwarded exports do not identify local code. |
| What libraries are declared? | ELF `libraries`; PE imports; Mach-O `libraries` commands | Runtime loading can add undeclared dependencies. |
| What needs relocation? | ELF `relocations`, `dynamic_relocations`, `pltgot_relocations`; PE `relocations`; Mach-O dyld metadata | Relocation arithmetic depends on machine, type, width, and addend. |

**Fragment/recipe — inventory a PE; replace the input path:**

```python
import lief
binary = lief.PE.parse('input.exe')
if binary is None:
    raise ValueError('Cannot parse PE')
for library in binary.imports:
    for entry in library.entries:
        target = f'ordinal:{entry.ordinal}' if entry.is_ordinal else entry.name
        print(library.name, target)
exports = binary.get_export()
if exports is not None:
    for entry in exports.entries:
        print(entry.ordinal, entry.name, hex(entry.address))
```

Collect output as evidence of **declared metadata**, not a recovered complete call
graph. ELF relocation addends can be explicit (RELA) or stored at the relocation
site (REL); LIEF parsing is not equivalent to applying the target loader. A symbol
name match does not prove the runtime linker resolves to that exact definition.

<a id="s06"></a>
## [S06] Editing and rebuilding contracts

| API | Parameters, result, and side effects |
| --- | --- |
| `binary.patch_address(address, patch_value, va_type=VA_TYPES.AUTO)` | `patch_value` is a sequence of integers in `0..255`; writes the in-memory content; returns `None`. Does not accept a file offset. |
| `binary.patch_address(address, integer, size=8, va_type=VA_TYPES.AUTO)` | Integer overload; default size is **8 bytes**, potentially wrong for the target. Prefer explicit byte encoding instead. |
| `ELF.Binary.write(output, config=...)` | Rebuilds to path; returns `None`; optional `ELF.Builder.config_t`. |
| `PE.Binary.write(output, config=...)` | Rebuilds to path; returns `None`; optional `PE.Builder.config_t`. |
| `MachO.Binary.write(output, config=...)` | Writes one slice; optional `MachO.Builder.config_t`; returns `None`. |
| `MachO.FatBinary.write(output)` | Rebuilds the container; returns `None`. Use to preserve multiple slices. |
| `PE.Builder(binary, config)` | Explicit builder constructor. `build()` returns `lief.ok_t` or `lief.lief_errors`; `write(path)` writes the build result. |

A `None` return from a void mutation is not a success flag. Read back the modified
range in memory, then write and reparse. `write()` is not a byte-preserving copy;
layout, padding, tables, and metadata can change. It can overwrite an existing path,
so select a new destination and preserve the original and its hash.

**Fragment/recipe — PE RVA patch; requires a parsed PE and a verified file-backed
range at `rva`, plus a new output path:**

```python
rva = 0x1000  # Placeholder: determine from this target; not a universal code address.
patch = (0x1234).to_bytes(2, 'little', signed=False)
kind = lief.Binary.VA_TYPES.RVA
before = bytes(binary.get_content_from_virtual_address(rva, len(patch), kind))
if len(before) != len(patch):
    raise ValueError('Incomplete patch range')
binary.patch_address(rva, list(patch), kind)
assert bytes(binary.get_content_from_virtual_address(rva, len(patch), kind)) == patch
binary.write('patched.exe')
```

This recipe assumes `import lief` and `binary` from [S05](#s05). It illustrates the
byte API, not a valid instruction change for an arbitrary executable. Instruction
patches must respect architecture, instruction boundaries, relative operands,
unwind metadata, branch targets, and relocation sites.

For structural edits, use the new object returned by `add`/`add_section`, not the
unattached input object, to inspect assigned addresses. After rebuilding, reacquire
all offsets and verify content in the reparsed binary. Restore executable file
permissions intentionally when replaying an ELF; do not assume writing preserves
the source mode. See the complete [ELF lab](#s10).

<a id="s07"></a>
## [S07] ELF operations

`ELF.Binary` exposes headers, sections, program segments, dynamic entries, symbols,
relocations, notes, and interpreter information. For runtime layout, start with
`PT_LOAD` segments; section headers can be absent from otherwise loadable files.

| Task | API / essential behavior |
| --- | --- |
| Get a section | `get_section(name: str) -> Section | None`. |
| Add metadata section | `Section(name, type=Section.TYPE.PROGBITS)`; set `.content`; `binary.add(section, loaded=False) -> Section | None`. Default `loaded=True` would request a loaded section. |
| Add a load segment | `binary.add(segment, base=0) -> Segment | None`; layout/alignment and permissions require target-specific verification. |
| Add dependency | `binary.add_library(name: str) -> DynamicEntryLibrary`; adds a declaration, not symbol calls or a bundled library. |
| Remove dependency | `binary.remove_library(name: str) -> None`; can break unresolved references. |
| Query dynamic tag | `binary.get(lief.ELF.DynamicEntry.TAG.RUNPATH) -> DynamicEntry | None`; `.has(tag)` gives a boolean. |
| Add dynamic entry | `binary.add(entry: DynamicEntry) -> DynamicEntry`; avoid duplicate singleton tags. |

**Fragment/recipe — inspect RUNPATH on an existing parsed ELF:**

```python
import lief
entry = binary.get(lief.ELF.DynamicEntry.TAG.RUNPATH)
if entry is not None:
    print(entry.runpath)
```

RPATH and RUNPATH have different loader search semantics. `$ORIGIN` is loader
syntax and must remain literal when passed through shells. Changing the
interpreter or search path does not guarantee the library ABI exists on another
host. Symbol renaming can require coordinated references, versioning, hash tables,
and string-table updates; changing one arbitrary name is not a general ABI rewrite.

`ELF.Builder.config_t()` has many rebuild controls. In this build `notes=False`,
`force_relocate=False`, `skip_dynamic=False`; common dynamic tables and static
symbols are enabled. If modifying notes, explicitly review `config.notes`.
Builder switches are not permission to discard structures the analysis skipped.

Reference: [ELF Python API](https://lief.re/doc/stable/formats/elf/python.html).

<a id="s08"></a>
## [S08] PE operations

Separate `header` (COFF metadata) from `optional_header` (PE image metadata).
Despite its name, the latter is needed for a normal PE image. `imagebase` is a
preferred base; the loader can relocate it. Section `virtual_size` and
`sizeof_raw_data` differ; raw alignment padding is not extra meaningful code.

| Task | API / essential behavior |
| --- | --- |
| Find RVA section | `section_from_rva(rva: int) -> Section | None`; validate the requested range, not just its first byte. |
| Add section | `Section(name)` then `.content`, `.characteristics`; `add_section(section) -> Section | None`. Old two-argument section-type recipes are not the 1.0.0 signature. |
| Add DLL import | `add_import(import_name: str, pos=-1) -> Import`; default appends. |
| Add function import | `import_object.add_entry(function_name: str) -> ImportEntry`. |
| Inspect exports | `get_export() -> Export | None`; enable `config.exports=True` when rebuilding edited exports. |
| Resources / TLS | `resources`, `resources_manager`, `tls`; check presence before descending into format-specific objects. |
| Verify signatures | `verify_signature(checks=Signature.VERIFICATION_CHECKS.DEFAULT) -> Signature.VERIFICATION_FLAGS`. Interpret flags, not truthiness as success. |

To preserve import edits, create `config = lief.PE.Builder.config_t()`, set
`config.imports = True`, and call `binary.write(output, config)`. The analogous
exports switch is also false by default. In contrast, resources, relocations,
load configuration, TLS, debug, and overlay controls default to true in this build.
Adding an import does not insert a call instruction; import rebuilding can affect
IAT layout, so existing code references require additional validation.

Authenticode verification concerns signature/digest consistency under chosen
checks. It is not a malware verdict or a substitute for platform trust policy,
revocation, and signing requirements. Changes to signed content can invalidate
signatures. The PE certificate directory uses a file offset, an exception to the
usual RVA interpretation of data directories. Do not run all directory values
through `rva_to_offset` indiscriminately.

References: [PE Python API](https://lief.re/doc/stable/formats/pe/python.html),
[Authenticode tutorial](https://lief.re/doc/stable/tutorials/13_pe_authenticode.html).

<a id="s09"></a>
## [S09] Mach-O operations

`fat = lief.MachO.parse(input)` returns a container. Check `fat is not None`, keep
it alive, then iterate slices or select with
`fat.get(lief.MachO.Header.CPU_TYPE.X86_64)`. `fat.at(index)` and `fat.get(cpu)` can
return `None`. Inspect CPU subtype too when the exact ABI matters.

**Fragment/recipe — inspect all slices; replace the input path:**

```python
import lief
fat = lief.MachO.parse('input.macho')
if fat is None:
    raise ValueError('Cannot parse Mach-O')
for binary in fat:
    print(binary.header.cpu_type, binary.header.cpu_subtype)
    section = binary.get_section('__TEXT', '__text')
    if section is not None:
        print(section.virtual_address, len(bytes(section.content)))
```

Use segment-plus-section lookup because section names can repeat across segments.
`binary.commands` exposes load commands; `binary.libraries` provides linked dylib
commands. `binary.add_library(name: str) -> LoadCommand | None` adds a dependency.
Path tokens such as `@rpath`, `@loader_path`, and `@executable_path` are interpreted
by dyld, not expanded by LIEF into a complete runtime environment.

Writing a slice with `binary.write(path)` does not preserve other architectures.
Use `fat.write(path)` for the container. Load-command growth, chained fixups,
exports, bindings, rebases, encryption, and code signing can complicate edits.
Rebuilding is not re-signing; macOS/iOS runtime validation requires the applicable
platform tooling. The [lab](#s12) validates an object file only, not a signed app.

Reference: [Mach-O Python API](https://lief.re/doc/stable/formats/macho/python.html).

<a id="s10"></a>
## [S10] Complete ELF lab: patch data, add metadata, replay

**Runnable example — Linux x86-64, `cc` on PATH, writable temporary storage.**
Creates and executes only its own small C program. This example is independent
of other snippets and includes its entire fixture. It checks the original bytes,
file mapping, patched bytes, metadata survival, and native output.

```python
from pathlib import Path
import os
import subprocess
import tempfile
import lief

source = r'''
#include <stdio.h>
char message[] = "before";
int main(void) { puts(message); return 0; }
'''
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    cfile, original, output = root/'main.c', root/'original', root/'patched'
    cfile.write_text(source)
    subprocess.run(['cc', '-O0', '-fno-pie', '-no-pie', str(cfile),
                    '-o', str(original)], check=True)
    def run(path):
        return subprocess.check_output([str(path)], timeout=5)
    assert run(original) == b'before\n'
    binary = lief.ELF.parse(original)
    assert binary is not None
    symbol = binary.get_symbol('message')
    assert symbol is not None and symbol.size == 7
    address = symbol.value
    old, new = b'before\0', b'after!\0'
    assert len(old) == len(new)
    mappings = [s for s in binary.segments
                if s.type == lief.ELF.Segment.TYPE.LOAD
                and s.virtual_address <= address
                and address + len(old) <= s.virtual_address + s.physical_size]
    assert len(mappings) == 1
    offset = binary.virtual_address_to_offset(address)
    assert not isinstance(offset, lief.lief_errors)
    assert original.read_bytes()[offset:offset + len(old)] == old
    assert bytes(binary.get_content_from_virtual_address(address, len(old))) == old
    binary.patch_address(address, list(new))
    metadata = lief.ELF.Section('.agent')
    metadata.content = list(b'LIEF reference fixture')
    assert binary.add(metadata, loaded=False) is not None
    config = lief.ELF.Builder.config_t()
    config.notes = True  # Preserve/rebuild notes when the section layout changes.
    binary.write(output, config)
    rebuilt = lief.ELF.parse(output)
    assert rebuilt is not None
    updated = rebuilt.get_symbol('message')
    assert updated is not None
    assert bytes(rebuilt.get_content_from_virtual_address(updated.value, 7)) == new
    section = rebuilt.get_section('.agent')
    assert section is not None
    assert bytes(section.content) == b'LIEF reference fixture'
    os.chmod(output, original.stat().st_mode & 0o777)
    assert run(output) == b'after!\n'
    assert run(original) == b'before\n'
print('ELF lab passed')
```

The result is a witness that this edit works for this compiled fixture and host.
It does not prove arbitrary ELF edits preserve behavior. The non-PIE compilation
makes the mapping simple; PIE and runtime patching require [S04](#s04).

<a id="s11"></a>
## [S11] Complete PE lab: synthetic image, section and import rebuild

**Runnable example — any host with LIEF and writable temporary storage.**
Constructs a minimal x86-64 PE fixture with `struct`; no download, cross compiler,
or Windows is required. It is a parser/builder fixture, **not a validated runnable
Windows application**. Its sparse headers can produce a diagnostic about RVA 0;
the assertions below check the specific structures under test.

```python
from pathlib import Path
import struct
import tempfile
import lief

raw = bytearray(0x400)
raw[:2] = b'MZ'
struct.pack_into('<I', raw, 0x3c, 0x80)
raw[0x80:0x84] = b'PE\0\0'
# AMD64, one section, 240-byte PE32+ optional header, executable/large-address flags.
struct.pack_into('<HHIIIHH', raw, 0x84, 0x8664, 1, 0, 0, 0, 0xf0, 0x22)
o = 0x98
struct.pack_into('<H', raw, o, 0x20b)
struct.pack_into('<I', raw, o + 16, 0x1000)       # Entrypoint RVA
struct.pack_into('<Q', raw, o + 24, 0x140000000)  # Image base
struct.pack_into('<II', raw, o + 32, 0x1000, 0x200)  # Section/file alignment
struct.pack_into('<II', raw, o + 56, 0x2000, 0x200)  # Image/header sizes
struct.pack_into('<H', raw, o + 68, 3)           # Console subsystem
struct.pack_into('<I', raw, o + 108, 16)         # Number of data directories
struct.pack_into('<8sIIIIIIHHI', raw, o + 0xf0,
                 b'.text', 1, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
raw[0x200] = 0xc3  # x86 RET, not executed in this lab.
binary = lief.PE.parse(bytes(raw))
assert binary is not None
kind = lief.Binary.VA_TYPES.RVA
assert binary.rva_to_offset(0x1000) == 0x200
assert bytes(binary.get_content_from_virtual_address(0x1000, 1, kind)) == b'\xc3'
section = lief.PE.Section('.agent')
section.content = list(b'LIEF')
section.characteristics = 0x40000040  # Readable initialized data
assert binary.add_section(section) is not None
library = binary.add_import('KERNEL32.dll')
library.add_entry('GetCurrentProcessId')
config = lief.PE.Builder.config_t()
config.imports = True
with tempfile.TemporaryDirectory() as directory:
    output = Path(directory)/'rebuilt.exe'
    binary.write(output, config)
    rebuilt = lief.PE.parse(output)
    assert rebuilt is not None
    metadata = rebuilt.get_section('.agent')
    assert metadata is not None and bytes(metadata.content) == b'LIEF'
    imports = {(lib.name.lower(), entry.name)
               for lib in rebuilt.imports for entry in lib.entries
               if not entry.is_ordinal}
    assert ('kernel32.dll', 'GetCurrentProcessId') in imports
    assert bytes(rebuilt.get_content_from_virtual_address(0x1000, 1, kind)) == b'\xc3'
print('PE lab passed')
```

This verifies metadata preservation through a rebuild. It does not verify Windows
loading, IAT references in existing code, API calling convention, signing, or
behavior on a real PE application.

<a id="s12"></a>
## [S12] Complete Mach-O lab: inspect a compiler-created object

**Runnable example — `clang` on PATH with an x86-64 Darwin target, temporary storage.**
No Apple SDK or linker is required because the source uses no headers and is only
compiled to an object. Nothing in this example executes Mach-O machine code.

```python
from pathlib import Path
import subprocess
import tempfile
import lief

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source, obj = root/'tiny.c', root/'tiny.o'
    source.write_text('int answer(void) { return 42; }\n')
    subprocess.run(['clang', '-target', 'x86_64-apple-darwin', '-c',
                    str(source), '-o', str(obj)], check=True)
    fat = lief.MachO.parse(obj)
    assert fat is not None and fat.size == 1
    binary = fat.get(lief.MachO.Header.CPU_TYPE.X86_64)
    assert binary is not None
    section = binary.get_section('__text')
    assert section is not None
    original_code = bytes(section.content)
    assert original_code
    assert '_answer' in {symbol.name for symbol in binary.symbols}
    again = lief.MachO.parse(obj.read_bytes())
    assert again is not None and again.size == 1
    rebuilt = again.at(0)
    assert rebuilt is not None
    text = rebuilt.get_section('__text')
    assert text is not None and bytes(text.content) == original_code
    assert '_answer' in {symbol.name for symbol in rebuilt.symbols}
print('Mach-O lab passed')
```

This exercises path/raw-byte parsing and the thin-input container API. This
compiler emits an unnamed enclosing segment for its object file, so the example
uses the unique section name instead of segment-plus-section lookup. A trial
`fat.write()` round-trip on this fixture produced an nlist parsing diagnostic and
lost the symbol table on reparse with the tested build. Consequently this lab does
not claim object-file writer support; do not use that transformation without
resolving the failure. Universal executables, dyld fixups, and platform signature
enforcement need separate tests.

<a id="s13"></a>
## [S13] Searchable troubleshooting

| Symptom | Likely cause | Next action |
| --- | --- | --- |
| `ModuleNotFoundError: lief` | Wrong interpreter/environment | Use the project's `.venv/bin/python`; inspect `lief.__file__`. |
| Missing enum or `TypeError` for an old builder | Release mismatch | Check installed `help()`; use nested enums and `Builder(binary, config)`. |
| Parse returns `None` | Unsupported, truncated, inaccessible, or wrong-format input | Confirm bytes, file size, format and diagnostics; do not report an empty binary. |
| Parse returns object but tables are missing | Disabled parsing, stripping, damage, or unsupported structure | Check config and raw format headers; record uncertainty. |
| Patch has no effect or wrong bytes | RVA/VA/file-offset confusion; BSS; out-of-range patch | Validate full file-backed range; read back bytes before and after rebuilding. |
| Integer patch overwrites neighboring data | Integer overload defaults to 8 bytes | Encode explicit width/endianness and pass a byte sequence. |
| Added PE imports/exports disappear | Builder switches default false | Enable `imports`/`exports` and inspect reparsed tables. |
| ELF note edits disappear | Notes rebuilding disabled | Review `ELF.Builder.config_t().notes` and validate the written note. |
| Rebuilt ELF cannot execute | Mode bits, interpreter/dependencies, layout, or relocation damage | Check permissions and loader metadata; replay only in the intended environment. |
| Output parses but crashes | Parse success is only a structural check | Validate instructions, ABI, relocations, loader rules, and behavior. |
| Mach-O loses architectures | Wrote a slice instead of container | Keep `FatBinary` and write the container; verify CPU list afterward. |
| A retained object/view becomes invalid | Parent lifetime or structural mutation | Keep parent alive; copy bytes; reacquire references after edits. |
| Signature verification fails after edit | Signed content changed | Verify actual flags and use the platform signing workflow if needed. |
| Memory/time exhausted or native crash | Input complexity or native-parser bug | Isolate parsing, impose external limits, preserve a reproducer and version. |

Do not suppress parser diagnostics while developing a transformation. When a
method reports `lief_errors`, keep the error value in the result record rather
than coercing it to an address or treating it as an empty successful result.

<a id="s14"></a>
## [S14] Advanced boundaries and integration

**Large-file inspection:** disable only structures irrelevant to a read-only
question, and record the configuration. Avoid copying every section when a small
range is sufficient. The parser does native work; no solver timeout is involved.
An externally killed parse is an incomplete operation, not evidence of absence.

**Memory dumps:** runtime relocations, unmapped section headers, zero-filled data,
and missing file-only regions make dumps different from original file images.
Specialized memory-aware options do not reconstruct arbitrary missing data.
Preserve mapping information and validate every claimed file conversion.

**Extended features:** `lief.__extended__` indicates the build flavor. Advanced
DWARF/PDB, disassembly/assembly, Objective-C, and dyld shared-cache facilities can
require LIEF Extended. This guide's tests use the standard build. Do not assume a
method seen on the online Extended pages is available in ReversEnv.

**Other formats:** COFF object files and Android DEX/OAT/VDEX/ART have dedicated
models. A successful parse does not imply a full symmetric writer exists or that
ELF/PE address rules apply. Their detailed APIs are outside this reference's
validated scope.

**angr / disassemblers:** use LIEF to inspect or rebuild the file, and reload the
output into the analysis tool. Cached CFGs, bytes, and symbols describe the old
image. angr's loaded addresses may be rebased; translate with the loader's actual
mapping rather than guessing from LIEF offsets. LIEF never establishes symbolic
reachability or equivalence. A successful native replay is a witness for tested
inputs; proof requires a separate model, assumptions, and verification argument.

**Result record:** include input/output hashes; Python and LIEF versions; target
format/CPU/endianness; parser/builder settings; slice identity; original address
domain and conversion; expected old/new bytes; rebuild/reparse outcomes; runtime
test outcome; diagnostics; and untested cases. Avoid claims that metadata
inspection establishes behavior in all loader environments.

<a id="s15"></a>
## [S15] Validation, reproduction, and primary sources

Validation environment: **CPython 3.12.14**, **LIEF 1.0.0-d05b3499b**, standard
build, **Linux x86-64**, checked **2026-09-25**. Repository pin: **lief==1.0.0**;
the tested base version matches. The suffix identifies the installed LIEF build.

Validation results are recorded below after execution. To reproduce, save each
**Runnable example** Python block separately and execute it with
`ReversEnv/.venv/bin/python`. They include all fixture source and create temporary
outputs. Do not run Fragment/recipe blocks as if they were complete programs.

- S01: six doctest checks passed.
- S02: ELF path/raw-bytes parsing, section content and file-offset assertions passed.
- S10: ELF compilation, symbol lookup, mapping, patch, non-loaded section insertion,
  rebuild with `config.notes=True`, reparse, and original/patched native output
  assertions passed. Default notes handling initially emitted note diagnostics
  after section insertion; explicitly rebuilding notes removed those diagnostics.
- S11: synthetic PE RVA conversion, section insertion, import rebuilding, and
  reparsed content/import assertions passed. Sparse-fixture RVA diagnostic noted.
- S12: Mach-O object compilation, architecture selection, symbol/content checks,
  and path/raw-byte parse assertions passed. A separate attempted object write
  failed symbol-table preservation; this limitation is documented in S12.
- All internal anchor links resolved and Markdown fences were balanced.

Not tested: recipe input placeholders, real Windows/macOS execution, multi-slice
Mach-O, signed binaries, resource/TLS/export modifications, ELF dependency or
RUNPATH changes, big-endian/32-bit targets, memory dumps, malformed-input robustness,
Extended features, and Android/COFF workflows. API inspection alone is not an
execution test. Compiler-generated fixture bytes can differ between toolchains.

### Re-run the executable blocks and document checks

**Fragment/recipe — maintenance harness, run from ReversEnv's root with its Python.**
This intentionally executes only this trusted document's Runnable example blocks.
It also executes the doctest block. It requires the compilers listed in the labs.

```python
from pathlib import Path
import doctest
import re
import subprocess
import sys
import tempfile

path = Path('doc/z3-doc.md')
text = path.read_text()
parts = re.split(r'^<a id="s\d+"></a>\s*$', text, flags=re.M)
count = 0
with tempfile.TemporaryDirectory() as directory:
    for part in parts:
        if not re.search(r'^\*\*Runnable example —', part, re.M):
            continue
        blocks = re.findall(r'^```python\n(.*?)^```\s*$', part, re.M | re.S)
        assert len(blocks) == 1
        script = Path(directory)/f'example_{count}.py'
        script.write_text(blocks[0])
        subprocess.run([sys.executable, str(script)], check=True, timeout=60)
        count += 1
assert count == 4
interactive = '\n\n'.join(re.findall(r'^```pycon\n(.*?)^```\s*$', text, re.M | re.S))
parser = doctest.DocTestParser()
runner = doctest.DocTestRunner()
runner.run(parser.get_doctest(interactive, {}, str(path), str(path), 0))
result = runner.summarize()
assert result.failed == 0 and result.attempted == 6
anchors = re.findall(r'<a id="([^"]+)"></a>', text)
assert len(anchors) == len(set(anchors))
assert set(re.findall(r'\]\(#([^)]*)\)', text)) <= set(anchors)
fence_open = False
for line in text.splitlines():
    if line.startswith('```'):
        if fence_open:
            assert line == '```'
        fence_open = not fence_open
assert not fence_open
print('4 runnable examples, 6 doctests, anchors and fences passed')
```

### Source/version record

Primary web references were consulted on 2026-09-25. The format API pages displayed
**1.0.0 (d05b3499b)**, matching the installed build. `stable` URLs can change; the
local binding signatures and executed examples establish the version-specific
contracts in this guide. Some upstream descriptive text still mentions historical
enum spellings; use the installed names documented here.

| Source | Use |
| --- | --- |
| Installed `lief` module, method docstrings, config objects | Directly checked signatures, types, enum names, feature flag, and defaults. |
| [Installation](https://lief.re/doc/stable/installation.html) | Distribution and platform installation guidance. |
| [Binary abstraction Python API](https://lief.re/doc/stable/api/binary_abstraction/python.html) | Common model, byte access and patching context. |
| [ELF Python API](https://lief.re/doc/stable/formats/elf/python.html) | ELF parser, structures and builder cross-checks. |
| [PE Python API](https://lief.re/doc/stable/formats/pe/python.html) | PE parser, imports, address conversion and builders. |
| [Mach-O Python API](https://lief.re/doc/stable/formats/macho/python.html) | FatBinary, slice selection and writing. |
| [Official repository](https://github.com/lief-project/LIEF) | Upstream implementation and release provenance. |

Explanations and lab fixtures in this document are original; no upstream tutorial
or generated API appendix is reproduced. This is a practical working reference,
not an exhaustive catalog of every LIEF format or native API.
