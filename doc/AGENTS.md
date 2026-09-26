# Reading the documentation

Choose by the task, then retrieve only the relevant sections:

| Task | Reference |
| --- | --- |
| Symbolically execute a binary, explore paths, recover CFGs or decompile; use angr/Claripy | [angr-doc.md](angr-doc.md) |
| Express and solve constraints directly with Z3; bitvectors, models, proofs | [z3-doc.md](z3-doc.md) |
| Inspect or modify ELF/PE/Mach-O structures, imports, sections, or file layouts | [lief-doc.md](lief-doc.md) |
| Decode machine-code bytes into instructions and operand metadata | [capstone-doc.md](capstone-doc.md) |
| Perform concrete encryption/decryption, hashing, key derivation, or signature checks | [pycryptodome-doc.md](pycryptodome-doc.md) |

1. Read **Summary — read this first**, then the **Task index** near the start.
2. Follow the selected `#sNN` anchor / `[SNN]` heading. Read that section and its
   explicit prerequisites, not the whole file. For an exact API or error, use
   `rg -n 'API_name|error text' doc/<reference>.md`, then read the matching section.
3. Check address domains, types, units, defaults, and failure behavior before
   adapting code. These are often more important than the shortest example.
4. **Runnable example** is complete under its stated requirements; **Doctest**
   includes expected results; **Fragment/recipe** needs context or replacement
   inputs. Check tested versions and validation limits against your environment.
5. Consult troubleshooting when blocked. Prefer the version-checked main guide
   over historical appendices; load an appendix only when the task requires it.

Combine references when needed: LIEF locates file bytes, Capstone decodes them,
and angr analyzes execution. Z3 solves an explicit model; PyCryptodome checks
concrete cryptographic operations. Parsing or decoding success alone does not
prove runtime behavior, and incomplete analysis is not a negative result.
