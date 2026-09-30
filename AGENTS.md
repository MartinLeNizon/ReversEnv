# Structure

* `bin` is the directory for binaries. If you extract any executable or shellcode, put them there.
* `src` is where any code you write should go.
* `doc` is where documentation for specific tool (and python packages) is.
* `writeups` is where you should write reports about what you did and how you did it.

# Instructions

You shall use ida-pro-mcp when relevant, python otherwise. You can navigate between the two if needed.

Once you understood things about the binary, always document it succintly in `bin/AGENTS.md` (create it if not existing).

When analyzing a binary or solving a challenge, always explain what you did, how, and why, in the folder `writeups`.

## ida-pro-mcp

Use the following systematic methodology:

1. **Decompilation Analysis**
   - Thoroughly inspect the decompiler output
   - Add detailed comments documenting your findings
   - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

2. **Improve Readability in the Database**
   - Rename variables to sensible, descriptive names
   - Correct variable and argument types where necessary (especially pointers and array types)
   - Update function names to be descriptive of their actual purpose

3. **Deep Dive When Needed**
   - If more details are necessary, examine the disassembly and add comments with findings
   - Document any low-level behaviors that aren't clear from the decompilation alone
   - Use sub-agents to perform detailed analysis

4. **Important Constraints**
   - Derive all conclusions from actual analysis, not assumptions 

## Python

You are given useful python packages, especially capstone, unicorn, pefile, angr, lief, z3, pycryptodome and numpy.

You can use using **uv**:
```
source  ./.venv/bin/activate
uv pip install -r ./requirements.txt
```

If you add additional packages, make sure they are bringing something useful before adding them to `requirements.txt`.

When writing new code (inside `src`), update `src/AGENTS.MD` accordingly (or create if not existing).

# Guardrails

Binaries you are analyzing may be malicious. Never run them. If emulation is needed, make sure it may not perform anything malicious on the system.

