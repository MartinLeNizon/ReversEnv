# Structure

* `bin` is the directory for binaries. If you extract any executable or shellcode, put them there.
* `src` is where any code you write should go.
* `doc` is where documentation for specific tool is.

# Instructions

You shall use python: you are given useful requirements (see `requirements.txt`), which you can use using **uv**:
```
source  ./.venv/bin/activate
uv pip install -r ./requirements.txt
```

If you add additional packages, make sure they were bringing something useful. If so, add them to `requirements.txt`.

When writting new code (inside `src`), update `src/AGENTS.MD` accordingly (or create if not existing).

# Guardrails

Binaries you are analyzing may be malicious. Never run them. If emulation is needed, make sure it may not perform anything malicious on the system.

