# angr documentation for AI-assisted analysis

## Summary — read this first

This is a self-contained working reference for **angr 9.3.4**, validated with
**Python 3.12 on Linux x86-64**. angr loads executable code, represents program
states, executes symbolic paths, and runs analyses such as CFG recovery and
decompilation. Use it by constructing a `Project`, creating an appropriate
`SimState`, expressing symbolic inputs with Claripy, and executing or analyzing
the model. The nine API chapters below explain signatures and results.

For most tasks, read the decision table and one relevant example; do not read
this entire file into working context. Each chapter has a stable `[SNN]` heading
and explicit anchor. Search for an API name, error, or `[SNN]` to retrieve a small
section. The complete example file set appears at the end, so this Markdown file
does not require the accompanying Sphinx site or repository to explain the labs.

**Essential rules:**

1. Load deliberately: `angr.Project(path, auto_load_libs=False)` is a useful
   starting point for small executable/function analyses. It still uses summaries
   for many imports; disabling library loading does not remove environmental effects.
2. Choose the initial state: `entry_state` for program entry, `full_init_state`
   when loader initialization is needed, `call_state` with an explicit prototype
   for a function harness, and `blank_state` only when you supply the missing context.
3. Use loaded addresses (`symbol.rebased_addr`) and the correct architecture/ABI.
   File offsets, linked addresses, relocated addresses, and instruction addresses
   are not interchangeable. PIE relocation is a common source of wrong targets.
4. Claripy widths are **bits**; memory sizes are **bytes**. Keep widths explicit.
   Default bitvector comparisons are unsigned. `>>` is arithmetic; `LShR` is logical.
   Match memory endianness when storing or loading native integers.
5. Constrain inputs in the state, then search with bounded execution. Check
   `found`, `active`, `deadended`, `unconstrained`, `unsat`, and `errored` as relevant.
   No result within a bound is not proof of unreachability.
6. Extract a witness from the **successful state's solver**, with the entire
   correlated input expression. `eval` gives one possible value; `eval_one`
   requires uniqueness. Replay the witness on the actual target when available.
7. Prefer narrow, explicit hooks. Model arguments, returns, memory changes, and
   error cases. A stub or zero-fill option changes the analysis assumptions.
8. Do not use symbolic expressions as Python conditions. Build `claripy.If`,
   `And`, `Or`, or issue an explicit solver query. A timeout is not UNSAT.
9. Static recovery and decompilation can be incomplete. Inspect result objects,
   missing nodes, and analysis errors; pseudocode is not the original source.
10. Keep the version and assumptions in every result report. Main-guide runnable
    examples are validated; marked fragments and original upstream appendices
    are not a promise of execution on an arbitrary target.

<a id="task-index"></a>

## Task index — retrieve only what you need

| Task or question | Start here | Then consult |
| --- | --- | --- |
| Install or verify angr | [S01 Installation](#s01) | [S02 compiler-free quick start](#s02) |
| Understand the object model | [S03 Architecture](#s03) | [S05 States](#s05) |
| Load ELF/PE/blob, resolve symbols or PIE | [S04 Loading](#s04) | [S15 Project API](#s15) |
| Construct program entry or function state | [S05 States](#s05) | [S16 Factory API](#s16), [S41 function example](#s41) |
| Solve expressions or extract bytes | [S06 Constraints](#s06) | [S18 Solver API](#s18) |
| Read/write memory or pass a pointer | [S07 Memory](#s07) | [S42 pointer-buffer example](#s42) |
| Solve stdin, argv, or file input | [S38 stdin](#s38), [S39 argv](#s39), [S40 file](#s40) | [S08 Environment](#s08), [S20 File API](#s20) |
| Explore toward a target or control state explosion | [S09 Exploration](#s09) | [S19 Manager API](#s19), [S25 Performance](#s25) |
| Hook an imported or local function | [S10 Hooks](#s10) | [S21 Hook API](#s21), [S43 example](#s43) |
| Instrument memory/register events | [S11 Inspection](#s11) | [S44 example](#s44) |
| Recover CFG or decompile a function | [S12 Analyses](#s12) | [S22 Analysis API](#s22), [S47 example](#s47) |
| Trace data dependencies or identify functions | [S27 Data flow](#s27) | [Official appendices](#official-index) |
| Understand Claripy internals or floating point | [S13 Solver architecture](#s13) | [S06 semantics](#s06) |
| Access DWARF variables and scope | [S14 Debug variables](#s14) | [S29 platform limits](#s29) |
| Extend a state, technique, analysis or OS | [S30 Extensions](#s30), [S31 Environment models](#s31) | [S45 plugin example](#s45) |
| Unexpected symbolic values, crashes, wrong answers | [S26 Troubleshooting](#s26) | [S23 Exceptions](#s23), [S24 workflow](#s24) |
| Options, common operations, terminology | [S33 Options](#s33), [S34 Recipes](#s34), [S35 Glossary](#s35) | [Official tables](#official-index) |
| Port an old script | [S36 Migration](#s36) | Preserved full migration notes in the appendix |
| Build the examples without the repository | [Recreate the example files](#recreate-examples) | [Validation and limitations](#scope) |

### Minimal analysis plan and result record

Before writing a script, record: target identity and format; architecture/ABI;
loaded base; entry or function boundary; symbolic bytes/registers and widths;
initial memory and environment; hooks; success/failure predicates; exploration
and solver budgets; and what will count as a validated result.

After running it, report: a witness or observed analysis output; native replay
outcome where applicable; remaining stashes and errors; the stopping condition;
and modeling assumptions. Never turn a search timeout, unsupported syscall,
missing CFG node, or approximate result into an unconditional proof.

### Readiness labels

- **Runnable example:** complete source appears below; native examples use the
  supplied C target and shared helper. Run from the recreated directory layout.
- **Doctest:** `>>>` and `...` show interactive input and expected output. Remove
  prompts before saving it as a script, or execute using Python doctest.
- **Fragment/recipe:** needs the surrounding project, target-specific address,
  class, or binary described in the prose. Replace placeholders deliberately.
- **Official appendix:** preserved release documentation, including historical
  guidance. Consult the version-checked main chapters before adapting old APIs.

<a id="scope"></a>

### Version, validation, and coverage

This file combines the independently authored technical guide, the full example
sources, and detailed narrative chapters from the official v9.3.4 documentation.
The main guide has 107 passing doctest checks and 16 behavioral tests. The official
appendix's examples have not all been executed here. Optional Unicorn, Java/JNI,
external tracing and live-process integrations are not validated by those tests.

The online `latest` documentation can differ from 9.3.4. External links are
additional references, not dependencies required to read this file. This file
contains the principal working API contracts, not every generated private member
in angr or every separately hosted ecosystem API. The Sphinx project also has a
broader locally generated API supplement. Historical upstream statements and TODOs
are retained and clearly marked; they do not override the tested main guidance.

## Main-reference contents

- [S01 — Installation](#s01)
- [S02 — Quick start](#s02)
- [S03 — Architecture and object model](#s03)
- [S04 — Binary loading and addresses](#s04)
- [S05 — Program states](#s05)
- [S06 — Symbolic expressions and constraint solving](#s06)
- [S07 — Memory and symbolic addressing](#s07)
- [S08 — Files and process environment](#s08)
- [S09 — Symbolic execution and state exploration](#s09)
- [S10 — Hooks and SimProcedures](#s10)
- [S11 — Execution inspection](#s11)
- [S12 — Control-flow analysis and decompilation](#s12)
- [S13 — Solver architecture and expression inspection](#s13)
- [S14 — Debug information and variable visibility](#s14)
- [S15 — Projects and binary loading](#s15)
- [S16 — State and execution factories](#s16)
- [S17 — States, registers, and memory](#s17)
- [S18 — Expressions and solver queries](#s18)
- [S19 — Simulation managers](#s19)
- [S20 — Files and input storage](#s20)
- [S21 — Hooks, procedures, and inspection](#s21)
- [S22 — Analysis interfaces](#s22)
- [S23 — Exceptions and execution failures](#s23)
- [S24 — A reliable analysis workflow](#s24)
- [S25 — Performance and search limits](#s25)
- [S26 — Troubleshooting](#s26)
- [S27 — Data flow, dependencies, and slicing](#s27)
- [S28 — Intermediate representations and execution engines](#s28)
- [S29 — Firmware, other platforms, and specialized workflows](#s29)
- [S30 — Extension interfaces](#s30)
- [S31 — Library, syscall, and operating-system models](#s31)
- [S32 — Developing angr and reporting problems](#s32)
- [S33 — Options and search controls](#s33)
- [S34 — Common operations](#s34)
- [S35 — Glossary](#s35)
- [S36 — Version migration and historical changes](#s36)
- [S37 — Reproduce and maintain an analysis](#s37)
- [S38 — Find an input and prove it works](#s38)
- [S39 — Solve a command-line argument](#s39)
- [S40 — Solve the contents of a file](#s40)
- [S41 — Solve a function return value](#s41)
- [S42 — Pass a symbolic buffer by pointer](#s42)
- [S43 — Replace a function with an explicit model](#s43)
- [S44 — Observe execution with breakpoints](#s44)
- [S45 — Preserve custom data through forks and merges](#s45)
- [S46 — Bound a loop and explain the boundary](#s46)
- [S47 — Recover functions and decompile one](#s47)

<a id="official-index"></a>

## Detailed official appendix index

- [S48 — Solver Engine](#s48)
- [S49 — Symbolic memory addressing](#s49)
- [S50 — Debug variable resolution](#s50)
- [S51 — Working with File System, Sockets, and Pipes](#s51)
- [S52 — Gotchas when using angr](#s52)
- [S53 — Intermediate Representation](#s53)
- [S54 — Java Support](#s54)
- [S55 — What’s Up With Mixins, Anyway?](#s55)
- [S56 — Understanding the Execution Pipeline](#s56)
- [S57 — Optimization considerations](#s57)
- [S58 — Working with Data and Conventions](#s58)
- [S59 — Backward Slicing](#s59)
- [S60 — Control-flow Graph Recovery (CFG)](#s60)
- [S61 — angr Decompiler](#s61)
- [S62 — Identifier](#s62)
- [S63 — Changelog](#s63)
- [S64 — Cheatsheet](#s64)
- [S65 — Migrating to angr 7](#s65)
- [S66 — Migrating to angr 8](#s66)
- [S67 — Migrating to angr 9.1](#s67)
- [S68 — CTF Challenge Examples](#s68)
- [S69 — List of Claripy Operations](#s69)
- [S70 — List of State Options](#s70)
- [S71 — Analyses](#s71)
- [S72 — A final word of advice](#s72)
- [S73 — Loading a Binary](#s73)
- [S74 — Simulation Managers](#s74)
- [S75 — Simulation  and Instrumentation](#s75)
- [S76 — Symbolic Expressions and Constraint Solving](#s76)
- [S77 — Machine State - memory, registers, and so on](#s77)
- [S78 — Symbolic Execution](#s78)
- [S79 — Core Concepts](#s79)
- [S80 — angr examples](#s80)
- [S81 — Writing Analyses](#s81)
- [S82 — Extending the Environment Model](#s82)
- [S83 — Hooks and SimProcedures](#s83)
- [S84 — State Plugins](#s84)
- [S85 — Frequently Asked Questions](#s85)
- [S86 — Reporting Bugs](#s86)
- [S87 — Help Wanted](#s87)
- [S88 — Installing angr](#s88)
- [S89 — Introduction](#s89)

---

<a id="s01"></a>

<a id="s01--installation"></a>

## [S01] Installation

The examples and API descriptions in this documentation target angr 9.3.4. Use a separate Python environment to keep its dependencies isolated from other projects. The validated environment is CPython 3.12 on Linux x86-64.

<a id="s01--install-angr"></a>

### Install angr

```console
$ python3.12 -m venv .venv
$ .venv/bin/python -m pip install angr==9.3.4
```

angr installs compatible versions of its associated libraries, including CLE, Claripy, PyVEX, and archinfo. Avoid upgrading those packages independently of angr without checking their compatibility.

<a id="s01--verify-the-installation"></a>

### Verify the installation

```console
$ .venv/bin/python -c "import angr, claripy; print(angr.__version__, claripy.__version__)"
9.3.4 9.3.4
```

Using `python -m pip` selects the package installer associated with that interpreter. If an import fails, check the interpreter path and environment before changing package versions.

Continue with [Quick start](#s02) for a self-contained execution example, or [Binary loading and addresses](#s04) to load an executable file.

<a id="s01--optional-components"></a>

### Optional components

Unicorn acceleration, Java analysis, live-process integrations, and the angr-management GUI have additional dependencies. They are not required for ordinary VEX symbolic execution or the quick start. See [Performance and search limits](#s25) and [Firmware, other platforms, and specialized workflows](#s29) before using those workflows.

An optional Unicorn loading diagnostic can appear when that backend is absent. This does not by itself prevent ordinary symbolic execution. Verify the specific execution engine needed by the application.

<a id="s01--repository-examples"></a>

### Repository examples

For all examples in this documentation repository, install the pinned `requirements-lock.txt` and run `make examples`. The native examples use Linux interfaces and the System V AMD64 ABI; the build helper requires a Linux x86-64 host and a C compiler. Other angr platforms are not validated by this repository’s native test suite.

Instructions for building and testing the documentation itself are in [Building the documentation](#scope).

<a id="s01--upstream-sources"></a>

### Upstream sources

- [Release metadata](https://github.com/angr/angr/blob/v9.3.4/pyproject.toml).

- [Installation guide](https://github.com/angr/angr/blob/v9.3.4/docs/getting-started/installing.rst).


---

<a id="s02"></a>

<a id="s02--quick-start"></a>

## [S02] Quick start

This example executes a single AMD64 instruction using a symbolic register. It requires angr but no compiler, external executable, or shared libraries.

<a id="s02--load-code"></a>

### Load code

`angr.load_shellcode` creates a [`Project`](#s15--angr.Project) from raw instruction bytes. The bytes below encode `add eax, 1`. A normal executable is loaded with [`angr.Project`](#s15--angr.Project) instead; see [Binary loading and addresses](#s04).

```python
>>> import angr, claripy
>>> project = angr.load_shellcode(b'\x83\xc0\x01', arch='AMD64')
>>> state = project.factory.blank_state()
```

<a id="s02--set-the-input-and-execute"></a>

### Set the input and execute

A [`SimState`](#s17--angr.SimState) contains registers, memory, and constraints. The register `eax` is 32 bits wide, so the input expression is 32 bits. Initialize the full 64-bit `rax` register with a zero-extended input to keep its upper half defined; the instruction operates on the lower 32 bits.

```python
>>> x = claripy.BVS('input', 32)
>>> state.regs.rax = x.zero_extend(32)
>>> successors = project.factory.successors(state, num_inst=1)
>>> len(successors.flat_successors)
1
>>> result = successors.flat_successors[0]
```

`num_inst=1` stops after the one supplied instruction. A [`SimulationManager`](#s19--angr.SimulationManager) is more convenient for executing multiple states or searching for a location in a larger program.

<a id="s02--constrain-and-evaluate-the-result"></a>

### Constrain and evaluate the result

Add a condition to the result state’s solver, then evaluate the original input expression under that condition:

```python
>>> result.solver.add(result.regs.eax == 42)
>>> result.solver.eval_one(x)
41
```

The solver determines that an input of 41 produces 42 after the addition. `eval_one` requires a unique value. Use `eval` for one possible value or `eval_upto` for a bounded list of values when the input is not unique.

<a id="s02--next-topics"></a>

### Next topics

- [Program states](#s05): state construction and initialized context.

- [Symbolic expressions and constraint solving](#s06): expression widths, constraints, and evaluation.

- [Symbolic execution and state exploration](#s09): search and state classification.

- [Find an input and prove it works](#s38): a complete executable-input example.


---

<a id="s03"></a>

<a id="s03--architecture-and-object-model"></a>

## [S03] Architecture and object model

Imagine a program reading one byte `x` and checking `x == 65`. A normal run chooses one byte and takes one branch. Symbolic execution starts with a name for the byte and can keep both possibilities: one state with `x == 65` and another with `x != 65`. Each state remembers the assumptions that made its path possible.

The solver answers questions about those assumptions. On the first state, asking for `x` returns 65. On the second, it returns some other allowed byte. Neither answer requires trying all 256 inputs by running the program repeatedly.

<a id="s03--principal-objects"></a>

### Principal objects

| Object | What it represents | Typical question |
|----|----|----|
| `Project` | Loaded code, architecture, hooks, and access to analyses. | Where is the function I want? |
| `SimState` | One possible machine configuration, including symbolic values. | What is in this register on this path? |
| Claripy AST | An immutable expression over fixed-width values or other solver types. | How does this output depend on the input? |
| State solver | Constraints describing feasible assignments for a state. | Can this expression equal 1 here? |
| `SimulationManager` | Groups of states plus the rules for advancing and classifying them. | Which paths have reached success? |

The loader, CLE, maps executable files into the project’s address space. A lifter such as PyVEX translates machine instructions into an intermediate representation. An execution engine applies those instructions to a state. Claripy constructs and solves expressions. Analyses can use these facilities without being a normal symbolic-execution search; CFG recovery is one example.

<a id="s03--execution-model"></a>

### Execution model

```text
binary --> loader --> Project
                         |
                         +--> initial SimState (inputs + environment)
                                   |
                                   v
                           execution step
                            /           \
                    state: x == 65   state: x != 65
                            |             |
                         found          avoid
                            |
                      solver witness --> native replay
```

A fork does not mean the original input changed. It means the analysis now tracks different restrictions on the same unknown input. State memory can be shared internally until changed, so a fork is not necessarily a full physical copy of every byte.

<a id="s03--results-and-validation"></a>

### Results and validation

**Reachability in the model:** a found state shows a path allowed by the initial state, summaries, memory policy, and search strategy.

**A concrete witness:** evaluating the original input expression gives bytes or integers that satisfy that found state’s constraints.

**A reproduced behavior:** running those values against the native target confirms the observed behavior for that concrete execution and environment.

These are separate steps. A summary could return success without modeling a required side effect. A symbolic pointer might have been restricted during concretization. A function-level state may assume globals that no real caller can create. Native replay helps reveal these mismatches.

<a id="s03--analysis-limits"></a>

### Analysis limits

A failed search is not a proof of safety. You may have exhausted a step budget, missed an input channel, avoided a necessary address, or encountered unsupported code. Even a completed search concerns the modeled initial states, not every possible environment. Conversely, a static CFG edge is only a recovered control-flow possibility; it is not a solver-confirmed feasible path.

The most productive question is specific: “Can this function return 1 for a four-byte input under these assumptions?” That question has a defined input, observation point, and result. “Analyze this binary completely” does not.

<a id="s03--source-trail"></a>

### Source trail

- [Core symbolic execution](https://github.com/angr/angr/blob/v9.3.4/docs/core-concepts/symbolic.rst).

- [State implementation](https://github.com/angr/angr/blob/v9.3.4/angr/sim_state.py).

- [Project implementation](https://github.com/angr/angr/blob/v9.3.4/angr/project.py).


---

<a id="s04"></a>

<a id="s04--binary-loading-and-addresses"></a>

## [S04] Binary loading and addresses

The loader creates a virtual address space from an executable and its associated objects. A project’s address is a guest address, not a Python pointer and not necessarily the address shown in a separate disassembler or live process.

<a id="s04--three-useful-address-forms"></a>

### Three useful address forms

| Form | Meaning |
|----|----|
| Relative address / RVA | Offset from an object’s base. |
| Linked virtual address | Address using the image’s linked base. |
| Rebased virtual address | Address using the base CLE selected for this project. |

For a known relative address `rva`, use `obj.mapped_base + rva`. For a linked virtual address, use `linked_address - obj.linked_base + obj.mapped_base`. A file offset is a fourth concept: map it through the containing segment or section, because file layout and virtual memory layout need not be identical.

<a id="s04--inspecting-loaded-objects"></a>

### Inspecting loaded objects

Adaptation recipe, after building the target:

```python
import angr
p = angr.Project('build/targets-pie', auto_load_libs=False)
obj = p.loader.main_object
print(p.arch.name, hex(p.entry))
print(hex(obj.linked_base), hex(obj.mapped_base))
print(p.loader.all_objects)
symbol = obj.get_symbol('check')
if symbol is None:
    raise ValueError('No check symbol in this binary')
print(hex(symbol.rebased_addr))
print(p.factory.block(symbol.rebased_addr).capstone)
```

The labs test the same symbol-based approach on both binary variants. For a stripped binary, use independently recovered function addresses, verified patterns, or a CFG inspection. A copied address from a tutorial is meaningful only for the exact binary and address mapping used in that tutorial.

<a id="s04--libraries-and-unresolved-functions"></a>

### Libraries and unresolved functions

These examples set `auto_load_libs=False` explicitly. In CLE 9.3.4 this is also the default, but older material describes other defaults. Explicit arguments make scripts readable across that history.

Disabling automatic library loading does not disable library-call modeling. angr installs available SimProcedures for recognized functions. Calls lacking an appropriate implementation may receive generic unconstrained-return stubs. Such a stub cannot stand in for every side effect of a real function.

Loading a real shared library does not necessarily mean every function in it will execute machine code: Project may still install SimProcedures. Inspect `p.is_hooked(address)` and `p.hooked_by(address)` when the distinction matters. Configure library loading and summary replacement as separate choices.

<a id="s04--import-symbols-versus-definitions"></a>

### Import symbols versus definitions

An import symbol may describe a request for a symbol rather than a useful function body address. Inspect its resolution and owning object. For a lab function defined in the main binary, `main_object.get_symbol` avoids accidentally selecting a same-named function elsewhere. For a library hook, `hook_symbol` handles loader symbol resolution for you.

<a id="s04--raw-images"></a>

### Raw images

A blob has no executable header to supply architecture, entry point, or mapping. You must provide them. See [Firmware, other platforms, and specialized workflows](#s29) for a recipe and its limits. Successfully loading bytes does not mean you have modeled a device.

CLE source for this release: [loader.py](https://github.com/angr/cle/blob/v9.3.4/cle/loader.py) and [symbol.py](https://github.com/angr/cle/blob/v9.3.4/cle/backends/symbol.py).

See also

[Projects and binary loading](#s15) for interface signatures and return values.

<a id="s04--source-trail"></a>

### Source trail

- [Project construction and hook installation](https://github.com/angr/angr/blob/v9.3.4/angr/project.py).

- [Official loading chapter](https://github.com/angr/angr/blob/v9.3.4/docs/core-concepts/loading.rst).


---

<a id="s05"></a>

<a id="s05--program-states"></a>

## [S05] Program states

A state combines registers, memory, constraints, environment, execution history, and plugins. Each state represents the possibilities still allowed along one modeled execution history; after merging it may represent several histories.

<a id="s05--state-constructors"></a>

### State constructors

| Factory | Appropriate use | What you still owe the model |
|----|----|----|
| `entry_state` | Begin at the executable’s entry point with process arguments. | Input content and relevant environment; initializers may matter. |
| `full_init_state` | Run modeled initialization before entry. | Environment and summaries still need validation. |
| `call_state` | Begin at a function as if called with arguments. | Prototype, valid pointed-to memory, globals, and caller invariants. |
| `blank_state` | Assemble a custom machine state at a selected address. | Every register and memory dependency relevant to the execution. |

`entry` does not mean `main`. In a typical ELF process, startup code runs before main. Setting `addr=main_address` on a blank state does not create main’s arguments or a valid return context.

<a id="s05--reading-state-information"></a>

### Reading state information

`state.regs` exposes architecture register names. `state.memory` is the raw byte-addressed memory interface; `state.mem` is the typed view. `state.solver` exposes constraints and evaluation. `state.posix` and `state.fs` hold environment models. `state.history` records how execution arrived here; `state.callstack` tracks call context. These are different views and plugins attached to a common state.

<a id="s05--uninitialized-registers-and-memory"></a>

### Uninitialized registers and memory

A warning about unspecified registers or memory means the engine needed a value you did not establish. Depending on options, angr introduces symbolic data or fills a value. A symbolic value permits many assignments and can create paths that no valid caller can produce.

Decide whether the value is an intended unknown input, a missing setup value, or irrelevant bookkeeping. Initialize it from the real calling context when it matters. Zero-filling everything can make a run quiet while changing the question. Symbol-fill options suppress warnings without creating a realistic caller. See [Options and search controls](#s33).

<a id="s05--copying-states"></a>

### Copying states

`child = state.copy()` creates a state you can constrain independently. Claripy ASTs are immutable; many internal structures use sharing to avoid copying every byte eagerly. Do not infer from that optimization that arbitrary Python containers you attach are copied deeply.

```python
>>> import angr, claripy
>>> p = angr.load_shellcode(b'\x90', arch='AMD64')
>>> original = p.factory.blank_state()
>>> value = claripy.BVS('copy_value', 8)
>>> child = original.copy()
>>> child.solver.add(value == 7)
>>> child.solver.eval_one(value)
7
>>> original.solver.satisfiable(extra_constraints=(value == 8,))
True
```

<a id="s05--merging-states"></a>

### Merging states

`merged, conditions, changed = left.merge(right)` can combine compatible states. Different values become conditional expressions associated with merge conditions. Merging is not just dropping duplicate program counters, and not all plugins can merge every kind of state. States at the same address can have different stacks, files, or constraints that make a merge inappropriate.

Merging reduces the number of states at the cost of more complex expressions. Evaluate whether that tradeoff helps your target. The [Preserve custom data through forks and merges](#s45) lab demonstrates how custom state data participates in it.

See also

[States, registers, and memory](#s17) for interface signatures and return values.

<a id="s05--source-trail"></a>

### Source trail

- [State construction and merge](https://github.com/angr/angr/blob/v9.3.4/angr/sim_state.py).

- [Factories](https://github.com/angr/angr/blob/v9.3.4/angr/factory.py).

- [State plugins](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/plugin.py).


---

<a id="s06"></a>

<a id="s06--symbolic-expressions-and-constraint-solving"></a>

## [S06] Symbolic expressions and constraint solving

A symbolic expression describes a value. A constraint restricts which values are allowed. Evaluation chooses an allowed concrete value; it does not replace the expression or permanently constrain it to the chosen answer.

<a id="s06--bitvector-width-and-arithmetic"></a>

### Bitvector width and arithmetic

Machine arithmetic wraps. Eight-bit 255 plus one becomes zero. The same bit pattern can represent unsigned 255 or signed -1; signedness belongs to the operation interpreting the bits, not to an intrinsic “signed variable” tag.

```python
>>> import claripy
>>> byte = claripy.BVV(255, 8)
>>> claripy.is_true(byte + 1 == 0)
True
>>> claripy.is_true(byte < 0)
False
>>> claripy.is_true(byte.SLT(0))
True
>>> claripy.is_true(claripy.LShR(byte, 1) == 127)
True
>>> claripy.is_true((byte >> 1) == 255)
True
```

Normal bitvector comparisons are unsigned in Claripy. Use `SLT`, `SLE`, `SGT`, or `SGE` for signed comparisons. `>>` is arithmetic right shift; `LShR` is logical right shift. Check the operation rather than relying on Python integer intuition. Expressions of different widths generally need an explicit extension or extraction before arithmetic.

```python
>>> small = claripy.BVV(0xff, 8)
>>> claripy.is_true(small.zero_extend(8) == 255)
True
>>> claripy.is_true(small.sign_extend(8) == 65535)
True
>>> word = claripy.BVV(0x43415421, 32)
>>> claripy.is_true(word.get_byte(0) == ord('C'))
True
>>> claripy.is_true(word[7:0] == ord('!'))
True
```

Bit slices have inclusive endpoints, counted from the least-significant bit. `get_byte(0)` starts at the most-significant byte. Neither operation by itself consults the target architecture’s memory byte order.

<a id="s06--constraint-queries"></a>

### Constraint queries

```python
>>> x = claripy.BVS('lesson_x', 8)
>>> solver = claripy.Solver()
>>> _ = solver.add([x >= 3, x <= 5])
>>> sorted(solver.eval(x, 10))
[3, 4, 5]
>>> solver.satisfiable(extra_constraints=(x == 9,))
False
>>> sorted(solver.eval(x, 10))
[3, 4, 5]
```

Standalone `claripy.Solver` accepts a collection in `add` and a requested count in `eval`. angr’s `state.solver` is a state plugin with convenience methods: `add(*constraints)`, `eval(expr)`, `eval_one(expr)`, and `eval_upto(expr, count)`. Do not mix their call signatures.

| State solver operation | Question answered |
|----|----|
| `satisfiable(extra_constraints=(condition,))` | Is there an assignment satisfying this path and this extra condition? |
| `eval(expr)` | Give one possible value; uniqueness is not asserted. |
| `eval_one(expr)` | Give the unique value, or raise if that requirement fails. |
| `eval_upto(expr, n)` | Give up to n distinct values; n results can still be incomplete. |
| `min(expr)` / `max(expr)` | Find the smallest/largest possible value under the chosen semantics. |
| `eval(expr, cast_to=bytes)` | Convert a bitvector witness to its byte sequence. |

<a id="s06--possibility-necessity-and-simplification"></a>

### Possibility, necessity, and simplification

To ask whether a condition is possible, check satisfiability with that condition. To ask whether it must hold, first confirm the state is satisfiable, then check that its negation is unsatisfiable. This avoids drawing a misleading “must” conclusion from an inconsistent state.

`claripy.is_true` and `claripy.is_false` recognize definite Boolean results without running a general path implication proof. A false result from `is_true` does not mean the expression is impossible. For proof obligations, write the satisfiability query explicitly.

Never put a symbolic Boolean directly in Python `if`, `and`, or `or`. Use `claripy.And`, `claripy.Or`, and `claripy.If` to construct formulas. Use a solver query when the Python program needs an actual Boolean decision.

<a id="s06--correlated-values"></a>

### Correlated values

If two input expressions depend on each other, request a joint assignment. Independent enumeration of their value sets loses the relationship. A single concatenated byte vector is convenient for a complete input; standalone Claripy also provides `batch_eval` for tuples of expressions.

```python
"""Bit widths, signedness, uniqueness, and consistent tuple evaluation."""
import claripy

def solve():
    x, y = claripy.BVS("x", 8), claripy.BVS("y", 8)
    solver = claripy.Solver()
    solver.add([x >= 1, x <= 9, y >= 1, y <= 9, x + y == 10])
    pairs = solver.batch_eval([x, y], 20)
    assert len(pairs) == 9 and all(a + b == 10 for a, b in pairs)
    assert claripy.is_true(claripy.BVV(255, 8) + 1 == 0)
    assert claripy.is_true(claripy.BVV(255, 8).SLT(0))
    assert not claripy.is_true(claripy.BVV(255, 8) < 0)
    return sorted(pairs)

if __name__ == "__main__":
    print(solve())
```

The test enumerates exactly nine pairs satisfying `x + y == 10` with both values between one and nine. It checks pairs, not the Cartesian product of independent value lists. Do not depend on incidental solver model reuse across separate queries when a joint query expresses the requirement directly.

<a id="s06--floating-point-and-harder-constraints"></a>

### Floating point and harder constraints

Claripy supports IEEE floating-point sorts and operations. A raw bit-pattern reinterpretation is different from a numeric conversion; rounding, NaN, signed zero, and infinities can matter. These facilities are not exercised by the native labs. Check `claripy/ast/fp.py` and the exact operation you need before translating a C floating-point expression into a custom summary.

Symbolic division, large multiplication, variable shifts, and long strings can make solving expensive. A timeout is an unknown result, not unsatisfiability. When modeling division yourself, account for zero-divisor behavior explicitly instead of assuming the solver automatically models a machine exception.

See also

[Expressions and solver queries](#s18) for interface signatures and return values.

<a id="s06--source-trail"></a>

### Source trail

- [State solver convenience methods](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/solver.py).

- [Solver guide](https://github.com/angr/angr/blob/v9.3.4/docs/core-concepts/solver.rst).

For frontend/backend architecture and expression inspection, see [Solver architecture and expression inspection](#s13).


---

<a id="s07"></a>

<a id="s07--memory-and-symbolic-addressing"></a>

## [S07] Memory and symbolic addressing

There are three separate questions: where the bytes live, what the bytes mean, and how many possible locations a pointer can name. Treat them separately to avoid hard-to-explain solver results.

<a id="s07--bytes-versus-integers"></a>

### Bytes versus integers

Raw memory operations use sizes in bytes. Claripy bitvector widths use bits. A 32-bit expression occupies four bytes, not 32. Explicit endness makes integer loads and stores match the target architecture.

```python
>>> import angr, claripy
>>> p = angr.load_shellcode(b'\x90', arch='AMD64')
>>> state = p.factory.blank_state()
>>> ptr = state.heap.allocate(8)
>>> state.memory.store(ptr, claripy.BVV(0x41424344, 32), endness=p.arch.memory_endness)
>>> state.solver.eval(state.memory.load(ptr, 4), cast_to=bytes)
b'DCBA'
>>> value = state.memory.load(ptr, 4, endness=p.arch.memory_endness)
>>> state.solver.eval_one(value) == 0x41424344
True
>>> state.memory.store(ptr, b'ABCD')
>>> state.solver.eval(state.memory.load(ptr, 4), cast_to=bytes)
b'ABCD'
```

On AMD64, an integer is little-endian in memory. A byte string has its sequence order already defined. The default raw bitvector interpretation is useful for extracting byte strings; it should not be mistaken for a native integer read.

<a id="s07--typed-views"></a>

### Typed views

`state.mem[ptr].uint32_t.resolved` reads a typed value as an expression. Typed views use target type/layout information and are convenient for integers, arrays, and structures. A `.concrete` access asks for a concrete reading; when uncertainty matters, keep `.resolved` and query the solver explicitly. Architecture-dependent types such as `long` need special care across ABIs.

<a id="s07--the-contents-can-be-symbolic-while-the-address-is-concrete"></a>

### The contents can be symbolic while the address is concrete

Most input-buffer analyses need a concrete allocated pointer containing symbolic bytes, as in [Pass a symbolic buffer by pointer](#s42). An unconstrained symbolic pointer can name a vast address space, much of it unrelated to a valid object. If the real pointer selects one of several objects, initialize those objects and constrain the pointer to those actual addresses.

<a id="s07--how-symbolic-addresses-become-accesses"></a>

### How symbolic addresses become accesses

The memory implementation uses read and write concretization strategies. They attempt to resolve a symbolic address to manageable concrete possibilities. Some policies enumerate a bounded range; others select a value, restricting the explored behaviors. Reads and writes need not have identical defaults.

Adaptation recipe for a deliberately small symbolic-write domain:

```python
import angr
state.memory.write_strategies.insert(
    0, angr.concretization_strategies.SimConcretizationStrategyRange(16)
)
```

This inserts a strategy ahead of the existing ones. It does not guarantee that all possible writes are represented: if the strategy fails, a later fallback can still restrict the address. First constrain the intended object bounds, then use an `address_concretization` inspection callback to observe actual chosen addresses and added constraints. The recipe is source-checked but not part of the native lab suite.

<a id="s07--logical-bounds-and-mapped-memory-differ"></a>

### Logical bounds and mapped memory differ

A pointer can remain inside a mapped page while leaving the logical four-byte buffer it should access. Memory mapping alone therefore does not prove that an access respects a source-level object’s bounds. A bounds analysis must track object base and length and test the access range, including integer wraparound and multi-byte accesses. Default symbolic memory is not an automatic C memory-safety checker.

See also

[States, registers, and memory](#s17) for interface signatures and return values.

<a id="s07--source-trail"></a>

### Source trail

- [Address concretization mixin](https://github.com/angr/angr/blob/v9.3.4/angr/storage/memory_mixins/address_concretization_mixin.py).

- [Range strategy](https://github.com/angr/angr/blob/v9.3.4/angr/concretization_strategies/range.py).

- [Typed memory view](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/view.py).


---

<a id="s08"></a>

<a id="s08--files-and-process-environment"></a>

## [S08] Files and process environment

Execution depends on more than the executable’s instructions. Arguments, files, syscall results, heap layout, globals, and operating-system conventions can decide which paths are reachable. An environment model says what the program is allowed to observe.

<a id="s08--storage-and-descriptors-are-different"></a>

### Storage and descriptors are different

A SimFile-like object holds data. A file descriptor handles operations such as read, write, seek, and its current position. `state.posix.fd` maps descriptor numbers to descriptor models. `state.fs` maps virtual paths to file storage. Inserting a file by path lets the modeled open operation create a descriptor.

| Storage type | Suitable use | Important boundary |
|----|----|----|
| `SimFile` | Seekable files or flat byte-addressed data. | File size, EOF, and position in bytes. |
| `SimFileStream` | A flat stream with its own advancing position. | Finite versus extendable input. |
| `SimPackets` | A sequence of reads, useful for short-read behavior. | Positions describe packets, not arbitrary byte offsets. |

A storage read can return data, an actual length, and a new position. The returned data expression may be wider than the number of valid bytes. Honor the actual length rather than treating all returned bits as consumed input.

<a id="s08--finite-input-newlines-and-short-reads"></a>

### Finite input, newlines, and short reads

`read` handles raw bytes, `fgets` observes line and capacity boundaries, and `scanf` interprets a format and conversions. They require different contracts. If your input is a line, decide whether the newline is fixed, symbolic, or absent. If a read requests ten bytes, do not silently assume the real environment always returns ten.

Use `has_end=True` for a known complete input. An open-ended file can produce additional unknown bytes beyond its current contents. That can be appropriate for a stream, but it means the eventual witness must include every relevant read, not only the original symbolic prefix.

<a id="s08--sockets-and-pipes"></a>

### Sockets and pipes

They can be represented using stream/packet storage and descriptor models, but a realistic protocol also needs connection state, message ordering, blocking, errors, and sometimes both input and output directions. The specific syscall or library summary determines which interface the program sees. These labs do not emulate a live network service. Begin with a parser function over a bounded message buffer when the question does not require transport behavior.

<a id="s08--syscalls-and-library-calls"></a>

### Syscalls and library calls

SimOS chooses platform behavior and syscall models. SimProcedures model many library and syscall effects. Unsupported behavior can stop the analysis or be approximated according to configuration. A stub return value is not a complete model of an operation with memory or resource side effects.

For a custom model, write down its preconditions, outputs, side effects, and failure cases. If you skip a call to a random-number function, decide whether you are reproducing a concrete seed, exploring possible outputs, or deliberately removing a dependency. Each is a different question.

<a id="s08--host-state-and-reproducibility"></a>

### Host state and reproducibility

A SimHostFilesystem mount exposes selected host files to the guest model. That can be convenient but makes results depend on those files. For repeatable experiments, insert the exact virtual files you need or use a controlled snapshot directory. The file lab uses explicit content and a temporary native replay file, making the data dependency visible in the script.

See also

[Files and input storage](#s20) for interface signatures and return values.

<a id="s08--source-trail"></a>

### Source trail

- [Storage and descriptor models](https://github.com/angr/angr/blob/v9.3.4/angr/storage/file.py).

- [POSIX plugin](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/posix.py).

- [Filesystem](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/filesystem.py).

- [OS models](https://github.com/angr/angr/blob/v9.3.4/angr/simos/simos.py).

For library registration, syscall libraries, OS models, and imported data, see [Library, syscall, and operating-system models](#s31).


---

<a id="s09"></a>

<a id="s09--symbolic-execution-and-state-exploration"></a>

## [S09] Symbolic execution and state exploration

A SimulationManager moves states through named lists called stashes. Stepping executes the selected states, collects successors, and classifies what happened. Without a special search strategy, it advances the active states round by round.

<a id="s09--stashes-and-result-categories"></a>

### Stashes and result categories

| Location | Interpretation |
|----|----|
| `active` | States available for further execution in the usual selected stash. |
| `found` | States matching Explorer’s success condition. |
| `avoid` | States matching its avoidance condition. |
| `deadended` | States with no continuing successors under current execution. |
| `unsat` | Saved unsatisfiable successors when configured to retain them. |
| `unconstrained` | Saved successors whose instruction pointer has too many possibilities. |
| `pruned` | Paths removed after discovering an unsatisfiable history, notably with lazy solving. |
| `deferred` | Work held for later by a technique such as DFS. |
| `errored` | A separate list of ErrorRecord objects, not a normal state stash. |

`unconstrained` does not merely mean “the input has not been restricted.” It is a control-flow classification. It can reveal a bad return address or uninitialized pointer as well as input-dependent control flow. It is not, on its own, evidence of an exploitable vulnerability.

<a id="s09--execution-methods"></a>

### Execution methods

`step()` advances a round. It usually executes a basic block per state, but hooks, engines, and options can change the unit. `run(n=100)` performs up to 100 rounds, stopping sooner when the selected stash is empty or completion criteria apply. `run()` has no numerical cap by default in this release.

`explore(find=..., avoid=..., n=100)` temporarily installs Explorer and runs the manager. It normally stops after one new found state. `num_find` counts states, not input solutions. One state can contain many satisfying inputs, and several found states can overlap in their input assignments.

<a id="s09--search-predicates"></a>

### Search predicates

For the examples, find and avoid are symbol-derived integer addresses. An adaptation recipe for a concrete output marker is:

```python
manager.explore(
    find=lambda s: b'ACCEPT' in s.posix.dumps(1),
    avoid=lambda s: b'REJECT' in s.posix.dumps(1),
    n=250,
)
```

This works well when the output is a fixed literal on each path. `dumps` concretizes output; if output is symbolic, a sampled rendering is not a proof that all or any relevant assignments print your intended marker. Construct and add the needed output constraint explicitly, or use a validated address observation instead.

<a id="s09--errors-and-incomplete-execution"></a>

### Errors and incomplete execution

```python
print({name: len(states) for name, states in manager.stashes.items()})
for record in manager.errored:
    print(record.state, type(record.error).__name__, str(record.error))
```

This diagnostic recipe works after a run in which `manager` exists. Inspect `record.traceback` or use its debugging support during local investigation. Keep the failure visible; swallowing every exception and returning “not found” erases the difference between a failed model and an infeasible path.

<a id="s09--exploration-techniques"></a>

### Exploration techniques

DFS keeps fewer paths active and holds alternatives in `deferred`. It can reduce memory pressure but spend a long time in an unproductive deep path. LoopSeer controls loop trips. Veritesting summarizes suitable regions and merges paths, which may reduce state count and enlarge formulas. Spiller moves states to storage, and tracing techniques use external execution information.

Techniques can interact through their hooks. Enable one at a time and compare both runtime and witness validity. A custom strategy that discards states has changed the search coverage even if its returned witness still replays.

See also

[Simulation managers](#s19) for interface signatures and return values.

<a id="s09--source-trail"></a>

### Source trail

- [Manager and ErrorRecord](https://github.com/angr/angr/blob/v9.3.4/angr/sim_manager.py).

- [Explorer](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/explorer.py).

- [DFS](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/dfs.py).


---

<a id="s10"></a>

<a id="s10--hooks-and-simprocedures"></a>

## [S10] Hooks and SimProcedures

A hook associates a loaded address with replacement behavior. When execution reaches that address, the hook runs instead of the corresponding machine code. Hooks belong to the project and affect states executed through that project.

<a id="s10--function-summaries"></a>

### Function summaries

A [`SimProcedure`](#s21--angr.SimProcedure) implements a function’s relevant effects in Python. The runtime extracts arguments and places the return value according to the procedure’s prototype and calling convention. Register a procedure with [`hook_symbol()`](#s21--angr.Project.hook_symbol) for a symbol or [`hook()`](#s21--angr.Project.hook) for a verified address.

Example: replace a function returning an unsigned integer:

```python
import angr
import claripy

class Transform(angr.SimProcedure):
    def run(self, value):
        return (value * claripy.BVV(3, 32)) ^ claripy.BVV(0x55, 32)

# project is an existing Project defining the transform symbol.
project.hook_symbol(
    'transform',
    Transform(prototype='unsigned int transform(unsigned int)'),
)
```

This summary preserves the arithmetic and return value for the stated type. A summary of a function that modifies memory must also implement the relevant writes. An unconstrained return value does not stand in for buffer writes, resource allocation, or global changes.

<a id="s10--symbolic-behavior"></a>

### Symbolic behavior

Use Claripy expressions to represent symbolic alternatives:

```python
accepted = claripy.If(condition, claripy.BVV(1, 32), claripy.BVV(0, 32))
```

Here `condition` is a symbolic Boolean expression. A Python `if condition` would attempt to choose one host-language branch and is not a symbolic branch. State-specific data should be stored on the state or a state plugin, rather than on shared mutable project data.

<a id="s10--instruction-hooks"></a>

### Instruction hooks

A Python callback registered with `project.hook(address, callback, length=n)` runs at that address and then skips `n` bytes. The skip must end at a valid instruction boundary. With a zero-length callback, execution resumes the original code without immediately triggering the same callback again.

Use this form for instrumentation or a verified instruction sequence. It does not automatically extract function arguments or perform a function return.

<a id="s10--inspecting-registered-hooks"></a>

### Inspecting registered hooks

[`is_hooked()`](#s21--angr.Project.is_hooked) tests whether a hook exists; [`hooked_by()`](#s21--angr.Project.hooked_by) returns its procedure. Loading a real shared library does not imply that all of its functions execute machine code, because angr may install available SimProcedures.

See also

[Hooks, procedures, and inspection](#s21) for signatures and replacement policy; [Replace a function with an explicit model](#s43) for a complete symbolic-input example; [Extension interfaces](#s30) for extension-point selection.


---

<a id="s11"></a>

<a id="s11--execution-inspection"></a>

## [S11] Execution inspection

SimInspect invokes callbacks at execution events. It can observe or, for supported events, modify memory accesses, register accesses, constraints, control-flow transfers, and procedure calls. These callbacks instrument simulated execution, not a separate native debugger process.

<a id="s11--registering-a-breakpoint"></a>

### Registering a breakpoint

Use [`angr.state_plugins.inspect.SimInspector.b()`](#s21--angr.state_plugins.inspect.SimInspector.b) through `state.inspect`:

```python
def report_write(state):
    event = state.inspect.attrs
    print(event.mem_write_address, event.mem_write_expr)

# state is an initialized SimState; angr has been imported.
breakpoint = state.inspect.b(
    'mem_write', when=angr.BP_BEFORE, action=report_write
)
```

The callback receives the state on which the event occurred. `BP_BEFORE` observes the proposed operation; `BP_AFTER` observes completed results when the event provides them. Attribute values are transient and should be captured inside the callback when later inspection is needed.

<a id="s11--common-events"></a>

### Common events

| Event | Relevant attributes on `state.inspect.attrs` | Timing |
|----|----|----|
| `mem_read` | `mem_read_address`, `mem_read_length`, `mem_read_expr` | The loaded expression is available after the read. |
| `mem_write` | `mem_write_address`, `mem_write_length`, `mem_write_expr` | Proposed data and address are available before the write. |
| `reg_write` | `reg_write_offset`, `reg_write_expr` | Register offset and written expression. |
| `instruction` | `instruction` | Address of the instruction being processed. |
| `constraints` | `added_constraints` | Constraint expressions involved in the event. |
| `address_concretization` | `address_concretization_expr`, `address_concretization_result` | The selected addresses are available after resolution. |
| `simprocedure` | `simprocedure_name`, `simprocedure_result` | Result availability depends on event timing. |

<a id="s11--filters-and-state-local-records"></a>

### Filters and state-local records

The breakpoint’s `condition` callback must return a Python Boolean. Event-specific filters can restrict which addresses or values trigger a breakpoint. If the condition depends on symbolic values, use an explicit solver query whose possibility or uniqueness semantics match the intended filter.

A host list can collect diagnostics across all callbacks. For independent per-path records, use state-local immutable values or a plugin with explicit copy behavior. `state.globals` is shallow-copied when states fork.

<a id="s11--avoiding-recursive-inspection"></a>

### Avoiding recursive inspection

Memory reads made by a callback can trigger memory-read breakpoints. To perform a diagnostic read without another inspection event or action record:

```python
data = state.memory.load(address, 4, inspect=False, disable_actions=True)
```

This suppresses observation of that diagnostic read, not the target program’s normal reads. Leave tracking enabled for operations required by downstream analyses.

See also

[Hooks, procedures, and inspection](#s21) and [Observe execution with breakpoints](#s44).

<a id="s11--source"></a>

### Source

[Events and attributes](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/inspect.py).


---

<a id="s12"></a>

<a id="s12--control-flow-analysis-and-decompilation"></a>

## [S12] Control-flow analysis and decompilation

angr analyses compute results associated with a project and its knowledge base. They are invoked through `project.analyses`. They need not execute the program in the same way as a symbolic search.

<a id="s12--control-flow-graphs"></a>

### Control-flow graphs

`CFGFast` recovers functions and control-flow structure using static analysis. It is the usual starting point for inspecting a binary. `CFGEmulated` uses emulation and call-context tracking; it is more expensive and is useful when an analysis specifically requires execution-derived information or saved states. It is not a universally complete replacement for CFGFast.

Example, for an existing project:

```python
cfg = project.analyses.CFGFast(normalize=True)
for function in cfg.kb.functions.values():
    print(hex(function.addr), function.name)
```

<a id="s12--graph-interfaces"></a>

### Graph interfaces

| Interface | Result |
|----|----|
| `cfg.model.graph` | Recovered program-level graph. |
| `cfg.model.get_any_node(address)` | One matching CFG node, or `None`. |
| `cfg.model.get_all_nodes(address)` | Matching nodes, including distinct contexts when applicable. |
| `cfg.kb.functions` | Function manager indexed by recovered entry address. |
| `function.transition_graph` | Transitions associated with a recovered function. |
| `cfg.kb.functions.callgraph` | Recovered call relationships between functions. |

A CFG edge is a recovered control-flow possibility. A path through the graph may still be infeasible under the program’s data constraints. Conversely, unresolved indirect jumps and incorrect function boundaries can omit real behavior. Check these limitations before using a CFG to prune execution.

<a id="s12--decompilation"></a>

### Decompilation

The decompiler accepts a recovered function and a CFG model. A normalized CFG provides a regular block structure for downstream processing:

```python
# address is a verified function entry in cfg.kb.functions.
function = cfg.kb.functions[address]
result = project.analyses.Decompiler(function, cfg=cfg.model)
if result.codegen is not None:
    print(result.codegen.text)
```

The output reconstructs C-like control flow, variables, and expressions. It is not the original source. Names, inferred types, block boundaries, and pseudocode can change with compiler output or analysis configuration.

<a id="s12--analysis-results-and-errors"></a>

### Analysis results and errors

Some analysis infrastructure retains partial results after recording failures. Inspect analysis errors where completeness matters. A missing `codegen` does not imply an empty function. Check the recovered function, CFG, calling convention, and error information before changing unrelated solver settings.

See also

[Analysis interfaces](#s22) for options and result contracts; [Data flow, dependencies, and slicing](#s27) for reaching definitions; [Recover functions and decompile one](#s47) for a complete executable example.


---

<a id="s13"></a>

<a id="s13--solver-architecture-and-expression-inspection"></a>

## [S13] Solver architecture and expression inspection

For ordinary path queries, use [Symbolic expressions and constraint solving](#s06). The layers below explain why expression construction, solving, and approximation are different operations and where a custom solver integration belongs.

<a id="s13--asts-frontends-and-backends"></a>

### ASTs, frontends, and backends

An AST records an operation and its arguments. Common types are bitvectors, Booleans, and floating-point expressions. It is immutable: combining expressions creates another expression rather than writing a value into the original one.

A frontend manages constraints and exposes queries. A backend translates expressions into its own representation and performs operations there. `BackendConcrete` handles concrete values, `BackendZ3` uses the SMT solver, and `BackendVSA` uses abstract value sets. Frontend mixins add behaviors such as caching and simplification. A solver assembles these components; an AST itself is not a solver with a current set of path constraints.

```python
>>> import claripy
>>> x = claripy.BVS('inspect_input', 16)
>>> expr = x + 3
>>> expr.size()
16
>>> expr.symbolic
True
>>> x.variables <= expr.variables
True
>>> expr.op
'__add__'
```

`op`, `args`, `variables`, and `depth` help inspect structure. They are not a stable textual serialization format: simplification can change the tree while preserving its meaning. Do not parse the printed representation to recover a semantic property when an AST interface exists for it.

<a id="s13--solver-families"></a>

### Solver families

| Family | Purpose and boundary |
|----|----|
| `Solver` | Constraint solving for supported expressions. |
| `SolverVSA` | Abstract value reasoning; approximation is not an exact enumeration proof. |
| `SolverReplacement` | Substitute expressions before delegating; replacement correctness is the caller’s responsibility. |
| `SolverHybrid` | Combine approximate and exact reasoning according to query controls. |
| `SolverComposite` | Partition independent constraints to reduce solving cost. |

The same method name on different solver families does not imply identical precision. Record which mode produced a result. An approximate bound does not establish that every integer within it is feasible, and a timeout is not an unsatisfiable result.

<a id="s13--floating-point-values"></a>

### Floating-point values

Select the correct sort and distinguish bit reinterpretation from numeric conversion. IEEE operations include rounding and exceptional values. This small example demonstrates a concrete single-precision bit pattern:

```python
>>> one = claripy.FPV(1.0, claripy.fp.FSORT_FLOAT)
>>> solver = claripy.Solver()
>>> solver.eval(one.raw_to_bv(), 1)
(1065353216,)
```

It does not validate a target’s floating-point environment. Use explicit rounding modes where the operation requires them; NaN comparisons and signed zero need the operation’s floating-point semantics.

The [official solver-engine chapter](#s48) contains the preserved backend/frontend discussion. The [Operation and state-option catalogues](#scope) page provides the operation tables.


---

<a id="s14"></a>

<a id="s14--debug-information-and-variable-visibility"></a>

## [S14] Debug information and variable visibility

Debug information connects machine locations to source names and types. It does not restore values that optimization removed. Use this interface when a binary contains DWARF and the question concerns a source variable at a specific point in execution. For untyped machine addresses, use the normal memory interface.

<a id="s14--loading-and-initialization"></a>

### Loading and initialization

Compile a target with debugging information (for example, `gcc -g -O0`), then request it from the loader and populate the debug-variable knowledge plugin:

```python
import angr
project = angr.Project('program', auto_load_libs=False, load_debug_info=True)
project.kb.dvars.load_from_dwarf()
```

This fragment requires your own binary. Loading symbols alone does not populate an executed stack frame. First run to a point where the variable has been initialized and its containing frame is live. `addr_to_line` on the loaded main object can help relate addresses to source lines; use addresses from this build, not numeric addresses copied from another example.

```python
manager = project.factory.simulation_manager(project.factory.entry_state())
manager.explore(find=observation_address)
if not manager.found:
    raise RuntimeError('Observation was not reached')
state = manager.found[0]
value = state.dvars['counter'].mem.resolved
possible_counter = state.solver.eval(value)
```

`observation_address` must identify the instruction at which to observe the variable. The returned expression belongs to the selected state’s constraints. An evaluated value is one possibility; use `eval_one` when uniqueness matters.

<a id="s14--access-forms"></a>

### Access forms

| Expression | Meaning |
|----|----|
| `state.dvars['name'].mem` | Typed memory view of the variable. |
| `state.dvars['ptr'].deref.mem` | Memory view of the object addressed by a pointer variable. |
| `state.dvars['object'].member('field').mem` | Named structure member. |
| `state.dvars['items'].array(index).mem` | Array element. |
| `state.dvars['text'].string` | String interpretation supported by the debug-variable view. |

Nearest enclosing scope wins when names are shadowed. At an inner-block observation, `state.dvars['x']` may name a different storage location than at an outer-block observation. Moving the instruction pointer manually does not execute the writes needed to establish either variable’s value.

<a id="s14--limitations-and-diagnostics"></a>

### Limitations and diagnostics

Confirm the loader read the intended debug information, the observation is in the right function/scope, and the location is supported. Optimized variables can move between registers and stack or have no recoverable location. Distinguish failure to resolve a debug variable from a symbolic value that resolves but has multiple possible assignments. This workflow is documented from release source; it is not part of the native example test suite.

See the complete [official debug-variable chapter](#s50) for its original scope example.


---

<a id="s15"></a>

<a id="s15--projects-and-binary-loading"></a>

## [S15] Projects and binary loading

A project owns the loaded image, architecture, execution configuration, and hooks. It is normally created once per binary and used to construct states and run analyses. Loader mappings are project-level data; state memory contains execution-specific modifications.

<a id="s15--angr.Project"></a>

**class angr.Project(*thing*, *\*\*kwargs*)**

Load an executable and configure its analysis environment. The signature shown here abbreviates optional configuration arguments.

**Parameters:**

- **thing** – Executable path, supported binary stream, or an existing CLE loader.

- **arch** – Optional architecture override; normally detected from the image.

- **use_sim_procedures** (*bool*) – Install available library summaries. Defaults to `True`.

- **load_options** – Dictionary forwarded to CLE; default is an empty dictionary.

- **kwargs** – Additional loader options, including `auto_load_libs`, `main_opts`, and `lib_opts`.

**Loader options:** `auto_load_libs` determines whether dependencies are loaded automatically (`False` in CLE 9.3.4). `main_opts` configures the main object’s backend, base address, entry point, or architecture. `lib_opts` maps library names to per-library option dictionaries.

**Failure behavior:** construction can raise loader errors for an unsupported format, missing required metadata, or an unreadable input. A successfully loaded binary can still require environment models for execution.

<a id="s15--angr.Project.loader"></a>

**loader**

The CLE loader containing `main_object`, `all_objects`, and symbol resolution methods. See [Binary loading and addresses](#s04) for address conversion.

<a id="s15--angr.Project.arch"></a>

**arch**

Architecture metadata, including register names, bit width, and memory byte order. Use `arch.memory_endness` for native integer memory access.

<a id="s15--angr.Project.entry"></a>

**entry**

Loaded entry-point address. This is usually startup code, not `main`.

<a id="s15--angr.Project.factory"></a>

**factory**

An [`AngrObjectFactory`](#s16--angr.factory.AngrObjectFactory) associated with this project.

<a id="s15--angr.Project.analyses"></a>

**analyses**

Analysis hub. Attribute access such as `project.analyses.CFGFast` selects a registered analysis and supplies its project context.

<a id="s15--angr.Project.kb"></a>

**kb**

Default knowledge base containing recovered information such as functions. Analyses can be configured to use another knowledge base.

<a id="s15--example-executable-and-symbols"></a>

### Example: executable and symbols

The following fragment requires an executable named `program` with a defined `main` symbol:

```python
import angr

project = angr.Project('program', auto_load_libs=False)
symbol = project.loader.main_object.get_symbol('main')
if symbol is None:
    raise ValueError('The main symbol is unavailable')
address = symbol.rebased_addr
print(project.factory.block(address).capstone)
```

`rebased_addr` is in the loaded project’s address space. Neither an on-disk file offset nor a live-process ASLR address is automatically interchangeable with it. A stripped image requires another method of identifying code.

See also

[Binary loading and addresses](#s04) for mappings, imports, and library behavior; [Hooks, procedures, and inspection](#s21) for replacing functions; [State and execution factories](#s16) for initial states.

<a id="s15--source"></a>

### Source

[Project implementation](https://github.com/angr/angr/blob/v9.3.4/angr/project.py); [CLE loader](https://github.com/angr/cle/blob/v9.3.4/cle/loader.py).


---

<a id="s16"></a>

<a id="s16--state-and-execution-factories"></a>

## [S16] State and execution factories

Use `project.factory` to construct states and execution objects with the project’s architecture and operating-system configuration.

<a id="s16--angr.factory.AngrObjectFactory"></a>

**class angr.factory.AngrObjectFactory**

Factory attached to [`angr.Project.factory`](#s15--angr.Project.factory). Factory methods do not launch native processes.

<a id="s16--angr.factory.AngrObjectFactory.blank_state"></a>

**blank_state(*\*\*kwargs*)**

Create a minimally initialized state.

**Parameters:**

- **addr** – Initial instruction address; defaults to the project entry.

- **add_options** – Set of options to add to the state configuration.

- **remove_options** – Set of options to remove.

- **kwargs** – Additional options forwarded to state/OS initialization.

**Returns:**

A [`SimState`](#s17--angr.SimState).

Initialize registers, memory, and control-flow context needed by the selected starting location. A blank state at a function address does not automatically represent a valid call.

<a id="s16--angr.factory.AngrObjectFactory.entry_state"></a>

**entry_state(*\*\*kwargs*)**

Create a process state at the executable’s entry point.

**Parameters:**

- **args** – Sequence of command-line arguments, including the program name.

- **env** – Environment supplied to the modeled process.

- **stdin** – Bytes, a symbolic bitvector, or a file-storage object for stdin.

- **kwargs** – Additional state and OS setup options.

**Returns:**

A [`SimState`](#s17--angr.SimState).

For native Linux executables, argv and its string storage are constructed by the OS model. This does not start at `main` or execute the full initialization sequence before returning the state.

<a id="s16--angr.factory.AngrObjectFactory.full_init_state"></a>

**full_init_state(*\*\*kwargs*)**

Create a state whose execution begins with modeled initialization and then transfers to the executable’s entry point.

**Parameters:**

**kwargs** – Process arguments, input storage, and state options as supported by the OS model.

**Returns:**

A [`SimState`](#s17--angr.SimState) before initialization executes.

Initialization occurs when the state is stepped, not during the factory call. This remains a simulated environment, not a native dynamic loader.

<a id="s16--angr.factory.AngrObjectFactory.call_state"></a>

**call_state(*addr*, *\*args*, *\*\*kwargs*)**

Create a state as if a function were called with the supplied arguments.

**Parameters:**

- **addr** (*int*) – Loaded function entry address.

- **args** – Positional function arguments, concrete or symbolic.

- **prototype** – Function prototype as a supported C declaration or SimTypeFunction.

- **cc** – Calling-convention instance; use an explicit convention if the default does not match.

- **base_state** – Existing state providing memory and other initial context.

- **ret_addr** – Address to which the function should return.

- **kwargs** – Additional stack, allocation, and state initialization options.

**Returns:**

A [`SimState`](#s17--angr.SimState) at the function’s entry.

The factory sets up arguments and call mechanics. It does not execute the actual caller or create arbitrary application globals. Pointer arguments must designate correctly initialized storage. A supplied return sentinel can be used as an exploration target before it is executed.

<a id="s16--angr.factory.AngrObjectFactory.simulation_manager"></a>

**simulation_manager(*thing=None*, *\*\*kwargs*)**

Construct a manager seeded with execution states.

**Parameters:**

- **thing** – One state, a list of states, or `None` to create an entry state.

- **kwargs** – Arguments forwarded to [`angr.SimulationManager`](#s19--angr.SimulationManager).

**Returns:**

A [`SimulationManager`](#s19--angr.SimulationManager).

**Raises:**

[**angr.errors.AngrError**](#s23--angr.errors.AngrError) – If the seed is not a supported state or state collection.

Pass the prepared state explicitly when its inputs or options matter. Omitting it does not reuse the last state created by the factory.

<a id="s16--angr.factory.AngrObjectFactory.successors"></a>

**successors(*state*, *\*\*kwargs*)**

Execute a state through the selected engine.

**Parameters:**

- **state** – Input [`SimState`](#s17--angr.SimState).

- **kwargs** – Engine controls, such as `num_inst` for supported instruction stepping.

**Returns:**

A SimSuccessors object with ordinary, unsatisfiable, and unconstrained successor collections.

`flat_successors` is the usual collection for ordinary successors with concrete instruction pointers. This method does not populate manager stashes or automatically retain an ErrorRecord on failure.

<a id="s16--angr.factory.AngrObjectFactory.block"></a>

**block(*addr*, *\*\*kwargs*)**

Decode and lift bytes at a loaded address.

**Parameters:**

- **addr** (*int*) – Block start address.

- **size** – Optional byte limit for the block.

- **num_inst** – Optional instruction limit.

- **kwargs** – Additional lifting options.

**Returns:**

An angr Block with `capstone` and `vex` representations.

A block describes instructions, not their execution results in a state. The signature shown abbreviates advanced lifting arguments.

<a id="s16--example-bounded-instruction-execution"></a>

### Example: bounded instruction execution

```python
>>> import angr
>>> project = angr.load_shellcode(b'\x90', arch='AMD64')
>>> initial = project.factory.blank_state()
>>> result = project.factory.successors(initial, num_inst=1)
>>> len(result.flat_successors)
1
>>> result.flat_successors[0].addr == initial.addr + 1
True
```

See also

[Program states](#s05), [States, registers, and memory](#s17), and [Simulation managers](#s19).

<a id="s16--source"></a>

### Source

[Factory implementation](https://github.com/angr/angr/blob/v9.3.4/angr/factory.py); [OS state initialization](https://github.com/angr/angr/blob/v9.3.4/angr/simos/simos.py).


---

<a id="s17"></a>

<a id="s17--states-registers-and-memory"></a>

## [S17] States, registers, and memory

A state contains one execution context: registers, memory, constraints, environment models, history, and plugins. Construct it through the [State and execution factories](#s16) so the project and operating-system context are established.

<a id="s17--angr.SimState"></a>

**class angr.SimState**

Mutable execution state. A symbolic state represents all assignments allowed by its constraints; copying and merging change how those alternatives are represented.

<a id="s17--angr.SimState.regs"></a>

**regs**

Register view. Read or assign named registers such as `state.regs.eax`. Names and widths depend on `state.arch`. `ip` and `sp` provide architecture-independent instruction- and stack-pointer aliases.

<a id="s17--angr.SimState.memory"></a>

**memory**

Raw memory interface. `load(address, size, endness=...)` returns an expression for `size` bytes; `store(address, data, endness=...)` writes bytes or a bitvector. Size is in bytes, while bitvector width is in bits. Use the architecture’s endness for native integers.

<a id="s17--angr.SimState.mem"></a>

**mem**

Typed memory view. For example, `state.mem[address].uint32_t.resolved` reads a typed value as an expression. Structure layout and type sizes must match the target ABI.

<a id="s17--angr.SimState.solver"></a>

**solver**

[`SimSolver`](#s18--angr.state_plugins.solver.SimSolver) attached to this state. Use the result state’s solver when extracting an input for a reached path.

<a id="s17--angr.SimState.globals"></a>

**globals**

Dictionary-like storage for user data. Its copy is shallow: mutable contained values can remain shared after a fork. Use immutable values with reassignment or define a state plugin for custom copy/merge behavior.

<a id="s17--angr.SimState.history"></a>

**history**

Execution-history plugin, including block addresses and path depth. Available actions depend on tracking options. Retaining long histories can increase memory use.

<a id="s17--angr.SimState.options"></a>

**options**

State option set. Add or remove individual options, or update it with an option bundle. See [Options and search controls](#s33).

<a id="s17--angr.SimState.copy"></a>

**copy()**

Copy this state’s execution context and plugins.

**Returns:**

An independent [`SimState`](#s17--angr.SimState) with the same constraints.

Built-in storage may share immutable or copy-on-write data internally. User-provided mutable objects still need a suitable copy policy.

<a id="s17--angr.SimState.merge"></a>

**merge(*\*others*, *\*\*kwargs*)**

Merge compatible alternatives into a returned state.

**Parameters:**

- **others** – Other states to merge with this one.

- **merge_conditions** – Optional conditions identifying the input alternatives.

- **common_ancestor** – Optional shared ancestor used by merge implementations.

- **kwargs** – Other merge configuration, including plugin selection.

**Returns:**

`(merged_state, merge_conditions, changed)`.

**Raises:**

[**angr.errors.SimMergeError**](#s23--angr.errors.SimMergeError) – If states or plugins cannot be merged.

Values that differ across alternatives can become conditional expressions. Sharing an instruction address is not sufficient to make all state contents compatible. The returned state must be used explicitly.

<a id="s17--angr.SimState.step"></a>

**step(*\*\*kwargs*)**

Generate successors through the associated project’s engine.

**Parameters:**

**kwargs** – Execution controls forwarded to the factory.

**Returns:**

A SimSuccessors result.

Equivalent in purpose to [`angr.factory.AngrObjectFactory.successors()`](#s16--angr.factory.AngrObjectFactory.successors); for repeated execution and result classification use a simulation manager.

<a id="s17--angr.SimState.register_plugin"></a>

**register_plugin(*name*, *plugin*, *inhibit_init=False*)**

Attach a named state plugin.

**Parameters:**

- **name** (*str*) – Plugin name; also usable for state attribute access.

- **plugin** – SimStatePlugin instance.

- **inhibit_init** (*bool*) – Suppress normal plugin initialization when `True`; default `False`.

**Returns:**

The attached plugin instance.

Normal use leaves initialization enabled. A custom plugin must implement appropriate copy behavior and define merging if merged states are needed.

<a id="s17--example-initialize-an-integer-in-memory"></a>

### Example: initialize an integer in memory

```python
>>> import angr, claripy
>>> project = angr.load_shellcode(b'\x90', arch='AMD64')
>>> state = project.factory.blank_state()
>>> address = state.heap.allocate(4)
>>> state.memory.store(address, claripy.BVV(123, 32), endness=state.arch.memory_endness)
>>> value = state.memory.load(address, 4, endness=state.arch.memory_endness)
>>> state.solver.eval_one(value)
123
```

The allocation is in simulated memory. Its address is not a pointer into the host Python process.

See also

[Memory and symbolic addressing](#s07) for byte ordering and symbolic-address policies; [Preserve custom data through forks and merges](#s45) for an executable plugin implementation.

<a id="s17--source"></a>

### Source

[SimState](https://github.com/angr/angr/blob/v9.3.4/angr/sim_state.py); [State plugins](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/plugin.py).


---

<a id="s18"></a>

<a id="s18--expressions-and-solver-queries"></a>

## [S18] Expressions and solver queries

Claripy creates immutable expressions. The state’s solver stores constraints and evaluates expressions under those constraints. The two layers have different call signatures; in particular, a standalone `claripy.Solver` is not the same interface as `state.solver`.

<a id="s18--expression-constructors"></a>

### Expression constructors

<a id="s18--claripy.BVS"></a>

**claripy.BVS(*name*, *size*, *explicit_name=None*, *\*\*kwargs*)**

Create a symbolic bitvector.

**Parameters:**

- **name** (*str*) – Human-readable symbol name.

- **size** (*int*) – Width in bits, not bytes.

- **explicit_name** – When true, disable automatic name uniquification. Default `None` uses normal naming behavior.

- **kwargs** – Additional supported AST metadata.

**Returns:**

A Claripy bitvector expression.

Reusing a name in two normal calls does not mean they represent the same variable. Keep and reuse the original expression object when modeling one input across several operations.

<a id="s18--claripy.BVV"></a>

**claripy.BVV(*value*, *size=None*, *\*\*kwargs*)**

Create a concrete bitvector.

**Parameters:**

- **value** – Integer value or supported byte sequence.

- **size** – Required bit width for an integer; derived from byte content when omitted.

- **kwargs** – Additional supported AST metadata.

**Returns:**

A Claripy bitvector expression.

Integer arithmetic is performed at the expression’s width. Byte order in memory is a separate choice made by memory loads and stores.

<a id="s18--claripy.Concat"></a>

**claripy.Concat(*\*args*)**

Concatenate bitvectors from most-significant to least-significant argument.

**Parameters:**

**args** – Bitvector expressions to concatenate.

**Returns:**

A bitvector whose width is the sum of the input widths.

<a id="s18--claripy.If"></a>

**claripy.If(*condition*, *true_value*, *false_value*)**

Construct a conditional expression without choosing a Python branch.

**Parameters:**

- **condition** – Symbolic Boolean expression.

- **true_value** – Value when the condition holds.

- **false_value** – Value otherwise, compatible in type/width with `true_value`.

**Returns:**

An expression representing both alternatives.

<a id="s18--state-solver"></a>

### State solver

<a id="s18--angr.state_plugins.solver.SimSolver"></a>

**class angr.state_plugins.solver.SimSolver**

State plugin available as [`angr.SimState.solver`](#s17--angr.SimState.solver). The contracts below describe the normal symbolic solver mode; abstract or approximate modes can have different guarantees.

<a id="s18--angr.state_plugins.solver.SimSolver.constraints"></a>

**constraints**

Constraints currently recorded for this solver. Add constraints through `add` rather than mutating the returned collection.

<a id="s18--angr.state_plugins.solver.SimSolver.add"></a>

**add(*\*constraints*)**

Add persistent constraints to the state.

**Parameters:**

**constraints** – Claripy Boolean expressions passed as separate arguments.

**Returns:**

`None`.

Pass `state.solver.add(a, b)`, not a list. To add a collection, unpack it with `state.solver.add(*conditions)`. This call alone does not prove the resulting state is satisfiable.

<a id="s18--angr.state_plugins.solver.SimSolver.satisfiable"></a>

**satisfiable(*extra_constraints=()*, *exact=None*)**

Check whether the state and optional temporary constraints are feasible.

**Parameters:**

- **extra_constraints** – Iterable of additional Boolean constraints for this query only.

- **exact** – Backend exactness control; leave the default for normal symbolic solving.

**Returns:**

`True` if feasible, `False` if unsatisfiable.

Temporary constraints are not retained. Solver errors or timeouts must not be interpreted as an unsatisfiable result.

<a id="s18--angr.state_plugins.solver.SimSolver.eval"></a>

**eval(*e*, *cast_to=None*, *\*\*kwargs*)**

Evaluate one possible value of an expression.

**Parameters:**

- **e** – Expression to evaluate.

- **cast_to** – Optional conversion; `bytes` is useful for byte-aligned bitvectors.

- **kwargs** – Query controls, including temporary `extra_constraints`.

**Returns:**

One Python value (normally an integer for a bitvector).

**Raises:**

- [**angr.errors.SimUnsatError**](#s23--angr.errors.SimUnsatError) – If a required solve yields no value.

- **ValueError** – If the requested conversion is unsupported or its width is invalid.

Evaluation does not constrain the expression to the returned value. A concrete expression may be returned without a solver call; use `satisfiable` separately when checking state feasibility.

<a id="s18--angr.state_plugins.solver.SimSolver.eval_one"></a>

**eval_one(*e*, *cast_to=None*, *\*\*kwargs*)**

Evaluate an expression that has exactly one possible value.

**Parameters:**

- **e** – Expression to evaluate.

- **cast_to** – Optional conversion, as for `eval`.

- **kwargs** – Query controls; `default` can supply a fallback for supported evaluation failures.

**Returns:**

The unique value, or the explicitly supplied fallback.

**Raises:**

- [**angr.errors.SimUnsatError**](#s23--angr.errors.SimUnsatError) – If no value exists and no fallback is supplied.

- [**angr.errors.SimValueError**](#s23--angr.errors.SimValueError) – If more than one value exists and no fallback is supplied.

A uniqueness failure is distinct from infeasibility. Do not use a fallback that makes those outcomes indistinguishable when they matter.

<a id="s18--angr.state_plugins.solver.SimSolver.eval_upto"></a>

**eval_upto(*e*, *n*, *cast_to=None*, *\*\*kwargs*)**

Enumerate a bounded number of distinct values.

**Parameters:**

- **e** – Expression to evaluate.

- **n** (*int*) – Positive maximum number of results.

- **cast_to** – Optional conversion applied to each result.

- **kwargs** – Additional query controls.

**Returns:**

A list containing up to `n` possible values.

**Raises:**

[**angr.errors.SimUnsatError**](#s23--angr.errors.SimUnsatError) – If a required solve yields no values.

Returning `n` values does not establish that there are only `n` solutions. A joint expression preserves correlations between input fields; independently enumerated lists do not.

<a id="s18--example-temporary-and-persistent-constraints"></a>

### Example: temporary and persistent constraints

```python
>>> import angr, claripy
>>> project = angr.load_shellcode(b'\x90', arch='AMD64')
>>> state = project.factory.blank_state()
>>> x = claripy.BVS('choice', 8)
>>> state.solver.add(x >= 3, x <= 5)
>>> state.solver.satisfiable(extra_constraints=(x == 9,))
False
>>> sorted(state.solver.eval_upto(x, 10))
[3, 4, 5]
>>> state.solver.add(x == 4)
>>> state.solver.eval_one(x)
4
```

See also

[Symbolic expressions and constraint solving](#s06) for signedness, shifts, widths, and joint queries.

<a id="s18--source"></a>

### Source

[State solver](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/solver.py); [Claripy bitvectors](https://github.com/angr/claripy/blob/v9.3.4/claripy/ast/bv.py).


---

<a id="s19"></a>

<a id="s19--simulation-managers"></a>

## [S19] Simulation managers

A simulation manager executes and classifies states. Obtain one with [`angr.factory.AngrObjectFactory.simulation_manager()`](#s16--angr.factory.AngrObjectFactory.simulation_manager). A named state list is a *stash*. Error records are stored separately.

<a id="s19--angr.SimulationManager"></a>

**class angr.SimulationManager(*project*, *active_states=None*, *\*\*kwargs*)**

Manage execution states for one project. This signature abbreviates additional constructor options.

**Parameters:**

- **project** – Owning [`Project`](#s15--angr.Project).

- **active_states** – Initial state list.

- **save_unsat** (*bool*) – Retain unsatisfiable successors. Default `False`.

- **kwargs** – Stash, resilience, completion, and exploration-technique configuration.

<a id="s19--angr.SimulationManager.stashes"></a>

**stashes**

Mapping from names to state lists. Common names include `active`, `found`, `avoid`, `deadended`, `unsat`, and `unconstrained`. Techniques may add names such as `deferred` or `spinning`. See [Symbolic execution and state exploration](#s09) for each category’s meaning.

<a id="s19--angr.SimulationManager.errored"></a>

**errored**

List of ErrorRecord objects with `state`, `error`, and `traceback` attributes. These are not states in a stash. A captured error indicates failed execution, not an infeasible path.

<a id="s19--angr.SimulationManager.step"></a>

**step(*stash='active'*, *\*\*kwargs*)**

Advance one manager round for a selected stash. The displayed signature abbreviates optional stepping callbacks.

**Parameters:**

- **stash** (*str*) – Stash to step.

- **kwargs** – Filtering/stepping callbacks and engine controls.

**Returns:**

This manager, modified in place.

The default is approximately one basic block per state, not one machine instruction. Engines, hooks, and techniques can change that unit.

<a id="s19--angr.SimulationManager.run"></a>

**run(*stash='active'*, *n=None*, *until=None*, *\*\*kwargs*)**

Step repeatedly until a stopping condition applies.

**Parameters:**

- **stash** (*str*) – Stash to execute.

- **n** – Maximum manager rounds, or `None` for no numeric bound.

- **until** – Callback receiving the manager; a true result stops the loop after a step.

- **kwargs** – Arguments forwarded to stepping.

**Returns:**

This manager.

Execution can also stop when the selected stash is empty or configured techniques report completion. A step count is not a wall-clock timeout.

<a id="s19--angr.SimulationManager.explore"></a>

**explore(*stash='active'*, *n=None*, *find=None*, *avoid=None*, *find_stash='found'*, *avoid_stash='avoid'*, *cfg=None*, *num_find=1*, *avoid_priority=False*, *\*\*kwargs*)**

Search for states matching a condition using the Explorer technique.

**Parameters:**

- **stash** (*str*) – States to execute.

- **n** – Optional maximum manager rounds.

- **find** – Address, address collection, or callback returning a Python Boolean for a state.

- **avoid** – Same forms as `find`, identifying states to stop exploring.

- **find_stash** (*str*) – Destination for matching states; default `found`.

- **avoid_stash** (*str*) – Destination for avoided states; default `avoid`.

- **cfg** – Optional supported CFG for reachability-based pruning. See Explorer’s release source for accepted models and limitations.

- **num_find** (*int*) – Number of additional found states requested; default one.

- **avoid_priority** (*bool*) – Give avoidance priority when both conditions match. Default `False`.

- **kwargs** – Additional run/step controls.

**Returns:**

This manager; inspect the named stashes for results.

`num_find` counts states, not concrete input solutions. A normal return with an empty found stash does not establish unreachability: inspect active/deferred work, discarded paths, and errors.

<a id="s19--angr.SimulationManager.move"></a>

**move(*from_stash*, *to_stash*, *filter_func=None*)**

Transfer matching states between stashes.

**Parameters:**

- **from_stash** (*str*) – Source stash.

- **to_stash** (*str*) – Destination stash.

- **filter_func** – Optional Boolean state predicate; omission moves all states.

**Returns:**

This manager.

Moving states changes classification, not their solver constraints.

<a id="s19--angr.SimulationManager.use_technique"></a>

**use_technique(*tech*)**

Install an exploration-technique instance.

**Parameters:**

**tech** – Instance of ExplorationTechnique.

**Returns:**

The installed technique instance, usable for removal.

<a id="s19--angr.SimulationManager.remove_technique"></a>

**remove_technique(*tech*)**

Remove a previously installed technique.

**Parameters:**

**tech** – The same technique instance supplied during installation.

**Returns:**

The removed technique instance.

<a id="s19--example-one-round"></a>

### Example: one round

```python
>>> import angr
>>> project = angr.load_shellcode(b'\x90\x90', arch='AMD64')
>>> state = project.factory.blank_state()
>>> manager = project.factory.simulation_manager(state)
>>> _ = manager.run(n=1, num_inst=1)
>>> len(manager.active)
1
>>> manager.active[0].addr == state.addr + 1
True
```

See also

[Symbolic execution and state exploration](#s09) for outcome interpretation and [Performance and search limits](#s25) for search-strategy selection.

<a id="s19--source"></a>

### Source

[SimulationManager](https://github.com/angr/angr/blob/v9.3.4/angr/sim_manager.py); [Explorer](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/explorer.py).


---

<a id="s20"></a>

<a id="s20--files-and-input-storage"></a>

## [S20] Files and input storage

File-storage objects hold bytes. Descriptors provide read/write/seek operations and track descriptor state. Paths are resolved through `state.fs`; standard input is normally supplied when the initial state is created.

<a id="s20--angr.SimFile"></a>

**class angr.SimFile(*name=None*, *content=None*, *size=None*, *has_end=None*, *seekable=True*, *writable=True*, *\*\*kwargs*)**

Model a flat, byte-addressed file. The signature abbreviates optional identifier and concrete-content configuration.

**Parameters:**

- **name** – Descriptive file name; insertion into a filesystem is a separate operation.

- **content** – Initial bytes or symbolic bitvector.

- **size** – File length in bytes; can be symbolic. A supplied content buffer can determine the initial length.

- **has_end** – Treat the size boundary as EOF when true. Defaults depend on size and state options; set explicitly when important.

- **seekable** (*bool*) – Allow seeking; default `True`.

- **writable** (*bool*) – Allow writes; default `True`.

- **kwargs** – Additional storage configuration.

A storage object must be attached to a state before solver-dependent operations. Passing it during state creation or inserting it in `state.fs` performs this attachment.

<a id="s20--angr.SimFile.read"></a>

**read(*pos*, *size*, *\*\*kwargs*)**

Read from a byte offset.

**Parameters:**

- **pos** – Starting position.

- **size** – Requested number of bytes, possibly symbolic.

- **kwargs** – Additional read options.

**Returns:**

`(data, actual_size, new_position)`.

The returned data expression can be wider than `actual_size`. Only the reported number of bytes are valid input for this read. With `has_end=False`, reads may generate symbolic content beyond the current frontier.

<a id="s20--angr.SimFile.concretize"></a>

**concretize(*\*\*kwargs*)**

Produce a concrete assignment for the file contents.

**Parameters:**

**kwargs** – Additional solver query options supported by the implementation.

**Returns:**

A byte string for this flat-file implementation.

Other storage types can return different representations. Keep a reference to the original symbolic input when extracting a fixed prefix or correlated fields.

<a id="s20--angr.SimFileStream"></a>

**class angr.SimFileStream(*name=None*, *content=None*, *pos=0*, *\*\*kwargs*)**

Flat-file storage that maintains an advancing stream position.

**Parameters:**

- **name** – Descriptive name.

- **content** – Initial byte content or symbolic expression.

- **pos** – Initial stream position, default zero.

- **kwargs** – SimFile configuration, including `size` and `has_end`.

Useful for bounded stdin inputs. This is distinct from packet storage: packet positions refer to read records rather than arbitrary byte offsets.

<a id="s20--angr.state_plugins.filesystem.SimFilesystem"></a>

**class angr.state_plugins.filesystem.SimFilesystem**

Filesystem plugin available as `state.fs`.

<a id="s20--angr.state_plugins.filesystem.SimFilesystem.insert"></a>

**insert(*path*, *simfile*)**

Associate a virtual path with file storage.

**Parameters:**

- **path** – Virtual path resolved by the filesystem plugin.

- **simfile** – SimFile-compatible storage object.

**Returns:**

Whether insertion succeeded.

The path does not create a host file. Mounts may affect path resolution and whether insertion is supported.

<a id="s20--angr.state_plugins.filesystem.SimFilesystem.get"></a>

**get(*path*)**

Look up file storage by virtual path.

**Parameters:**

**path** – Virtual file path.

**Returns:**

Storage object or `None` if unavailable.

<a id="s20--example-insert-a-fixed-file"></a>

### Example: insert a fixed file

```python
>>> import angr
>>> project = angr.load_shellcode(b'\x90', arch='AMD64')
>>> state = project.factory.blank_state()
>>> source = angr.SimFile('settings', content=b'yes', has_end=True)
>>> state.fs.insert('/settings', source)
True
>>> state.fs.get('/settings').concretize()
b'yes'
```

See also

[Files and process environment](#s08) for descriptors, packets, EOF, and short reads; [Solve the contents of a file](#s40) for symbolic file input and native replay.

<a id="s20--source"></a>

### Source

[File storage](https://github.com/angr/angr/blob/v9.3.4/angr/storage/file.py); [Filesystem](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/filesystem.py).


---

<a id="s21"></a>

<a id="s21--hooks-procedures-and-inspection"></a>

## [S21] Hooks, procedures, and inspection

Hooks replace or instrument code at loaded addresses. SimProcedures model function calls, while SimInspect callbacks observe execution events.

<a id="s21--project-hooks"></a>

### Project hooks

<a id="s21--angr.Project.hook"></a>

**angr.Project.hook(*addr*, *hook=None*, *length=0*, *kwargs=None*, *replace=False*)**

Register a SimProcedure or user callback at an address.

**Parameters:**

- **addr** (*int*) – Address in the project’s loaded space.

- **hook** – SimProcedure instance or Python callback; omission enables decorator use.

- **length** (*int*) – Bytes skipped after a user callback, default zero. Not an instruction count.

- **kwargs** – Configuration for the installed procedure.

- **replace** – Existing-hook replacement policy: `False` retains it with a warning, `True` replaces it, and `None` replaces with a warning.

A zero-length user callback resumes original code without immediately retriggering itself. For argument extraction and function returns, use a SimProcedure rather than assuming a callback has call semantics.

<a id="s21--angr.Project.hook_symbol"></a>

**angr.Project.hook_symbol(*symbol_name*, *simproc*, *kwargs=None*, *replace=None*)**

Resolve a symbol and register a procedure at the appropriate address.

**Parameters:**

- **symbol_name** (*str*) – Symbol to resolve.

- **simproc** – Procedure instance or supported hook target.

- **kwargs** – Procedure configuration.

- **replace** – Replacement policy, default `None` (replace with a warning).

**Returns:**

Hooked address, or `None` when symbol resolution fails.

Use this interface for imported symbols rather than assuming an import record’s address is the function body.

<a id="s21--angr.Project.is_hooked"></a>

**angr.Project.is_hooked(*addr*)**

**Parameters:**

**addr** (*int*) – Loaded address.

**Returns:**

Whether a procedure is installed there.

<a id="s21--angr.Project.hooked_by"></a>

**angr.Project.hooked_by(*addr*)**

**Parameters:**

**addr** (*int*) – Loaded address.

**Returns:**

Installed procedure, or `None` if no hook exists.

<a id="s21--angr.Project.unhook"></a>

**angr.Project.unhook(*addr*)**

Remove the hook at an address.

**Parameters:**

**addr** (*int*) – Loaded address.

**Returns:**

`None`.

<a id="s21--procedure-implementation"></a>

### Procedure implementation

<a id="s21--angr.SimProcedure"></a>

**class angr.SimProcedure**

Base class for function summaries. Instantiate a subclass and register it with a project. Its prototype and calling convention control argument extraction and return placement.

<a id="s21--angr.SimProcedure.run"></a>

**run(*\*args*, *\*\*kwargs*)**

Override with the modeled function’s arguments.

**Parameters:**

- **args** – Values extracted from the simulated calling convention.

- **kwargs** – Configuration supplied to the procedure instance.

**Returns:**

A concrete or symbolic return value, unless the procedure explicitly transfers control.

`self.state` is the executing state; `self.project` is its project. Model observable memory writes and other side effects as well as the return value. Do not use Python conditionals to choose between symbolic alternatives; construct a symbolic conditional expression.

<a id="s21--inspection"></a>

### Inspection

<a id="s21--angr.state_plugins.inspect.SimInspector.b"></a>

**angr.state_plugins.inspect.SimInspector.b(*event_type*, *when=angr.BP_BEFORE*, *enabled=True*, *condition=None*, *action=angr.BP_IPDB*, *\*\*kwargs*)**

Register a breakpoint through `state.inspect.b`. This is an alias for the inspector’s breakpoint-construction method.

**Parameters:**

- **event_type** – Event name, such as `mem_read`, `mem_write`, or `instruction`.

- **when** – Event phase, default `angr.BP_BEFORE`.

- **enabled** (*bool*) – Whether the breakpoint is enabled; default `True`.

- **condition** – Optional Boolean callback filtering the event.

- **action** – Callback taking a state; the default opens the configured debugger.

- **kwargs** – Event-specific filter fields.

**Returns:**

The breakpoint object.

`when` selects `angr.BP_BEFORE` or `angr.BP_AFTER`; the default is before. `action` is a callback taking a state. `condition` is an optional callback returning a Python Boolean. Other event-specific fields can filter triggering conditions.

Event values are available through `state.inspect.attrs` while the callback is executing. A read’s result is available after the read, not before it.

<a id="s21--example-observe-a-write"></a>

### Example: observe a write

```python
>>> import angr
>>> project = angr.load_shellcode(b'\x90', arch='AMD64')
>>> state = project.factory.blank_state()
>>> observed = []
>>> def record(current):
...     observed.append(current.inspect.attrs.mem_write_address)
>>> breakpoint = state.inspect.b('mem_write', when=angr.BP_BEFORE, action=record)
>>> state.memory.store(0x1000, b'A')
>>> len(observed)
1
```

The list in this example is a host-side diagnostic collector. Use a state plugin or state-local immutable values when records must remain independent per path.

See also

[Hooks and SimProcedures](#s10), [Execution inspection](#s11), and [Replace a function with an explicit model](#s43).

<a id="s21--source"></a>

### Source

[Project hooks](https://github.com/angr/angr/blob/v9.3.4/angr/project.py); [SimProcedure](https://github.com/angr/angr/blob/v9.3.4/angr/sim_procedure.py); [SimInspect](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/inspect.py).


---

<a id="s22"></a>

<a id="s22--analysis-interfaces"></a>

## [S22] Analysis interfaces

Analyses run through `project.analyses`. The analysis hub supplies project and knowledge-base context. Invoke `project.analyses.CFGFast(...)`, for example, rather than constructing the implementation class directly.

The signatures below abbreviate configuration with `**kwargs` and document selected options. The release sources contain the full option sets.

<a id="s22--control-flow-recovery"></a>

### Control-flow recovery

<a id="s22--angr.analyses.cfg.cfg_fast.CFGFast"></a>

**class angr.analyses.cfg.cfg_fast.CFGFast(*\*\*kwargs*)**

Static function and control-flow recovery. Invoke through `project.analyses.CFGFast`.

**Parameters:**

- **normalize** (*bool*) – Normalize recovered blocks for downstream analyses; default `False`.

- **function_starts** – Optional known function-entry addresses.

- **resolve_indirect_jumps** (*bool*) – Attempt indirect-target resolution; default `True`.

- **data_references** (*bool*) – Collect data references; default `True`.

- **kwargs** – Additional recovery, scanning, and knowledge-base options.

**Results:** `model` contains the recovered CFG; `kb.functions` contains function objects. `model.get_any_node(address)` returns one matching node or `None`. `model.graph` exposes the recovered graph.

Recovered edges are structural possibilities, not proof that a path is feasible. Stripped binaries, indirect transfers, and mixed code/data can require additional configuration and inspection.

<a id="s22--angr.analyses.cfg.cfg_emulated.CFGEmulated"></a>

**class angr.analyses.cfg.cfg_emulated.CFGEmulated(*\*\*kwargs*)**

Recover control flow using emulated execution and context tracking. Invoke through `project.analyses.CFGEmulated`.

**Parameters:**

- **starts** – Optional start addresses or supported entry descriptors.

- **initial_state** – Optional prepared state.

- **keep_state** (*bool*) – Retain states at recovered nodes; default `False`.

- **context_sensitivity_level** (*int*) – Call-context depth; default one.

- **kwargs** – Additional execution and recovery options.

**Results:** CFG model and function knowledge comparable in organization to CFGFast, with context-sensitive nodes and optional saved states. More context increases cost; emulation limitations can leave gaps in the graph.

<a id="s22--decompilation"></a>

### Decompilation

<a id="s22--angr.analyses.decompiler.decompiler.Decompiler"></a>

**class angr.analyses.decompiler.decompiler.Decompiler(*func*, *\*\*kwargs*)**

Recover C-like pseudocode for a function. Invoke through `project.analyses.Decompiler`.

**Parameters:**

- **func** – Recovered function object or supported function identifier.

- **cfg** – CFG model, usually from a normalized CFGFast analysis.

- **kwargs** – Decompilation options and analysis configuration.

**Results:** `codegen.text` contains pseudocode when generation succeeds. Check `codegen is not None` before accessing text. Type, variable, and control-structure recovery may differ from the original source.

<a id="s22--data-flow"></a>

### Data flow

<a id="s22--angr.analyses.reaching_definitions.reaching_definitions.ReachingDefinitionsAnalysis"></a>

**class angr.analyses.reaching_definitions.reaching_definitions.ReachingDefinitionsAnalysis(*subject*, *\*\*kwargs*)**

Compute reaching definitions for a function or block. Invoke through `project.analyses.ReachingDefinitions`.

**Parameters:**

- **subject** – Function, block, or another supported analysis subject.

- **observation_points** – Collection of observation kind/address/before-or-after tuples.

- **observe_all** (*bool*) – Record all supported observations; default `False`.

- **dep_graph** – Dependency graph or Boolean configuration; default `True`.

- **kwargs** – Abstract-state, function-handler, and analysis controls.

**Results:** `observed_results` maps observation points to abstract definitions; `dep_graph` contains dependencies when enabled. These results are abstract analysis states, not SimStates for normal symbolic execution. Aliasing and unknown-call handling affect precision.

<a id="s22--custom-analysis-registration"></a>

### Custom analysis registration

<a id="s22--angr.Analysis"></a>

**class angr.Analysis**

Base for project-level analyses. The analysis hub establishes `self.project` and `self.kb` before the subclass initializer runs. Expose results through attributes with an explicit contract.

<a id="s22--angr.analyses.AnalysesHub.register_default"></a>

**classmethod angr.analyses.AnalysesHub.register_default(*name*, *plugin_cls*, *preset='default'*)**

Register an analysis class under a hub name.

**Parameters:**

- **name** (*str*) – Attribute used to invoke the analysis through `project.analyses`.

- **plugin_cls** – Analysis subclass.

- **preset** (*str*) – Plugin preset; default `'default'`.

**Returns:**

`None`.

Import `AnalysesHub` from `angr.analyses` in this release.

<a id="s22--example-cfg-and-decompiler"></a>

### Example: CFG and decompiler

This fragment requires the repository’s target built with `make examples`:

```python
import angr

project = angr.Project('build/targets', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True)
symbol = project.loader.main_object.get_symbol('check')
if symbol is None:
    raise ValueError('Missing check symbol')
function = cfg.kb.functions[symbol.rebased_addr]
result = project.analyses.Decompiler(function, cfg=cfg.model)
if result.codegen is not None:
    print(result.codegen.text)
```

The complete [Recover functions and decompile one](#s47) example is exercised by the behavioral test suite.

See also

[Control-flow analysis and decompilation](#s12), [Data flow, dependencies, and slicing](#s27), and [Extension interfaces](#s30).

<a id="s22--source"></a>

### Source

[Analysis hub](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/analysis.py); [CFGFast](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/cfg/cfg_fast.py); [Decompiler](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/decompiler/decompiler.py); [Reaching definitions](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/reaching_definitions/reaching_definitions.py).


---

<a id="s23"></a>

<a id="s23--exceptions-and-execution-failures"></a>

## [S23] Exceptions and execution failures

Direct calls can raise exceptions. During managed execution, configured resilience may capture execution failures as records in [`angr.SimulationManager.errored`](#s19--angr.SimulationManager.errored). Inspect those records separately from normal state stashes.

<a id="s23--angr.errors.AngrError"></a>

**exception angr.errors.AngrError**

Base error for angr framework operations. Subclasses distinguish more specific failures. A loader or solver dependency may also raise its own exception type.

<a id="s23--angr.errors.SimUnsatError"></a>

**exception angr.errors.SimUnsatError**

A solver operation requiring a value found no satisfying assignment. Use `state.solver.satisfiable()` when the desired result is a Boolean feasibility check instead of a witness.

<a id="s23--angr.errors.SimValueError"></a>

**exception angr.errors.SimValueError**

An operation’s value requirement was not satisfied, for example more than one possible value when `eval_one` requires uniqueness.

<a id="s23--angr.errors.SimMergeError"></a>

**exception angr.errors.SimMergeError**

States or state plugins could not be merged under the requested operation. Matching instruction addresses alone does not establish compatibility.

<a id="s23--error-handling"></a>

### Error handling

Check failure categories before drawing conclusions about the target program:

- An empty `found` stash is a search outcome, not an exception.

- Unsatisfiability concerns the constraints in the modeled state.

- A solver timeout is not an unsatisfiability result.

- An unsupported operation or invalid address can prevent execution before the relevant path condition is evaluated.

See [Troubleshooting](#s26) for diagnosis and [Simulation managers](#s19) for managed-execution behavior.

<a id="s23--source"></a>

### Source

[Exception definitions](https://github.com/angr/angr/blob/v9.3.4/angr/errors.py).


---

<a id="s24"></a>

<a id="s24--a-reliable-analysis-workflow"></a>

## [S24] A reliable analysis workflow

Start by writing the question in a form you can test: input source, input size, starting point, success observation, and environmental assumptions. For the course target, it is “find four stdin bytes that reach `win` and print `ACCEPT` when replayed.”

<a id="s24--inspect-the-program-before-making-inputs-symbolic"></a>

### 1. Inspect the program before making inputs symbolic

Load without shared libraries initially, print the architecture and mapped objects, locate symbols, and inspect the target function. Use CFGFast when you need a map of functions. Run a known concrete input through angr before using a symbolic one; a broken concrete run often identifies a loading or environment problem before solver complexity hides it.

<a id="s24--choose-the-smallest-honest-starting-state"></a>

### 2. Choose the smallest honest starting state

Use a process entry state for a complete input-to-result question. Use `call_state` when the question is about a function and you can specify its arguments, memory, and global dependencies. A blank state at a mid-function address is appropriate only when you reconstruct everything the preceding code would have established.

Shorter execution is useful, but skipping setup creates obligations. For example, a parser might rely on a global length, a locale table, or a heap object constructed earlier. Document those obligations next to the state setup.

<a id="s24--model-the-input-including-its-boundaries"></a>

### 3. Model the input, including its boundaries

A four-byte vector is not automatically a C string. A stream with four known bytes is not automatically at EOF. An argument cannot contain an embedded NUL and still behave like a four-character C argument. Set these details deliberately. Preserve a Python reference to each original input expression so you can extract that input from the eventual result state.

<a id="s24--name-success-and-failure-precisely"></a>

### 4. Name success and failure precisely

Prefer symbol-derived addresses for these labs. An output predicate works well when the marker is concrete and unambiguous. Finding the address of a print function means you reached its entry, not that it already printed anything. Use native replay or continue execution when the observation requires a side effect after that address.

<a id="s24--run-with-observable-limits"></a>

### 5. Run with observable limits

Give the search a step budget. Capture stash counts and error records if it fails. Large analyses also need an outer process timeout and a memory limit: one simulation step can itself spend a long time solving constraints, so a step count is not a wall-clock deadline.

<a id="s24--extract-replay-and-explain"></a>

### 6. Extract, replay, and explain

Evaluate the original symbol using the found state’s solver. Keep bytes as bytes; do not strip NULs or newlines unless the input contract says they are irrelevant. Replay on the same binary and check exit status plus the intended behavior. Save the binary hash, dependency versions, assumptions, and limits.

<a id="s24--a-short-analysis-record"></a>

### A short analysis record

For each run, record:

- Binary identity and architecture; source and compilation flags when available.

- Start state and initialized memory, globals, arguments, and file contents.

- Installed hooks and any concretization or loop restrictions.

- Success and avoidance criteria, with the address space stated explicitly.

- Search outcome, remaining stashes, errors, witness, and replay result.

[Reproduce and maintain an analysis](#s37) provides commands for collecting this evidence. The reference snippets in [Common operations](#s34) are intended to support this workflow, not substitute for its assumptions.

<a id="s24--source-trail"></a>

### Source trail

- [Gotchas](https://github.com/angr/angr/blob/v9.3.4/docs/advanced-topics/gotchas.rst).

- [Simulation manager search implementation](https://github.com/angr/angr/blob/v9.3.4/angr/sim_manager.py).


---

<a id="s25"></a>

<a id="s25--performance-and-search-limits"></a>

## [S25] Performance and search limits

Measure what is expensive before choosing a technique. A high state count, a huge expression in one state, and a slow external function are different problems. The same “optimization” can help one and harm another.

<a id="s25--a-useful-first-measurement"></a>

### A useful first measurement

Record elapsed time, peak memory, stash counts, executed blocks, and where states spend time. Restrict logging to the subsystem you are diagnosing. A callback that prints every memory event can become the largest cost itself. Repeated solver queries inside a find predicate can also dominate execution.

| Symptom | First change to try | What to check afterward |
|----|----|----|
| Many active paths | Restrict inputs to the real contract or try DFS. | Did you exclude valid inputs? Is work left deferred? |
| One state with huge formulas | Inspect symbolic loops, lengths, and memory indexes. | Does an exact smaller summary preserve the needed behavior? |
| Long library execution | Check which functions are hooked and which libraries loaded. | Does the summary implement side effects and failure cases? |
| Lots of irrelevant startup | Use a function harness with explicit context. | Are caller invariants and globals reconstructed? |
| Repeated equivalent paths | Consider a merge point or Veritesting. | Did larger conditional expressions increase solver time? |
| Large retained history | Release unused states and review history/action tracking. | Does the downstream analysis require the discarded information? |

<a id="s25--optimization-versus-restriction"></a>

### Optimization versus restriction

Avoiding irrelevant logging changes cost without changing the modeled program. Constraining an input length changes the input domain. Loop bounds exclude longer behaviors. Concretizing a symbolic value selects an assignment. Replacing code with a summary changes semantics unless the summary preserves the observations you need. State these distinctions in the analysis record.

<a id="s25--dfs-and-merging"></a>

### DFS and merging

DFS often reduces active memory use by exploring one path at a time, but other paths remain deferred. It may get stuck spending time on a long path before trying a short successful one. Merging exchanges multiple states for conditional expressions. For small branch-heavy arithmetic this may help; for difficult memory expressions it can make queries slower.

Veritesting is not a universal switch. It performs region-based reasoning that can interact with other exploration techniques and unusual control flow. Try it on a reproducible workload, compare witness replay, and keep a baseline run so a speedup does not conceal missing results.

<a id="s25--unicorn-acceleration"></a>

### Unicorn acceleration

Unicorn can accelerate suitable concrete execution when its optional backend is available and the engine’s entry conditions hold. Symbolic data and frequent transitions back to angr can eliminate the advantage. Enabling an option is not evidence that the workload actually used the engine; inspect its logs.

Concretization thresholds can force values to become concrete to stay in an accelerated mode. That discards alternatives and symbolic dependencies. Treat it as an explicit analysis restriction, not a transparent speed improvement. The course does not benchmark or validate Unicorn.

<a id="s25--timeouts-and-resource-limits"></a>

### Timeouts and resource limits

A manager step bound limits rounds, not time. Solver calls can take longer than expected inside a single round. An outer process timeout can stop a stuck run, but its outcome should be recorded as incomplete. Keep analysis inputs and logs outside the temporary process so you can reproduce the stopping point. A solver timeout also means “unknown,” not “unsatisfiable.”

<a id="s25--optimize-one-variable-at-a-time"></a>

### Optimize one variable at a time

Keep the binary, input domain, target condition, and machine fixed. Change one setting, measure, replay witnesses, and account for all stashes. This is more informative than enabling every technique from a cheatsheet at once.

<a id="s25--source-trail"></a>

### Source trail

- [Exploration techniques](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/__init__.py).

- [Unicorn execution](https://github.com/angr/angr/blob/v9.3.4/angr/engines/unicorn.py).

- [Veritesting technique](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/veritesting.py).


---

<a id="s26"></a>

<a id="s26--troubleshooting"></a>

## [S26] Troubleshooting

First decide whether the program failed to load, execution failed, the model had no successful path, or the recovered witness failed native replay. Those four outcomes call for different fixes.

<a id="s26--the-found-list-is-empty"></a>

### The found list is empty

Print stash counts and inspect every ErrorRecord. If active or deferred states remain, the search has unfinished work. If states are avoided, check whether your avoid addresses are too broad. If states deadend, inspect their exit paths and output. If execution errors, fix that before drawing a reachability conclusion. Lowering constraints indiscriminately can make a wrong model return an answer without fixing the original problem.

<a id="s26--the-address-looks-right-but-is-never-reached"></a>

### The address looks right but is never reached

Compare linked, relative, and rebased addresses. Check the exact binary hash and compiler flags. Verify that the address is an instruction boundary in an executable mapping. Inspect hooks at that location. On ARM, execution mode and Thumb address conventions also matter. A source line is not necessarily a single block address after compilation.

<a id="s26--the-solver-complains-about-a-boolean-conversion"></a>

### The solver complains about a Boolean conversion

Look for a Python `if symbolic_expression` or Python `and`/`or` joining symbolic conditions. Use Claripy logical operations to build a formula, then query satisfiability if the Python script itself needs a yes/no answer.

<a id="s26--the-solver-reports-incompatible-widths"></a>

### The solver reports incompatible widths

Check units first: bytes for memory length, bits for bitvectors. Then check register and C type widths. Extend deliberately with zero or sign extension; extract low bits only when truncation matches the machine operation. A Python integer constant is coerced into the surrounding bitvector width, which may wrap a value you expected to remain large.

<a id="s26--there-are-warnings-about-unconstrained-memory-or-registers"></a>

### There are warnings about unconstrained memory or registers

Identify the first read of the unspecified value. A direct function call may need a global pointer or a callee-saved register that the real caller supplies. A returned function may have no valid return address. Determine whether the value affects the target condition. Initialize relevant values instead of quieting all warnings with zero-fill options.

<a id="s26--a-state-is-in-unconstrained"></a>

### A state is in unconstrained

Inspect the symbolic instruction pointer and the history leading to it. Was a function return context missing? Was a pointer read from uninitialized memory? Is there an intentionally input-dependent indirect jump? Save these states when investigating control flow, but do not label them as a confirmed security issue without validating the cause and native behavior.

<a id="s26--the-answer-is-mostly-nul-bytes"></a>

### The answer is mostly NUL bytes

The solver only honors your constraints. If bytes are irrelevant on the found path, zero can be a valid witness. If you need printable characters or a C string, model that input domain explicitly. Do not post-process a witness with `strip` or decoding that drops bytes: it can change a valid input into a wrong one. Extract the original input expression from the found state.

<a id="s26--the-witness-fails-on-the-real-program"></a>

### The witness fails on the real program

Check the same binary and input framing first: argv versus stdin, trailing newline, EOF, file length, and encoding. Then inspect custom hooks, unresolved calls, symbolic globals, and skipped initializers. Compare a concrete angr run of the failing witness with the native run to find the first divergence. A difference may be an environment mismatch or a summary limitation rather than a solver bug.

<a id="s26--cfg-or-decompilation-is-incomplete"></a>

### CFG or decompilation is incomplete

Inspect unresolved indirect jumps and function boundaries. Try the small unstripped lab target to separate an installation issue from target complexity. Do not assume CFGEmulated will fix every missing edge. Decompiler output is reconstructed and may require better type or calling-convention information.

<a id="s26--the-script-is-old"></a>

### The script is old

Older examples use names such as `state.se`, `PathGroup`, `path_group`, or direct inspection attributes. Treat a historical script as a technique illustration. Port it against the installed release and validate its results. The current lab suite uses `state.solver` and `SimulationManager`.

<a id="s26--a-good-bug-report"></a>

### A good bug report

Include the smallest reproducer, exact package versions, platform and architecture, binary hash or a redistributable target, initial-state setup, complete exception, expected behavior, and actual behavior. Avoid a screenshot of only the final error: the state construction often explains the failure. The original C targets here can be modified to isolate many API questions.

<a id="s26--source-trail"></a>

### Source trail

- [Gotchas](https://github.com/angr/angr/blob/v9.3.4/docs/advanced-topics/gotchas.rst).

- [ErrorRecord and stash handling](https://github.com/angr/angr/blob/v9.3.4/angr/sim_manager.py).

- [Inspect compatibility handling](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/inspect.py).


---

<a id="s27"></a>

<a id="s27--data-flow-dependencies-and-slicing"></a>

## [S27] Data flow, dependencies, and slicing

A reachability search asks whether execution can reach an observation. Data-flow analysis asks which definitions can influence values at an observation. It is useful for understanding arguments, tracing computations, and deciding which part of a binary deserves a more expensive symbolic search.

<a id="s27--a-tested-reaching-definitions-example"></a>

### A tested reaching-definitions example

```python
"""Observe reaching definitions at each node of one small function."""
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from common import address, project

def analyze():
    p = project()
    cfg = p.analyses.CFGFast(normalize=True)
    function = cfg.kb.functions[address(p, "transform")]
    points = [("node", block_addr, OP_AFTER) for block_addr in function.block_addrs_set]
    result = p.analyses.ReachingDefinitions(subject=function, observation_points=points, dep_graph=True)
    assert result.observed_results
    assert result.dep_graph is not None
    return {"observations": len(result.observed_results),
            "definitions": result.dep_graph.graph.number_of_nodes(),
            "dependencies": result.dep_graph.graph.number_of_edges()}

if __name__ == "__main__":
    print(analyze())
```

Run `.venv/bin/python examples/analyze_dataflow.py`. The result contains positive counts for observation points, definitions, and dependencies. Exact counts depend on the lifted code. The test confirms that observations and a nonempty dependency graph are produced; it does not assert a whole-program data-flow proof.

The subject is a recovered function. Each observation point has a kind, an address, and a before/after operation marker. Here we observe after each recovered node. A node address is not interchangeable with an instruction address; use the matching observation kind. `dep_graph=True` requests a graph recording relationships among definitions.

<a id="s27--how-to-interpret-the-result"></a>

### How to interpret the result

A definition describes a write to an atom, such as a register or memory location, at a code location. Reaching definitions describe writes that may supply the value observed later. A dependency graph relates definitions through computations. These abstract values are not ordinary SimStates you can drop into a SimulationManager and execute.

Unknown values, aliases, merged flows, and function-call handling affect precision. A missing edge can reflect the analysis model, not the absence of a real dependency. Before extending to a large binary, test a small function where you know the expected relation between inputs and outputs.

<a id="s27--function-handlers-and-interprocedural-work"></a>

### Function handlers and interprocedural work

A function handler describes the effect of a call for reaching-definitions analysis. This is separate from a SimProcedure used by normal symbolic execution. A custom symbolic-execution hook does not automatically supply a correct abstract transfer function for every static analysis.

Start with a single function and selected observation points. Enable interprocedural handling only to the depth required by the question, and record the summaries or unknown-call policy. Observing every statement and tracking all liveness information can consume substantial memory.

<a id="s27--backward-slicing-useful-idea-fragile-historical-interface"></a>

### Backward slicing: useful idea, fragile historical interface

A backward slice starts at an observation and works toward computations or control decisions that influence it. A control dependence graph describes branch choices governing execution. A data dependence graph describes value flow. Neither is the same as a CFG.

The release’s `BackwardSlice` source still contains an explicit warning about engine-refactoring compatibility. The historical tutorial is therefore not presented as a tested, ready-to-run lab here. A source-oriented adaptation outline is:

```python
# Advanced outline: not executed by this handbook's test suite.
cfg = p.analyses.CFGEmulated(
    keep_state=True,
    state_add_options=angr.options.refs,
    context_sensitivity_level=1,
)
cdg = p.analyses.CDG(cfg)
ddg = p.analyses.DDG(cfg)
node = cfg.model.get_any_node(target_address)
if node is None:
    raise ValueError('Target absent from the recovered CFG')
result = p.analyses.BackwardSlice(
    cfg, cdg=cdg, ddg=ddg, targets=[(node, -1)]
)
```

This requires an existing project `p`, imported `angr`, and a verified target address. Saving states and reference actions is needed by this historical CFG/DDG route. The target statement index `-1` denotes the beginning of the node in this interface; it is not a machine-code line number. For a particular release and binary, verify that the analysis actually works and examine the result before relying on it. Reaching definitions is a tested starting point for the smaller data-flow question shown above.

<a id="s27--identifier-and-related-analyses"></a>

### Identifier and related analyses

Identifier attempts to recognize some common library functions from behavior and calling patterns, with a historical focus on CGC binaries. Its matches are analysis results to investigate, not universal proof of a function’s identity. Variable recovery, calling-convention recovery, propagation, and the decompiler can supply complementary information. Consult their release-specific APIs and regression tests when building a pipeline around them.

<a id="s27--source-trail"></a>

### Source trail

- [Reaching definitions](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/reaching_definitions/reaching_definitions.py).

- [Observation tests](https://github.com/angr/angr/blob/v9.3.4/tests/analyses/reaching_definitions/test_reachingdefinitions.py).

- [BackwardSlice compatibility warning](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/backward_slice.py).

- [Identifier scope](https://github.com/angr/angr/blob/v9.3.4/docs/analyses/identifier.rst).

<a id="s27--identifier-invocation-and-results"></a>

### Identifier invocation and results

For an appropriate CGC target, the official workflow invokes the analysis through the project hub. In 9.3.4, consume `run()` to perform recognition:

```python
project = angr.Project('cgc-target', auto_load_libs=False)
identification = project.analyses.Identifier()
for address, recognized_name in identification.run():
    print(hex(address), recognized_name)
```

`func_info` stores stack/argument information keyed by function objects; iterating it alone does not perform recognition. `matches` retains matched function objects and their recognized names/models after running the generator.

This fragment needs an external compatible target and is not executed by the local tests. Treat names as recognition results for inspection, not proof of full semantic equivalence. The [official Identifier chapter](#s62) preserves the original example.


---

<a id="s28"></a>

<a id="s28--intermediate-representations-and-execution-engines"></a>

## [S28] Intermediate representations and execution engines

angr separates decoding instructions, representing their effects, executing those effects, and deciding which paths to pursue. Understanding these layers helps locate a failure and choose the smallest extension that solves it.

<a id="s28--read-an-instruction-block"></a>

### Read an instruction block

Adaptation recipe on the local target:

```python
import angr
p = angr.Project('build/targets', auto_load_libs=False)
addr = p.loader.main_object.get_symbol('transform').rebased_addr
block = p.factory.block(addr)
print(block.capstone)
block.vex.pp()
print(block.vex.jumpkind)
print(block.vex.next)
```

Capstone provides disassembly. VEX gives an intermediate representation of register reads, arithmetic, memory accesses, and control-flow effects. A block is not a complete function, and one lifted block can contain several conditional exits before its final exit.

<a id="s28--a-small-vex-vocabulary"></a>

### A small VEX vocabulary

| Term | Read it as |
|----|----|
| `IMark` | Boundary marker for a machine instruction. |
| `GET` / `PUT` | Read/write the register file at an architecture-defined offset. |
| `WrTmp` / `RdTmp` | Define/read a temporary within this lifted block. |
| `Load` / `Store` | Read/write memory with an explicit type and byte order. |
| `Exit` | Conditional control-flow exit inside the block. |
| `next` | Target expression for the block’s final exit. |
| `jumpkind` | Kind of transfer, such as ordinary branch, call, return, or syscall. |

Temporaries are local to their IRSB. Register offsets refer to the guest architecture’s register layout, not process memory. Condition flags may be represented lazily using bookkeeping fields describing the previous operation; do not assume every flag is eagerly materialized after every instruction.

<a id="s28--the-execution-path-through-angr"></a>

### The execution path through angr

`SimulationManager.run` repeats `step`. The manager dispatches selected states through successor generation, normally via `Project.factory.successors`. The engine produces a SimSuccessors result; the manager converts that result into stashes and error records.

The default UberEngine combines mixins for failures, syscalls, hooks, optional concrete acceleration, inspection/action support, and IR execution. A mixin can handle a state or pass it along to the next implementation. Method resolution order matters: rearranging bases is not merely a performance setting.

<a id="s28--successors-before-stashes"></a>

### Successors before stashes

`flat_successors` contains ordinary successors with concrete instruction pointers after the engine resolves manageable target alternatives. `unsat_successors` contains impossible successors. `unconstrained_successors` contains overly broad symbolic control-flow targets. The manager decides whether and where to retain these lists. Thresholds and policies are implementation choices; do not build a proof around a historical magic number.

<a id="s28--vex-ail-and-p-code"></a>

### VEX, AIL, and P-code

VEX is the main machine-code IR used in these examples. AIL is useful for higher-level analysis and decompilation. P-code offers another lifting route for supported architectures and workflows. Support for lifting a particular instruction set is only one part of support for a complete binary: loader, calling convention, operating system, and required operations also matter.

<a id="s28--when-something-is-unsupported"></a>

### When something is unsupported

Check the bytes and address mapping first, then the lifter and operation, then the execution model. A decode error at an invalid return address is a state setup bug, not necessarily a missing instruction. A custom hook may be simpler than a custom engine when only one external operation needs modeling.

See also

[State and execution factories](#s16) for interface signatures and return values.

<a id="s28--source-trail"></a>

### Source trail

- [UberEngine composition](https://github.com/angr/angr/blob/v9.3.4/angr/engines/__init__.py).

- [Successor handling](https://github.com/angr/angr/blob/v9.3.4/angr/engines/successors.py).

- [Block representations](https://github.com/angr/angr/blob/v9.3.4/angr/block.py).

- [IR guide](https://github.com/angr/angr/blob/v9.3.4/docs/advanced-topics/ir.rst).


---

<a id="s29"></a>

<a id="s29--firmware-other-platforms-and-specialized-workflows"></a>

## [S29] Firmware, other platforms, and specialized workflows

The main labs deliberately use one platform to keep examples reproducible. angr’s wider ecosystem supports other loaders, architectures, and workflows, but support is a stack of capabilities rather than a single yes/no checkbox.

<a id="s29--raw-firmware-images"></a>

### Raw firmware images

Source-checked adaptation recipe, requiring your own `firmware.bin`:

```python
import angr
p = angr.Project(
    'firmware.bin',
    auto_load_libs=False,
    main_opts={
        'backend': 'blob',
        'arch': 'ARMEL',
        'base_addr': 0x08000000,
        'entry_point': 0x08000100,
    },
)
```

The addresses and architecture are illustrative and must come from the image format, board mapping, or independent reverse engineering. A reset vector may contain a pointer to code rather than code itself. Determine ARM versus Thumb mode explicitly. Initialize stack, RAM, globals, and memory-mapped peripherals as required by the function or startup path you analyze.

A blob mapping is not a board emulator. A polling loop on a hardware register will not become meaningful just because the instruction set lifts. Model the register’s behavior with bounded assumptions or a targeted summary, and record the hardware behavior the model leaves out. Mixed code/data images also need careful CFG scan boundaries and known function starts.

<a id="s29--pe-mach-o-and-different-abis"></a>

### PE, Mach-O, and different ABIs

Successful loading does not imply complete operating-system modeling. Imports, thread-local storage, exceptions, object initialization, and calling conventions can differ from the Linux lab. A Windows x64 integer argument does not use the same first register as a System V AMD64 argument. Use the correct SimCC and prototype instead of copying register assignments from another platform.

For C++ code, object pointers, vtables, constructors, exceptions, and mangled names introduce additional context. Begin with a function whose object state you can reconstruct, then expand the harness. Recovered decompiler types are helpful evidence but may need correction.

<a id="s29--java-and-android"></a>

### Java and Android

The upstream guide describes an experimental Soot-based route and extra components such as pysoot and Android platform libraries. Java/DEX analysis and mixed native/JNI execution have different state and dependency requirements from ELF machine-code analysis. No Java or Android target was executed for this edition. Read the matching source and examples, verify their dependencies in an isolated environment, and treat historical installation instructions as version-sensitive. See [Upstream example atlas](#scope).

<a id="s29--debug-information-and-source-variables"></a>

### Debug information and source variables

A binary built with suitable DWARF can expose source-level variable information. The upstream debug-variable workflow loads with `load_debug_info=True` and initializes `project.kb.dvars.load_from_dwarf()`. State variable lookup then depends on where execution currently is and the variable’s scope/location. Optimized-out values and complex location expressions can prevent recovery. This is an advanced source-checked workflow, not a tested lab here.

<a id="s29--concrete-traces-and-hybrid-execution"></a>

### Concrete traces and hybrid execution

Tracer-style techniques follow an external execution trace. Symbion-oriented workflows combine concrete process state with symbolic exploration. They need additional tools and a consistent mapping between trace/process addresses and the loaded project. Record the concrete input, process state, modules, and trace collection method. A trace describes the observed execution, not all possible paths through the binary.

For large parsers, a useful hybrid approach is to capture valid state after setup and explore a small symbolic input region. The hard part is preserving all relevant context. If a local function harness can answer the same question, it is usually easier to reproduce than a live-process integration.

<a id="s29--command-line-tools-and-gui"></a>

### Command-line tools and GUI

The pinned release includes a CLI with decompile and disassemble commands. Inspect the installed interface with:

```console
$ .venv/bin/python -m angr --help
$ .venv/bin/python -m angr decompile --help
```

The top-level help was checked for this edition. The Python labs remain the validated analysis interface. angr-management is a separate GUI project for interactive exploration; it is not required to read or run this handbook.

<a id="s29--source-trail"></a>

### Source trail

- [Java support scope](https://github.com/angr/angr/blob/v9.3.4/docs/advanced-topics/java_support.rst).

- [Debug variables](https://github.com/angr/angr/blob/v9.3.4/docs/advanced-topics/debug_var.rst).

- [CLI entry point](https://github.com/angr/angr/blob/v9.3.4/angr/__main__.py).

- [Tracer technique](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/tracer.py).

For source-variable lookup and shadowing, see [Debug information and variable visibility](#s14).


---

<a id="s30"></a>

<a id="s30--extension-interfaces"></a>

## [S30] Extension interfaces

angr is designed to be extended, but not every extension belongs in the execution engine. Pick the narrowest layer that can express the behavior.

| Requirement | Extension point |
|----|----|
| Replace one function’s behavior | SimProcedure or a carefully scoped user hook. |
| Observe an execution event | SimInspect callback. |
| Retain per-path data through forks | State plugin. |
| Change path scheduling or classification | ExplorationTechnique. |
| Compute a reusable project-level result | Analysis subclass. |
| Model a file provider or operating system | Filesystem mount or SimOS extension. |
| Support a new instruction execution mechanism | Lifter/engine integration, after ruling out a simpler model. |

<a id="s30--a-tested-custom-analysis"></a>

### A tested custom analysis

```python
"""A registered analysis returning useful, deterministic function sizes."""
import angr
from angr.analyses import AnalysesHub
from common import address, project

class FunctionSizes(angr.Analysis):
    def __init__(self):
        cfg = self.project.analyses.CFGFast(normalize=True)
        self.result = {function.addr: sum(block.size for block in function.blocks)
                       for function in cfg.kb.functions.values()
                       if self.project.loader.main_object.contains_addr(function.addr)}

AnalysesHub.register_default("HandbookFunctionSizes", FunctionSizes)

def analyze():
    p = project()
    result = p.analyses.HandbookFunctionSizes()
    return result.result[address(p, "check")]

if __name__ == "__main__":
    print("Recovered bytes in check:", analyze())
```

The analysis recovers functions and counts the bytes in their recovered blocks. Registration makes it available through the project’s analysis hub. The hub provides `self.project` before the analysis constructor runs. Its result is an ordinary address-to-size mapping; the caller decides how to use it.

Run `.venv/bin/python examples/custom_analysis.py`. The test verifies a positive recovered size for `check`. This is the size of recovered blocks, not necessarily the exact original source function’s allocation. Shared tails, misidentified boundaries, and overlapping recovery can affect such metrics.

<a id="s30--a-source-checked-exploration-technique-recipe"></a>

### A source-checked exploration technique recipe

```python
import angr

class DepthBudget(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, maximum):
        super().__init__()
        self.maximum = maximum

    def filter(self, simgr, state, **kwargs):
        if state.history.depth > self.maximum:
            return 'over_budget'
        return simgr.filter(state, **kwargs)

# manager.use_technique(DepthBudget(200))
```

This recipe demonstrates the delegation contract; it is not a separately tested course lab. Calling `simgr.filter` delegates to the next hook or original implementation through angr’s technique mechanism. Omitting delegation can bypass other techniques. The custom stash preserves evidence that work was excluded; it should be included in the final run report.

`complete` differs from these chained hooks: it returns the technique’s own completion decision, rather than recursively calling `simgr.complete`. Technique ordering and completion mode matter when combining strategies.

<a id="s30--analysis-resilience"></a>

### Analysis resilience

The Analysis infrastructure can collect some failures so an analysis returns partial results. That is useful when processing many functions, but callers must inspect errors and named errors if completeness matters. During debugging, use the supported fail-fast behavior to expose the first failure. Do not silently turn exceptions into empty successful results in a custom wrapper.

<a id="s30--develop-against-a-coherent-release"></a>

### Develop against a coherent release

Keep the relevant angr ecosystem repositories on compatible versions. Use small regression targets that exercise the behavior you changed. A test that only checks “did not crash” is insufficient for a summary: compare return values and side effects across representative inputs, including errors. For a state plugin, test independent copying and merging; for a technique, test both found results and the work it intentionally excludes.

<a id="s30--custom-engines-and-mixins"></a>

### Custom engines and mixins

Read the current UberEngine class and its method resolution order. Removing a mixin can remove inspection, action tracking, resilience, or syscall behavior that another analysis relies on. Validate both execution and any metadata used by downstream consumers. [Intermediate representations and execution engines](#s28) gives a map of the layers.

<a id="s30--source-trail"></a>

### Source trail

- [Analysis hub](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/analysis.py).

- [Technique hook contract](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/base.py).

- [Engine composition](https://github.com/angr/angr/blob/v9.3.4/angr/engines/__init__.py).


---

<a id="s31"></a>

<a id="s31--library-syscall-and-operating-system-models"></a>

## [S31] Library, syscall, and operating-system models

An environment extension supplies behavior outside the analyzed instructions. Choose the registration mechanism according to whether the operation is an imported function, a syscall, an OS setup rule, or an imported data object. Function models use [Hooks and SimProcedures](#s10) and must describe side effects as well as return values.

<a id="s31--library-catalogues-and-library-definitions"></a>

### Library catalogues and library definitions

`angr.SIM_PROCEDURES` groups procedure classes by interface catalogue, such as `libc` or `posix`. A catalogue is not a loaded library. A `SimLibrary` associates implementations and metadata with actual library names. Entries in `angr.SIM_LIBRARIES` are lists of library definitions, indexed by name.

For an extension that should affect new projects, register the procedure class with the relevant library **before constructing the project**:

```python
# MyProcedure is an angr.SimProcedure subclass defined by the application.
angr.SIM_LIBRARIES['libc.so.6'][0].add('my_function', MyProcedure)
project = angr.Project('program', auto_load_libs=False)
```

This changes a process-wide library definition; use it deliberately. Adding a class to `SIM_PROCEDURES` after libraries were initialized does not update libraries that already copied that catalogue. For one project, prefer `project.hook_symbol('my_function', MyProcedure())` after loading.

In an angr development checkout, implementations belong to the relevant `angr/procedures/<catalogue>` directory. Library-definition files in `angr/procedures/definitions` create library instances and register names, prototypes, and implementations. A new model needs tests for calling convention, return value, memory changes, and failure paths.

<a id="s31--syscall-dispatch"></a>

### Syscall dispatch

A syscall instruction ends execution with a syscall jump kind. SimOS chooses the ABI and syscall number and obtains a procedure from its `SimSyscallLibrary`. Hooking a function symbol does not replace this dispatch. Syscall libraries map numbers to names separately for each ABI; overlapping numbers in different ABIs must not be conflated.

For an existing userland project with a syscall library, a project-local replacement is:

```python
project.simos.syscall_library.add('read', MyReadProcedure)
```

The name must correspond to the applicable syscall mapping and the replacement must implement the syscall’s ABI and behavior. The library is copied during project setup, so this is distinct from modifying the global registration. A kernel-object address identifies a syscall in traces; `project.simos.is_syscall_addr(address)` and `project.simos.syscall_from_addr(address)` interpret it. These identifying addresses are not ordinary procedure hooks.

<a id="s31--new-operating-systems"></a>

### New operating systems

An OS model with syscalls derives from `angr.simos.userland.SimUserland`. Its constructor supplies a syscall library; project configuration supplies the supported ABI list. Override `syscall_abi(state)` when instruction context is needed to choose the ABI. Syscall calling conventions provide the syscall number extraction in addition to argument and return locations.

Register a model with `angr.simos.register_simos(os_name, ModelClass)` before loading, or pass the class explicitly with `angr.Project(..., simos=ModelClass)`. The model must also establish process entry state, stack layout, and other OS assumptions. Registering the class alone does not implement these behaviors.

<a id="s31--imported-data"></a>

### Imported data

An unresolved data symbol requires storage layout and initial content, not a function return stub. When a real dependency is loaded, relocation may resolve it normally. Otherwise CLE’s `SimData` interface can describe its size, content, relocations, and dependencies. Warnings about an external symbol with unknown size are relevant if the program dereferences it. Suppressing the warning does not provide a data model.

These are extension recipes, not a runnable new OS implementation. The complete [official environment chapter](#s82) contains the registration details and source references.


---

<a id="s32"></a>

<a id="s32--developing-angr-and-reporting-problems"></a>

## [S32] Developing angr and reporting problems

Developing this documentation and contributing to angr are separate workflows. For documentation builds, see [Building the documentation](#scope). An angr contributor needs a development environment for the code being changed, a reproducible test, and the contribution rules of the target repository.

<a id="s32--development-environment"></a>

### Development environment

Keep angr and its companion repositories on compatible revisions. The official `angr-dev` repository provides a development setup workflow. Read its current instructions before running installation scripts. For a focused Python-only change, an isolated environment and an editable install of the appropriate checkout may suffice; native components still need their build dependencies. Avoid mixing a development checkout with unrelated installed dependency versions.

```console
$ python3.12 -m venv .venv
$ .venv/bin/python -m pip install -e /path/to/angr-checkout
```

This example assumes dependencies appropriate to the checkout can be resolved. It is not a replacement for the upstream multi-repository installation guide. Check `angr.__file__` to verify imports refer to the intended checkout.

<a id="s32--a-useful-regression-case"></a>

### A useful regression case

Reduce the problem to a small binary or instruction sequence and a short Python script. State what should happen and what actually happens. A good regression test asserts the relevant semantics: a recovered function, a feasible input, a register value, a memory side effect, or a specific error. Include an error case when a procedure handles failures. For symbolic summaries, replay feasible witnesses against the real implementation where possible.

Run the relevant upstream tests and repository-required checks before submitting a change. The tests in this documentation validate its examples, not angr’s entire implementation. Consult repository instructions for formatting, test layout, and contributor requirements rather than inferring them from this site.

<a id="s32--issue-reports"></a>

### Issue reports

Include the package versions, Python and OS details, the minimal script, exact exception/traceback, loader options, state construction, and expected outcome. If possible, provide source and build instructions for a redistributable target. Record the binary identity and relevant addresses. Explain whether a failure is in loading, lifting, simulation, solving, or analysis recovery. Removing the exception or replacing unknown values with zero is not evidence of a fix.

Do not attach a confidential binary merely because it reproduces the issue; reduce it to a shareable target. Search existing issues before opening a new one. For conceptual questions, use the support channels linked by the project.

<a id="s32--upstream-references"></a>

### Upstream references

- [Official development instructions](#s86).

- [Contribution opportunities](#s87).

- [Support and citation information](#s89).

- [angr-dev](https://github.com/angr/angr-dev).


---

<a id="s33"></a>

<a id="s33--options-and-search-controls"></a>

## [S33] Options and search controls

Use named options from `angr.options`. An uppercase option is usually one setting; lowercase bundles such as `refs` or `unicorn` are sets. Some settings live on plugins or constructors instead of in the option set.

Source-checked configuration patterns:

```python
state = p.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
state.options.add(angr.options.TRACK_MEMORY_ACTIONS)
state.options.discard(angr.options.TRACK_MEMORY_ACTIONS)
state.options.update(angr.options.refs)
```

These statements illustrate configuration, not a recommended bundle. A memory tracking option has a cost, and a downstream analysis may require it to be present before execution starts.

<a id="s33--options-you-are-likely-to-encounter"></a>

### Options you are likely to encounter

| Option or bundle | Intended effect | Interpretation risk |
|----|----|----|
| `LAZY_SOLVES` | Delay some satisfiability checks. | Impossible paths may be explored until later pruning. |
| `ZERO_FILL_UNCONSTRAINED_MEMORY` | Use zero for otherwise unspecified memory. | Replaces an unknown with an assumption. |
| `ZERO_FILL_UNCONSTRAINED_REGISTERS` | Use zero for otherwise unspecified registers. | Can conceal a missing caller context. |
| `SYMBOL_FILL_UNCONSTRAINED_MEMORY` | Explicitly permit symbolic fills without the usual warning. | Quiet logs do not validate the memory model. |
| `SYMBOL_FILL_UNCONSTRAINED_REGISTERS` | Explicitly permit symbolic register fills. | The target may gain unrealistic freedoms. |
| `SYMBOLIC_WRITE_ADDRESSES` | Enable broader symbolic-write handling in the memory policy. | Bounded strategies and fallback behavior still matter. |
| `CONSERVATIVE_READ_STRATEGY` / `CONSERVATIVE_WRITE_STRATEGY` | Avoid some forced single-address fallback behavior. | The resulting approximation still needs interpretation. |
| `TRACK_MEMORY_ACTIONS` / `TRACK_REGISTER_ACTIONS` | Record corresponding state actions. | More metadata and memory use; not a complete trace by itself. |
| `refs` | Bundle reference/action tracking settings for relevant analyses. | May significantly increase cost. |
| `UNICORN` / `unicorn` | Request optional concrete acceleration and related settings. | Availability and execution conditions determine whether it runs. |
| `UNICORN_THRESHOLD_CONCRETIZATION` | Allow threshold-driven concretization for acceleration. | Excludes symbolic alternatives and dependencies. |
| `BYPASS_UNSUPPORTED_SYSCALL` | Continue through some unsupported syscall cases. | Can replace missing behavior with an approximation. |
| `CALLLESS` | Avoid ordinary call execution using unconstrained return behavior. | Omits callee side effects; changes semantics. |
| `FILES_HAVE_EOF` | Control finite-end behavior for applicable file creation paths. | Prefer explicit `has_end` for important input storage. |
| `SHORT_READS` | Permit modeled reads shorter than requested in applicable storage. | Changes possible input framing. |

<a id="s33--not-state-options"></a>

### Not state options

`auto_load_libs` belongs to loading. `save_unsat` and `save_unconstrained` belong to the SimulationManager configuration. `find`, `avoid`, `num_find`, and `n` control a search invocation. LoopSeer’s `bound` belongs to that technique. A `SimFile` has its own `size` and `has_end` behavior. Mixing these layers can produce a setting that never affects the part of the analysis you intended to change.

<a id="s33--defaults-can-change"></a>

### Defaults can change

Read the pinned release’s option definitions and the code that consumes an option. An option’s existence does not guarantee that every engine, memory model, or SimProcedure honors it identically. The tested course intentionally uses a small number of explicit choices rather than a large “fast mode” set.

<a id="s33--source-trail"></a>

### Source trail

- [Option declarations and bundles](https://github.com/angr/angr/blob/v9.3.4/angr/sim_options.py).

- [Option set implementation](https://github.com/angr/angr/blob/v9.3.4/angr/sim_state_options.py).

- [Default memory filling](https://github.com/angr/angr/blob/v9.3.4/angr/storage/memory_mixins/default_filler_mixin.py).

The full preserved upstream mode, bundle, and option tables are accessible from [Operation and state-option catalogues](#scope).


---

<a id="s34"></a>

<a id="s34--common-operations"></a>

## [S34] Common operations

These are short adaptation fragments, not complete standalone programs. The full tested versions live in the tutorials. Names such as `p`, `state`, `manager`, `address`, and `target` refer to objects you have already created or verified; replace them deliberately.

<a id="s34--load-an-executable-and-find-a-defined-symbol"></a>

### Load an executable and find a defined symbol

```python
import angr
import claripy
p = angr.Project('build/targets', auto_load_libs=False)
symbol = p.loader.main_object.get_symbol('check')
if symbol is None:
    raise ValueError('Symbol not available')
address = symbol.rebased_addr
```

Use a rebased address inside angr. A file offset needs a mapping conversion.

<a id="s34--a-finite-symbolic-stdin-prefix"></a>

### A finite symbolic stdin prefix

```python
data = claripy.BVS('data', 8 * 16)
state = p.factory.full_init_state(
    stdin=angr.SimFileStream(name='stdin', content=data, has_end=True)
)
```

This models exactly sixteen bytes. Append a concrete newline if the real input is a sixteen-byte line plus a newline, rather than silently assuming newline behavior is handled by the stream constructor.

<a id="s34--constrain-a-format"></a>

### Constrain a format

```python
for byte in data.chop(8):
    state.solver.add(byte >= ord('A'), byte <= ord('Z'))
```

The restriction is an assumption about your input domain. It can exclude a valid witness if the program also accepts punctuation or binary bytes.

<a id="s34--run-and-inspect-all-result-categories"></a>

### Run and inspect all result categories

```python
manager = p.factory.simulation_manager(state, save_unconstrained=True)
manager.explore(find=target, avoid=failure, n=500)
print({name: len(items) for name, items in manager.stashes.items()})
print([str(record.error) for record in manager.errored])
if not manager.found:
    raise RuntimeError('No witness under this model and search budget')
candidate = manager.found[0].solver.eval(data, cast_to=bytes)
```

`target` and `failure` must be verified addresses or Python predicates. Five hundred is a manager-step limit, not seconds or instructions.

<a id="s34--a-possible-versus-necessary-condition"></a>

### A possible versus necessary condition

```python
feasible = state.solver.satisfiable()
possible = state.solver.satisfiable(extra_constraints=(condition,))
necessary = feasible and not state.solver.satisfiable(
    extra_constraints=(claripy.Not(condition),)
)
```

The feasibility guard avoids interpreting inconsistent constraints as evidence of a meaningful necessary property.

<a id="s34--enumerate-correlated-bytes-together"></a>

### Enumerate correlated bytes together

```python
pairs_as_bytes = state.solver.eval_upto(
    claripy.Concat(first_byte, second_byte), 10, cast_to=bytes
)
```

Each two-byte result is one consistent assignment. Ten results do not establish that there are only ten possibilities. Retain the full original input expression when other fields also need to stay correlated.

<a id="s34--load-and-store-a-native-integer"></a>

### Load and store a native integer

```python
state.memory.store(pointer, claripy.BVV(123, 32), endness=p.arch.memory_endness)
number = state.memory.load(pointer, 4, endness=p.arch.memory_endness)
```

`pointer` must designate valid initialized storage for the model. The load size is four bytes; the bitvector width is 32 bits.

<a id="s34--resume-a-found-state-for-a-later-stage"></a>

### Resume a found state for a later stage

```python
manager.move(from_stash='found', to_stash='active')
manager.explore(find=second_target, n=200)
```

Check other active states before doing this if only the first-stage winners should continue. A fresh manager seeded with those winners makes that choice explicit. Moving a stash does not add any new semantic constraint by itself.

<a id="s34--change-exploration-order"></a>

### Change exploration order

```python
manager.use_technique(angr.exploration_techniques.DFS())
```

Deferred states still represent unfinished work. Use [Performance and search limits](#s25) to decide whether DFS addresses your bottleneck.

<a id="s34--list-recovered-calls"></a>

### List recovered calls

```python
cfg = p.analyses.CFGFast(normalize=True)
function = cfg.kb.functions[address]
for site in function.get_call_sites():
    print(hex(site), function.get_call_target(site))
```

Sites are recovered call-block addresses. A target may be unresolved; do not assume that every call is direct or that the CFG is complete.

<a id="s34--keep-an-immutable-trace-in-a-state"></a>

### Keep an immutable trace in a state

```python
state.globals['events'] = state.globals.get('events', ()) + ('observed',)
```

Reassignment of a tuple avoids mutating a list shared through a shallow copy. For large traces or merging semantics, use a state plugin.

<a id="s34--source-trail"></a>

### Source trail

- [Manager API](https://github.com/angr/angr/blob/v9.3.4/angr/sim_manager.py).

- [Solver API](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/solver.py).

- [Function API](https://github.com/angr/angr/blob/v9.3.4/angr/knowledge_plugins/functions/function.py).


---

<a id="s35"></a>

<a id="s35--glossary"></a>

## [S35] Glossary

<a id="s35--term-ABI"></a>

**ABI**

The binary-level agreement covering calling conventions, type sizes, layout, and other platform behavior.

<a id="s35--term-AST"></a>

**AST**

An abstract syntax tree representing an expression. Claripy ASTs describe concrete or symbolic values and are immutable.

<a id="s35--term-Basic-block"></a>

**Basic block**

A unit of machine code with structured entry and exit behavior. A lifted VEX IRSB can include several conditional exits.

<a id="s35--term-Bitvector"></a>

**Bitvector**

A fixed-width sequence of bits. Arithmetic wraps at its width; signed and unsigned operations can interpret the same bits differently.

<a id="s35--term-Calling-convention"></a>

**Calling convention**

Rules for passing arguments and returns and preserving registers across calls. A function prototype describes types, not register locations.

<a id="s35--term-CFG"></a>

**CFG**

Control-flow graph: recovered code nodes and possible transfers between them. A graph path need not be feasible under program constraints.

<a id="s35--term-CLE"></a>

**CLE**

angr’s loader library, responsible for executable objects and mappings.

<a id="s35--term-Claripy"></a>

**Claripy**

angr’s expression and solver library, with multiple frontends/backends.

<a id="s35--term-Concrete"></a>

**Concrete**

A value whose bits are fixed for the modeled execution.

<a id="s35--term-Concretization"></a>

**Concretization**

Selecting concrete possibilities for a symbolic expression, often an address. A restrictive selection can discard behaviors.

<a id="s35--term-Constraint"></a>

**Constraint**

A Boolean formula limiting allowed assignments to symbolic values.

<a id="s35--term-Deadended-state"></a>

**Deadended state**

A state with no continuing successors in the current model; often a terminated path, but not inherently a successful one.

<a id="s35--term-Definition"></a>

**Definition**

A write to an analyzed atom at a code location, used by data-flow analyses.

<a id="s35--term-Found-state"></a>

**Found state**

A state matching the search’s success condition. Its meaning depends on that condition and the model, not on the stash name alone.

<a id="s35--term-Hook"></a>

**Hook**

A replacement or instrumentation attached to a guest code address.

<a id="s35--term-Initial-state"></a>

**Initial state**

The registers, memory, environment, and constraints from which analysis begins. It defines the starting assumptions.

<a id="s35--term-Knowledge-base"></a>

**Knowledge base**

Project-associated recovered information such as functions, CFG models, and variables. It is different from a single machine state.

<a id="s35--term-Native-replay"></a>

**Native replay**

Executing a concrete witness on the compiled target to check the behavior outside the symbolic model.

<a id="s35--term-Path-explosion"></a>

**Path explosion**

Rapid growth in the number of paths requiring separate consideration.

<a id="s35--term-PIE"></a>

**PIE**

Position-independent executable. Use the loader’s rebased addresses.

<a id="s35--term-Predicate"></a>

**Predicate**

A condition. A manager callback must return an actual Python Boolean; a symbolic predicate is a Claripy formula that may need solving.

<a id="s35--term-SimProcedure"></a>

**SimProcedure**

A function-level model implemented in Python, integrated with the target calling convention and angr state.

<a id="s35--term-SimState"></a>

**SimState**

The simulated machine configuration, including constraints and plugins.

<a id="s35--term-Stash"></a>

**Stash**

A named list of states managed by a SimulationManager.

<a id="s35--term-Symbolic"></a>

**Symbolic**

Represented by expressions over values not yet fixed to one assignment.

<a id="s35--term-Unconstrained-successor"></a>

**Unconstrained successor**

A successor with an overly broad symbolic instruction pointer under the engine’s control-flow policy. Not synonymous with symbolic input.

<a id="s35--term-Unsatisfiable"></a>

**Unsatisfiable**

No assignment satisfies the constraints. A timeout is not this result.

<a id="s35--term-VEX-AIL-P-code"></a>

**VEX / AIL / P-code**

Intermediate representations used in lifting, analysis, or execution. Their roles and supported workflows differ.

<a id="s35--term-Witness"></a>

**Witness**

A concrete input satisfying a stated model-level condition. Replay tests whether it produces the expected real behavior.


---

<a id="s36"></a>

<a id="s36--version-migration-and-historical-changes"></a>

## [S36] Version migration and historical changes

This project targets angr 9.3.4. Older examples can express valid analysis ideas using interfaces that have since changed. Port the setup, types, and result handling before interpreting an old script’s failures as an analysis limitation. Keep the old environment available when comparing behavior.

<a id="s36--angr-9-1-calling-conventions-and-prototypes"></a>

### angr 9.1: calling conventions and prototypes

Function prototypes specify argument and return types; calling conventions specify their machine locations. The 9.1 refactor made types central to the calling-convention interface. Use `SimCCUsercall` when argument/return locations need explicit customization rather than passing old customization arguments to `SimCC`. Typed SimCC operations take SimTypes instead of the older `is_fp` and `size` parameters.

Pass an explicit `prototype` to function-call interfaces. The older name `func_ty` became `prototype`. A return type can affect argument placement, including ABIs that return a large structure through an implicit pointer. When `PointerWrapper` should serialize a buffer of child elements, specify `buffer=True` rather than relying on scalar interpretation.

See [Solve a function return value](#s41) and the complete [9.1 migration notes](#s67).

<a id="s36--angr-8-python-3-and-loader-interfaces"></a>

### angr 8: Python 3 and loader interfaces

Program bytes use Python `bytes`; names and labels use text strings. Use `cast_to=bytes` when extracting input data. Indexing a byte string returns an integer. Avoid silently encoding arbitrary binary content as Unicode. Use `state.solver` rather than the historical `state.se` alias.

CLE’s loader memory is distinct from simulated state memory. Historical `read_bytes`/`write_bytes` become `load`/`store`; word operations use `unpack_word`/`pack_word`. Enumerate symbols using the supported symbol collections. Historical loader option names beginning with `custom_` lost that prefix. These changes require more than renaming Python imports.

The [full 8 migration notes](#s66) include byte conversions, memory backers, symbol lookup, and removed interfaces.

<a id="s36--angr-7-simulation-and-state-organization"></a>

### angr 7: simulation and state organization

The old SimuVEX split was removed. Historical Path/PathGroup code needs to be ported to state-based simulation and SimulationManager operations; blindly substituting class names misses history and successor changes. Start from a current state factory and explicitly inspect the resulting manager stashes. See the [full 7 migration notes](#s65).

<a id="s36--changelog-boundaries"></a>

### Changelog boundaries

The [preserved upstream changelog](#s63) is historical documentation shipped in the pinned source. It is not a promise that every change through the present day is listed. For a later upgrade, review that release’s source changes and run the local examples under the new version. Build a version-specific compatibility record rather than relabeling these 9.3.4 results as validation of a newer release.


---

<a id="s37"></a>

<a id="s37--reproduce-and-maintain-an-analysis"></a>

## [S37] Reproduce and maintain an analysis

A useful result is one you or a colleague can rerun. Preserve the target, assumptions, versions, and checks together rather than saving only the final input string.

<a id="s37--capture-the-environment"></a>

### Capture the environment

From the repository root:

```console
$ .venv/bin/python --version
$ .venv/bin/python -m pip freeze
$ cc --version
$ sha256sum build/targets build/targets-pie
$ git log --oneline
$ make verify
```

The full dependency lock file already records this edition’s resolution. A build with a different compiler may legitimately produce different addresses and pseudocode. The important invariant is that the solver analyzes and replays the same executable for that run.

<a id="s37--tests-should-check-the-claim"></a>

### Tests should check the claim

A witness test should run the real target and assert the intended output or behavior, not only compare a solver result to a hardcoded string. A function summary should be checked against the original operation over a meaningful input set. CFG tests should assert structural facts rather than incidental node counts unless the exact graph is the claim under test.

The course’s tests include rejection as well as acceptance. They also run the stdin solver on a PIE build to catch address-handling mistakes. Doctests check small semantic examples such as integer wraparound and memory byte order.

<a id="s37--keep-generated-artifacts-out-of-source-commits"></a>

### Keep generated artifacts out of source commits

The project ignores virtual environments, native builds, caches, and Sphinx output. Commit explanations, C sources, scripts, tests, and dependency pins. Regenerate HTML with `make html`. Use `make clean` only when you intend to remove the generated `build` and `_build` directories.

<a id="s37--updating-angr"></a>

### Updating angr

Create an update branch, change the direct pins and lock file, rebuild the local targets, and run the full verification suite. Review source-linked behavior that the tests do not cover, especially optional backends and advanced analysis interfaces. Record any changed defaults or migration steps in the coverage and validation pages. A successful package installation alone is not an API compatibility test.

<a id="s37--when-a-regression-appears"></a>

### When a regression appears

Reduce the target and inputs until the difference is understandable. Compare old and new runs with the same binary. Separate solver-answer differences from semantic differences: two distinct witnesses may both be correct when the input is not unique. Use a joint evaluation or an explicit uniqueness check when that distinction matters.

<a id="s37--reproduce-external-examples-carefully"></a>

### Reproduce external examples carefully

The example atlas links to a recorded upstream revision. Historical scripts may assume old package versions, working directories, optional tools, or challenge binaries. Port the API calls in a separate checkout and keep a note of each assumption changed. The downloaded upstream material was used for research; its challenge binaries were not executed as part of this handbook’s validation.

<a id="s37--source-trail"></a>

### Source trail

- [Project metadata](https://github.com/angr/angr/blob/v9.3.4/pyproject.toml).

- [Upstream development guide](https://github.com/angr/angr/blob/v9.3.4/docs/getting-started/developing.rst).


---

<a id="s38"></a>

<a id="s38--find-an-input-and-prove-it-works"></a>

## [S38] Find an input and prove it works

**Question:** Which four stdin bytes make the target accept?

**Prerequisites:** [Installation](#s01) and [Architecture and object model](#s03). **Tested:** complete solver, fixed-address target, PIE target, and native replay.

<a id="s38--the-target"></a>

### The target

The `check` function accepts exactly `CAT!`. Knowing the answer lets us verify the analysis while learning the mechanics. `main` reads exactly four bytes from stdin, calls `check`, and dispatches to `win` or `lose`. The same target supports later argv, file, and function labs.

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Original teaching target; no third-party challenge binary is required. */
__attribute__((noinline)) int check(const unsigned char *p) {
    if (p[0] != 'C') return 0;
    if (p[1] != 'A') return 0;
    if (p[2] != 'T') return 0;
    if (p[3] != '!') return 0;
    return 1;
}
__attribute__((noinline)) uint32_t transform(uint32_t x) {
    return (x * 3u) ^ 0x55u;
}
__attribute__((noinline)) int score(unsigned int n) {
    unsigned int sum = 0;
    for (unsigned int i = 0; i < n; ++i) sum += i;
    return sum == 6;
}
__attribute__((noinline)) void win(void) { puts("ACCEPT"); }
__attribute__((noinline)) void lose(void) { puts("REJECT"); }

int main(int argc, char **argv) {
    unsigned char p[4] = {0};
    if (argc == 3 && strcmp(argv[1], "number") == 0) {
        printf("%u\n", transform((uint32_t)strtoul(argv[2], NULL, 10)));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "file") == 0) {
        FILE *f = fopen(argv[2], "rb");
        if (!f) return 2;
        size_t n = fread(p, 1, 4, f);
        fclose(f);
        if (n != 4) return 2;
    } else if (argc == 2) {
        if (strlen(argv[1]) != 4) return 2;
        memcpy(p, argv[1], 4);
    } else {
        if (read(0, p, 4) != 4) return 2;
    }
    if (check(p)) { win(); return 0; }
    lose();
    return 1;
}
```

Compile it with `make examples`. The helper uses no optimization and keeps symbols for teaching. Turning off PIE in one target makes disassembly easier to compare, while a second PIE build tests that our address lookup is robust. The target is intentionally a small teaching program, not a production build configuration recommendation.

<a id="s38--the-complete-solver"></a>

### The complete solver

```python
"""Find a four-byte stdin witness and replay it on the original target."""
import subprocess
import angr
import claripy
from common import BINARY, project, search

def solve(binary=BINARY):
    p = project(binary)
    token = claripy.BVS("token", 4 * 8)
    stream = angr.SimFileStream(name="stdin", content=token, has_end=True)
    initial = p.factory.full_init_state(args=[str(binary)], stdin=stream)
    winner = search(p, initial)
    candidate = winner.solver.eval(token, cast_to=bytes)
    replay = subprocess.run([str(binary)], input=candidate, capture_output=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout == b"ACCEPT\n", replay
    return candidate

if __name__ == "__main__":
    print(repr(solve()))
```

Run from the repository root:

```console
$ .venv/bin/python examples/solve_stdin.py
b'CAT!'
```

Logging may appear before the final result. The assertion checks the actual native process, not the logger output.

<a id="s38--why-each-choice-matters"></a>

### Why each choice matters

`BVS("token", 4 * 8)` creates 32 unknown bits. Its name is a label for an expression, not a variable in the C source. angr discovers the connection between these bits and `check` by executing the compiled instructions.

`SimFileStream(..., has_end=True)` makes stdin a finite four-byte stream. Without a defined end, a later read could introduce more unknown bytes. We use `full_init_state` so modeled initializers run before normal process entry. It still uses angr’s environment model; it does not launch a real OS process.

`search` advances the manager until a state reaches `win`, avoiding states that reach `lose`. It limits the number of manager steps and gives a useful failure message instead of blindly indexing an empty `found` list.

```python
"""Small shared utilities; each tutorial explains the relevant calls."""
from pathlib import Path
import angr

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build/targets"

def project(binary=BINARY):
    if not Path(binary).is_file():
        raise FileNotFoundError("Build targets first: make examples")
    return angr.Project(str(binary), auto_load_libs=False)

def address(p, name):
    symbol = p.loader.main_object.get_symbol(name)
    if symbol is None:
        raise ValueError(f"Missing symbol {name!r}; use the unstripped lab binary")
    return symbol.rebased_addr

def search(p, state, steps=250):
    manager = p.factory.simulation_manager(state, save_unconstrained=True)
    manager.explore(find=address(p, "win"), avoid=address(p, "lose"), n=steps)
    if not manager.found:
        errors = [str(record.error) for record in manager.errored]
        counts = {name: len(states) for name, states in manager.stashes.items()}
        raise RuntimeError(f"No witness within {steps} steps: {counts}; errors={errors}")
    return manager.found[0]
```

The helper obtains `rebased_addr` from symbols in the main object. These are the addresses angr uses after loading, so the code also works on the PIE target. A stripped executable will need another way to identify those functions.

Finally, `winner.solver.eval(token, cast_to=bytes)` asks for the original input under the successful path’s constraints. Evaluating with `initial.solver` would discard the path constraints and could return unrelated bytes.

<a id="s38--what-was-established"></a>

### What was established

The search reached `win` under the model. The subprocess assertion then confirmed that the exact four bytes make the original compiled target print `ACCEPT` and exit successfully. This proves the witness for this target and run; it does not prove the analysis explored every input or every state.

<a id="s38--try-changing-one-thing"></a>

### Try changing one thing

Replace the symbolic stream with `b"DOG!"`. The helper should raise “No witness” and show an avoided state. Restore symbolic input, then change the input length to three. The target’s short-read check prevents acceptance. These exercises distinguish a wrong input from a wrong input model.

<a id="s38--source-trail"></a>

### Source trail

- [State factories](https://github.com/angr/angr/blob/v9.3.4/angr/factory.py).

- [Explorer classification](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/explorer.py).

- [Stream storage](https://github.com/angr/angr/blob/v9.3.4/angr/storage/file.py).


---

<a id="s39"></a>

<a id="s39--solve-a-command-line-argument"></a>

## [S39] Solve a command-line argument

**Question:** Which four-character argument reaches acceptance? **Tested:** symbolic argument construction and native argv replay.

Command-line strings have a different boundary from stdin. The program receives an array of pointers, and each pointed-to string ends at its first NUL byte. The number of arguments includes the program name at index zero.

```python
"""Symbolic argv; the factory creates the trailing string terminator."""
import subprocess
import claripy
from common import BINARY, project, search

def solve():
    p = project()
    token = claripy.BVS("argument", 32)
    state = p.factory.full_init_state(args=[str(BINARY), token])
    for byte in token.chop(8):
        state.solver.add(byte >= 0x21, byte <= 0x7e)
    winner = search(p, state)
    candidate = winner.solver.eval(token, cast_to=bytes)
    replay = subprocess.run([str(BINARY), candidate.decode("ascii")], capture_output=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout == b"ACCEPT\n"
    return candidate

if __name__ == "__main__":
    print(repr(solve()))
```

```console
$ .venv/bin/python examples/solve_argv.py
b'CAT!'
```

The factory builds argv storage and string termination. We provide the program name and one symbolic 32-bit expression, so `argc` is concrete and equal to two. Restricting the four bytes to printable non-space ASCII excludes embedded NULs and makes decoding for native replay unambiguous. This restriction is a stated input-domain choice; it would be wrong if we intended to investigate arbitrary binary data in another input channel.

<a id="s39--why-not-make-argc-symbolic-too"></a>

### Why not make argc symbolic too?

It is usually clearer to enumerate a small number of plausible argument counts. A symbolic count must remain consistent with the argv storage you created. Otherwise the program may read pointers that your model never initialized. Begin with one uncertain feature at a time: count, length, then contents.

<a id="s39--variable-length-arguments"></a>

### Variable-length arguments

For short maximum lengths, run separate analyses for each fixed length. This avoids mixing string length constraints with content constraints and makes EOF and termination behavior explicit. If you choose a symbolic length instead, model where the NUL occurs and prevent earlier NULs in the significant prefix. A concrete prefix plus a symbolic suffix can reduce the search space further.

Do not run recovered arguments through a shell. Pass them as elements of the subprocess argument list, as the lab does. That preserves spaces and punctuation as data rather than interpreting them as shell syntax.

<a id="s39--source-trail"></a>

### Source trail

- [Linux process state setup](https://github.com/angr/angr/blob/v9.3.4/angr/simos/linux.py).

- [General OS state setup](https://github.com/angr/angr/blob/v9.3.4/angr/simos/simos.py).


---

<a id="s40"></a>

<a id="s40--solve-the-contents-of-a-file"></a>

## [S40] Solve the contents of a file

**Question:** Which bytes in `/input.bin` make file mode accept? **Tested:** virtual filesystem insertion, symbolic file contents, and replay using a real temporary file.

A filename passed to argv does not automatically provide its contents. The simulated program opens paths in the state’s filesystem, so insert the file there before starting execution.

```python
"""Solve a virtual file, then replay with an equivalent temporary real file."""
from pathlib import Path
import subprocess
import tempfile
import angr
import claripy
from common import BINARY, project, search

def solve():
    p = project()
    content = claripy.BVS("file_content", 32)
    state = p.factory.full_init_state(args=[str(BINARY), "file", "/input.bin"])
    state.fs.insert("/input.bin", angr.SimFile("/input.bin", content=content, size=4, has_end=True))
    winner = search(p, state)
    candidate = winner.solver.eval(content, cast_to=bytes)
    with tempfile.TemporaryDirectory() as directory:
        filename = Path(directory) / "input.bin"
        filename.write_bytes(candidate)
        replay = subprocess.run([str(BINARY), "file", str(filename)], capture_output=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout == b"ACCEPT\n"
    return candidate

if __name__ == "__main__":
    print(repr(solve()))
```

```console
$ .venv/bin/python examples/solve_file.py
b'CAT!'
```

`SimFile` models a seekable sequence of bytes. We give it exactly four bytes and a definite end. That lets `fread` report the correct length under the modeled libc interface. A short file takes a different branch in the target.

The virtual path is unrelated to the host root directory. The script does not create a real `/input.bin`. For replay it creates an equivalent temporary file and passes that real filename to the native target. This preserves the relevant contents and file length while avoiding dependence on host filesystem state.

<a id="s40--model-the-failure-cases-too"></a>

### Model the failure cases too

In a larger program, existence, permissions, current directory, seek behavior, and error returns may affect the outcome. An inserted file makes existence a known fact. If the question includes missing-file handling, perform a separate run modeling that condition and verify the relevant open behavior rather than assuming a missing virtual path behaves exactly like your host OS.

<a id="s40--when-the-file-is-not-seekable"></a>

### When the file is not seekable

Use a stream or packet model for data arriving incrementally. A packet’s position is not interchangeable with a byte offset. Short reads may be a central part of a protocol, so assuming that every read fills the requested buffer can remove important behavior. See [Files and process environment](#s08) for the storage-versus-descriptor distinction.

<a id="s40--source-trail"></a>

### Source trail

- [SimFile and descriptors](https://github.com/angr/angr/blob/v9.3.4/angr/storage/file.py).

- [Filesystem state plugin](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/filesystem.py).

- [fread summary](https://github.com/angr/angr/blob/v9.3.4/angr/procedures/libc/fread.py).


---

<a id="s41"></a>

<a id="s41--solve-a-function-return-value"></a>

## [S41] Solve a function return value

**Question:** Which unsigned 32-bit integer makes `transform` return 127? **Tested:** direct function call, return constraint, uniqueness, and native replay.

The target computes `(x * 3u) ^ 0x55u` using unsigned 32-bit arithmetic. Analyzing just this function avoids stdin parsing and process startup.

```python
"""Call one function under an explicit ABI contract; validate through main."""
import subprocess
import claripy
from common import BINARY, address, project

def solve():
    p = project()
    x = claripy.BVS("x", 32)
    # This sentinel is only a stopping address, never executed.
    stop = 0x70000000
    assert p.loader.find_object_containing(stop) is None
    state = p.factory.call_state(address(p, "transform"), x,
        prototype="unsigned int transform(unsigned int)", ret_addr=stop)
    manager = p.factory.simulation_manager(state)
    manager.explore(find=stop, n=40)
    assert manager.found and not manager.errored
    returned = manager.found[0]
    returned.solver.add(returned.regs.eax == 0x7f)
    candidate = returned.solver.eval_one(x)
    replay = subprocess.run([str(BINARY), "number", str(candidate)],
                            capture_output=True, text=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout.strip() == "127"
    return candidate

if __name__ == "__main__":
    print(solve())
```

```console
$ .venv/bin/python examples/solve_function.py
14
```

<a id="s41--a-function-call-is-a-contract"></a>

### A function call is a contract

`call_state` creates a state as if the function had been called. The prototype specifies the argument and return types; the calling convention specifies where those values live. The factory handles argument placement and a return address. It does not run the real caller or initialize arbitrary globals for you.

Here `x` is 32 bits because the C type is `unsigned int` on the target. The return is read from `eax`, the low 32-bit integer return register for this Linux AMD64 lab. Using `rax` indiscriminately in a different ABI or with a narrower return type can constrain bits that are not part of the result.

`stop` is an unmapped sentinel address. The function returns there, and `explore(find=stop)` captures the state before trying to execute any code at that address. A larger harness should select and check its sentinel against all loaded objects and any custom mappings it creates.

<a id="s41--reach-the-return-then-constrain-it"></a>

### Reach the return, then constrain it

A state at the function’s entry has not computed the result yet. The solver constraint belongs on a returned state. `eval_one` is used because the fixed-width transformation has exactly one preimage for this target value. If uniqueness is not part of your problem, use `eval` for a witness or `eval_upto` to examine a bounded set of possibilities.

<a id="s41--functions-with-several-return-paths"></a>

### Functions with several return paths

The straight-line function has one returned state. A branching function may have many. Asking `explore` for its default one found state can capture only a rejecting path. The memory lab collects several returns and checks each for feasibility of the desired result. In a general harness, account for all remaining active and deferred states before claiming complete enumeration.

<a id="s41--native-validation-through-a-wrapper"></a>

### Native validation through a wrapper

The target’s `number` mode parses a concrete decimal argument, calls the same function, and prints its result. This wrapper independently confirms the witness under real machine execution. For a private function without a wrapper, you can build a test harness, use an authorized debugger session, or describe explicitly that only model-level validation was performed.

<a id="s41--source-trail"></a>

### Source trail

- [call_state factory](https://github.com/angr/angr/blob/v9.3.4/angr/factory.py).

- [ABI setup and extraction](https://github.com/angr/angr/blob/v9.3.4/angr/calling_conventions.py).


---

<a id="s42"></a>

<a id="s42--pass-a-symbolic-buffer-by-pointer"></a>

## [S42] Pass a symbolic buffer by pointer

**Question:** What must the four bytes pointed to by `check` contain? **Tested:** allocated state memory, pointer argument, return-path selection, and native replay in the test suite.

An unknown pointer and unknown contents are different models. For this question we know that the pointer designates a four-byte buffer, so we allocate one and make its contents symbolic. Making the pointer itself unconstrained would add an unnecessary address-resolution problem.

```python
"""Allocate a real buffer in the state before passing a pointer."""
import claripy
from common import address, project

def solve():
    p = project()
    base = p.factory.blank_state()
    pointer = base.heap.allocate(4)
    data = claripy.BVS("buffer", 32)
    base.memory.store(pointer, data)
    stop = 0x70000000
    state = p.factory.call_state(address(p, "check"), pointer,
        prototype="int check(unsigned char *)", base_state=base, ret_addr=stop)
    manager = p.factory.simulation_manager(state)
    manager.explore(find=stop, num_find=8, n=80)
    for returned in manager.found:
        if returned.solver.satisfiable(extra_constraints=(returned.regs.eax == 1,)):
            returned.solver.add(returned.regs.eax == 1)
            return returned.solver.eval(data, cast_to=bytes)
    raise RuntimeError("No accepting return found")

if __name__ == "__main__":
    print(repr(solve()))
```

```console
$ .venv/bin/python examples/solve_memory.py
b'CAT!'
```

<a id="s42--the-base-state-owns-the-buffer"></a>

### The base state owns the buffer

The heap plugin allocates storage in the simulated address space. We write the 32-bit input expression into those four bytes, then pass the concrete address to `call_state` using `base_state` so the initialized memory is retained. This is simulated memory; it does not allocate a pointer the host Python process may dereference.

<a id="s42--byte-order-is-deliberate"></a>

### Byte order is deliberate

The input represents a byte sequence, so the high-order byte of the expression is the first byte in memory under the default raw store ordering. A machine integer would instead need explicit `endness=p.arch.memory_endness` on the store and load. See [Memory and symbolic addressing](#s07) for an executable comparison.

<a id="s42--find-the-accepting-returned-state"></a>

### Find the accepting returned state

`check` rejects at several branches. Each returned state carries different constraints on the input. We collect up to eight returned states, which is more than this particular function needs, within 80 manager steps. On each, we ask whether `eax == 1` is feasible. Only after that succeeds do we add the condition and extract the buffer.

The `extra_constraints` feasibility query is temporary. It does not change the state. The following `add` makes the condition persistent for extraction. This distinction matters when a returned state contains both successful and unsuccessful assignments after state merging or a summarized conditional result.

<a id="s42--what-about-structures"></a>

### What about structures?

A structure is an ABI layout, not just a list of fields. Respect member offsets, alignment, padding, pointer width, and byte order. Use an architecture-bound SimType and typed memory views when appropriate, or initialize fields at verified offsets. A pointer field must point to separately initialized storage. Do not assume that a Python tuple automatically matches every packed C layout.

<a id="s42--source-trail"></a>

### Source trail

- [Memory model](https://github.com/angr/angr/blob/v9.3.4/angr/storage/memory_mixins/__init__.py).

- [Heap base](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/heap/heap_base.py).

- [State call setup](https://github.com/angr/angr/blob/v9.3.4/angr/simos/simos.py).


---

<a id="s43"></a>

<a id="s43--replace-a-function-with-an-explicit-model"></a>

## [S43] Replace a function with an explicit model

**Question:** Can an exact summary of the four-byte check recover the same input? **Tested:** custom SimProcedure, hooked search, and native replay in the tests.

A hook replaces code at an address. A SimProcedure is a function-level model that knows how to receive arguments and return using a calling convention. It is useful when executing the original code is expensive or when a dependency is absent, provided you can describe the relevant behavior correctly.

```python
"""Replace a pure function with its exact fixed-width expression."""
import angr
import claripy
from common import BINARY, project, search

class CheckSummary(angr.SimProcedure):
    def run(self, pointer):
        data = self.state.memory.load(pointer, 4)
        return claripy.If(data == claripy.BVV(b"CAT!"), claripy.BVV(1, 32), claripy.BVV(0, 32))

def solve():
    p = project()
    p.hook_symbol("check", CheckSummary(prototype="int check(unsigned char *)"))
    data = claripy.BVS("token", 32)
    state = p.factory.full_init_state(args=[str(BINARY)],
        stdin=angr.SimFileStream(name="stdin", content=data, has_end=True))
    winner = search(p, state)
    return winner.solver.eval(data, cast_to=bytes)

if __name__ == "__main__":
    print(repr(solve()))
```

```console
$ .venv/bin/python examples/solve_hook.py
b'CAT!'
```

The summary reads exactly four bytes and returns the C integer 1 or 0 as a 32-bit conditional expression. There is no Python `if` over symbolic data: `claripy.If` represents both results until constraints decide between them. The prototype tells the SimProcedure how to interpret its pointer argument and integer return.

<a id="s43--what-makes-this-summary-adequate"></a>

### What makes this summary adequate?

For a valid, initialized four-byte buffer, the real `check` has no observable side effects and returns the same integer predicate. The summary is adequate for the course’s acceptance question. It does not preserve instruction timing, per-byte memory-read order, or fault behavior for invalid pointers. If your question is about those observations, it is the wrong abstraction.

<a id="s43--avoid-summaries-that-manufacture-success"></a>

### Avoid summaries that manufacture success

Returning 1 from every check would make a search easier, but the resulting input would say nothing about the original check. Similarly, returning an unconstrained value from a function that fills a buffer leaves the buffer unmodeled. List the return value, written memory, global updates, and error conditions that the real function exposes before writing its replacement.

<a id="s43--function-model-or-instruction-hook"></a>

### Function model or instruction hook?

Use a SimProcedure when replacing an entire function. A user hook such as `project.hook(address, callback, length=...)` is suited to a verified span of instructions. Its length is a count of bytes to skip, not instructions. An incorrect length can land execution in the middle of an instruction. A zero-length user hook resumes the original code without immediately invoking itself again; it is not the same as replacing a whole function and returning.

Hook registration belongs on the project. State-specific data belongs on the state or a state plugin, because many paths can execute the same hook. See [Preserve custom data through forks and merges](#s45) before storing mutable path history.

<a id="s43--source-trail"></a>

### Source trail

- [SimProcedure runtime](https://github.com/angr/angr/blob/v9.3.4/angr/sim_procedure.py).

- [Hook registration](https://github.com/angr/angr/blob/v9.3.4/angr/project.py).

- [Hooking guide](https://github.com/angr/angr/blob/v9.3.4/docs/extending-angr/simprocedures.rst).


---

<a id="s44"></a>

<a id="s44--observe-execution-with-breakpoints"></a>

## [S44] Observe execution with breakpoints

**Question:** Did memory writes occur along the accepting concrete path? **Tested:** a memory-write callback and state-local counting.

SimInspect breakpoints call Python functions when modeled events occur. They can observe instructions, memory accesses, constraints, forks, and other operations. They are instrumentation for angr’s execution, not breakpoints in a native debugger process.

```python
"""Observe state memory writes without recursively triggering inspection."""
import angr
from common import BINARY, project, search

def observe():
    p = project()
    state = p.factory.full_init_state(args=[str(BINARY)], stdin=b"CAT!")
    state.globals["write_count"] = 0
    def count_write(current):
        # Integers are immutable, so each state's shallow globals copy is safe.
        current.globals["write_count"] += 1
        assert current.inspect.attrs.mem_write_address is not None
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=count_write)
    winner = search(p, state)
    return winner.globals["write_count"]

if __name__ == "__main__":
    print("Observed writes:", observe())
```

```console
$ .venv/bin/python examples/inspect_writes.py
Observed writes: ...
```

The exact count depends on compiler output and modeled startup. The test checks that it is positive rather than tying the lesson to an incidental count.

<a id="s44--event-timing-and-attributes"></a>

### Event timing and attributes

The callback runs before a memory write and reads `current.inspect.attrs.mem_write_address`. In this release, `attrs` is the explicit event-attribute container. Older tutorials may use direct attributes on `inspect`. Prefer the interface tested for your installed version.

A before-event callback can inspect the proposed operation. An after-event callback can inspect the completed result when that event supplies one. For instance, the loaded value of a memory read belongs to the after event. Attributes are transient; copy the values you need into your own record while the callback runs instead of reading them later and assuming they persist.

<a id="s44--avoid-observing-your-own-observation"></a>

### Avoid observing your own observation

Reading state memory inside a memory-read callback may trigger the same breakpoint recursively. In an adaptation recipe, use:

```python
data = state.memory.load(pointer, 4, inspect=False, disable_actions=True)
```

This is a diagnostic read that suppresses inspection and action creation for that read. It should not be used indiscriminately to hide the program’s actual memory operations from an analysis that depends on them.

<a id="s44--state-local-counters"></a>

### State-local counters

`state.globals` is shallow-copied when states fork. Reassigning an integer is safe because integers are immutable. Appending to a shared list is different: two states may still refer to the same list. Use immutable tuples with reassignment, copy containers explicitly, or implement a state plugin.

<a id="s44--source-trail"></a>

### Source trail

- [Inspect events and attributes](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/inspect.py).

- [Globals copy semantics](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/globals.py).


---

<a id="s45"></a>

<a id="s45--preserve-custom-data-through-forks-and-merges"></a>

## [S45] Preserve custom data through forks and merges

**Question:** How can a path-local counter survive copying and represent two possible values after a merge? **Tested:** plugin registration, independent copies, and both merged values.

The counter is a 32-bit symbolic expression. Incrementing it on different state copies produces different values. Merging should retain both possibilities, not choose whichever Python object happens to be copied last.

```python
"""A plugin that preserves a symbolic counter through copies and merges."""
import angr
import claripy

class Counter(angr.SimStatePlugin):
    def __init__(self, value=None):
        super().__init__()
        self.value = claripy.BVV(0, 32) if value is None else value

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return Counter(self.value)

    def merge(self, others, merge_conditions, common_ancestor=None):
        self.value = claripy.ite_cases(
            [(condition, other.value) for condition, other in zip(merge_conditions[1:], others)],
            self.value)
        return True

def demonstrate():
    project = angr.load_shellcode(b"\x90", arch="AMD64")
    state = project.factory.blank_state()
    state.register_plugin("counter", Counter())
    left, right = state.copy(), state.copy()
    left.counter.value += 1
    right.counter.value += 2
    merged, conditions, changed = left.merge(right)
    assert state.solver.eval_one(state.counter.value) == 0
    assert changed and len(conditions) == 2
    return sorted(merged.solver.eval_upto(merged.counter.value, 3))

if __name__ == "__main__":
    print(demonstrate())
```

```console
$ .venv/bin/python examples/state_plugin.py
[1, 2]
```

<a id="s45--the-lifecycle-contract"></a>

### The lifecycle contract

A plugin calls `super().__init__` and implements `copy` with the `SimStatePlugin.memo` decorator. Claripy expressions are immutable, so a copy can safely refer to the same expression until a new one replaces it. Mutable nested objects need their own copy policy.

The merge receives conditions for `self` followed by the other plugins. `ite_cases` selects the other value when its merge condition holds and uses the original value as the fallback. The state’s merge machinery constrains the choice of merge conditions; the plugin must preserve their association with values. `merge` mutates the receiver and reports a change.

<a id="s45--why-not-just-use-a-python-integer"></a>

### Why not just use a Python integer?

A Python integer can store one count per path, but a merged state may represent several counts. A bitvector plus conditional expressions represents that uncertainty. In a different plugin, the right representation might be a set, a join in an abstract domain, or a refusal to merge incompatible states. Do not return success from a merge that silently loses relevant information.

<a id="s45--this-is-a-minimal-plugin"></a>

### This is a minimal plugin

The lesson does not implement widening, persistent serialization, or a nested plugin hierarchy. Those need explicit semantics for the data you store. Initialization that depends on the owning state belongs in `set_state` or `init_state` according to the plugin lifecycle, not in a constructor that assumes a state has already been attached.

<a id="s45--source-trail"></a>

### Source trail

- [Plugin lifecycle](https://github.com/angr/angr/blob/v9.3.4/angr/state_plugins/plugin.py).

- [State merge](https://github.com/angr/angr/blob/v9.3.4/angr/sim_state.py).


---

<a id="s46"></a>

<a id="s46--bound-a-loop-and-explain-the-boundary"></a>

## [S46] Bound a loop and explain the boundary

**Question:** For unsigned `n` between 0 and 6, when does `score(n)` return 1? **Tested:** loop-aware search and complete returned-state accounting for this domain.

`score` sums integers from 0 through `n - 1` and compares the sum to 6. The finite input domain is part of the question, not an optimization we hide from the reader.

```python
"""Apply a loop bound to a function with an explicitly bounded argument."""
import angr
import claripy
from common import address, project

def solve():
    p = project()
    n = claripy.BVS("n", 32)
    stop = 0x70000000
    state = p.factory.call_state(address(p, "score"), n,
        prototype="int score(unsigned int)", ret_addr=stop)
    state.solver.add(n <= 6)
    cfg = p.analyses.CFGFast(normalize=True)
    manager = p.factory.simulation_manager(state)
    manager.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=8))
    manager.explore(find=stop, num_find=10, n=150)
    answers = set()
    for returned in manager.found:
        returned.solver.add(returned.regs.eax == 1)
        if returned.solver.satisfiable():
            answers.update(returned.solver.eval_upto(n, 7))
    assert not manager.active and not manager.errored
    assert not manager.stashes.get("spinning", [])
    return sorted(answers)

if __name__ == "__main__":
    print(solve())
```

```console
$ .venv/bin/python examples/bounded_search.py
[4]
```

<a id="s46--two-limits-do-different-jobs"></a>

### Two limits do different jobs

The constraint `n <= 6` defines the domain of the unsigned input. LoopSeer uses recovered loop structure and a trip-count bound to control exploration. The manager’s `n=150` limits stepping. Neither number is a timeout in seconds.

The lab uses a bound above the expected iterations for the chosen domain and checks that no states remain active, errored, or in `spinning`. This makes it possible to distinguish “we enumerated the modeled domain” from “we discarded paths before they returned.” A general program may have additional stashes, including deferred or custom ones, which must also be accounted for.

<a id="s46--change-the-bound"></a>

### Change the bound

Lower the LoopSeer bound and rerun. The assertions are expected to reveal excluded paths rather than silently returning a smaller answer set. Inspect `manager.stashes` before deciding what the smaller set means.

<a id="s46--a-finite-loop-count-does-not-make-all-searches-cheap"></a>

### A finite loop count does not make all searches cheap

A loop can create a large symbolic expression without creating many states. Conversely, several simple branches can create many short paths. Diagnose whether your cost is state count, constraint size, or expensive operations before choosing DFS, merging, or a summary. [Performance and search limits](#s25) explains these tradeoffs.

<a id="s46--source-trail"></a>

### Source trail

- [LoopSeer](https://github.com/angr/angr/blob/v9.3.4/angr/exploration_techniques/loop_seer.py).

- [SimulationManager.run](https://github.com/angr/angr/blob/v9.3.4/angr/sim_manager.py).


---

<a id="s47"></a>

<a id="s47--recover-functions-and-decompile-one"></a>

## [S47] Recover functions and decompile one

**Question:** What is the shape of `check`, and what pseudocode can angr recover? **Tested:** CFGFast, symbol-to-function lookup, graph lookup, and decompiler output.

Static analysis answers structural questions before symbolic execution starts. Use it to find functions, inspect branches, and identify observations for a later search. It does not automatically solve path constraints.

```python
"""Recover the local target's functions and decompile check."""
from common import address, project

def analyze():
    p = project()
    cfg = p.analyses.CFGFast(normalize=True, data_references=True)
    function = cfg.kb.functions[address(p, "check")]
    node = cfg.model.get_any_node(function.addr)
    assert node is not None
    decompiled = p.analyses.Decompiler(function, cfg=cfg.model)
    if decompiled.codegen is None:
        raise RuntimeError("Decompiler did not produce text")
    return {"functions": len(cfg.kb.functions), "blocks": len(function.block_addrs_set),
            "code": decompiled.codegen.text}

if __name__ == "__main__":
    result = analyze()
    print("Recovered functions:", result["functions"])
    print("Blocks in check:", result["blocks"])
    print(result["code"])
```

```console
$ .venv/bin/python examples/analyze_cfg.py
Recovered functions: ...
Blocks in check: ...
...
```

Read the function containing byte comparisons and integer returns. Names, formatting, character-versus-integer constants, and graph counts can change with compiler and angr versions. The test checks structural properties and that code generation succeeds; it does not promise a particular printed listing.

<a id="s47--three-graph-related-objects"></a>

### Three graph-related objects

`cfg` is the analysis result. `cfg.model` provides node lookup and the whole recovered graph. `cfg.kb.functions` is the function manager inside the knowledge base. Its values are function objects, not states.

`function.transition_graph` describes transitions associated with one function. `cfg.model.graph` covers the recovered program graph. `cfg.kb.functions.callgraph` connects functions through recovered calls. Choose the graph matching your question before counting nodes or edges.

<a id="s47--why-normalize"></a>

### Why normalize?

A normalized CFG gives downstream analyses a more regular block structure. The decompiler consumes the recovered function and CFG model, translates to analysis-friendly forms, recovers variables and control structure, and emits C-like text. That text is a reconstruction; the compiler did not preserve all original source names or types.

<a id="s47--when-recovery-is-incomplete"></a>

### When recovery is incomplete

Indirect calls, unusual prologues, mixed code and data, obfuscation, and missing metadata can all leave gaps. A recovered function boundary can be wrong. Check disassembly around suspicious boundaries and unresolved jumps before using the graph to prune a symbolic search. If a decompiler produces no `codegen`, inspect its errors and the function/CFG input rather than treating absence of text as evidence that the function is empty.

<a id="s47--cfgemulated-is-a-different-tradeoff"></a>

### CFGEmulated is a different tradeoff

CFGEmulated uses emulation and context information, so it can be useful for specific analyses that need saved states or execution-derived dependencies. It is typically more expensive and can itself miss behavior because of state or environment limitations. It is not a universally more accurate substitute for CFGFast. Start with CFGFast unless your downstream task requires otherwise.

<a id="s47--source-trail"></a>

### Source trail

- [CFGFast implementation](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/cfg/cfg_fast.py).

- [CFG model](https://github.com/angr/angr/blob/v9.3.4/angr/knowledge_plugins/cfg/cfg_model.py).

- [Decompiler implementation](https://github.com/angr/angr/blob/v9.3.4/angr/analyses/decompiler/decompiler.py).


---

<a id="s48"></a>

<a id="s48--solver-engine"></a>

## [S48] Solver Engine

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr’s solver engine is called Claripy. Claripy exposes the following design:

- Claripy ASTs (the subclasses of claripy.ast.Base) provide a unified way to interact with concrete and symbolic expressions

- `Frontend`s provide different paradigms for evaluating these expressions. For example, the `FullFrontend` solves expressions using something like an SMT solver backend, while `LightFrontend` handles them by using an abstract (and approximating) data domain backend.

- Each `Frontend` needs to, at some point, do actual operation and evaluations on an AST. ASTs don’t support this on their own. Instead, `Backend`s translate ASTs into backend objects (i.e., Python primitives for `BackendConcrete`, Z3 expressions for `BackendZ3`, strided intervals for `BackendVSA`, etc) and handle any appropriate state-tracking objects (such as tracking the solver state in the case of `BackendZ3`). Roughly speaking, frontends take ASTs as inputs and use backends to `backend.convert()` those ASTs into backend objects that can be evaluated and otherwise reasoned about.

- `FrontendMixin`s customize the operation of `Frontend`s. For example, `ModelCacheMixin` caches solutions from an SMT solver.

- The combination of a Frontend, a number of FrontendMixins, and a number of Backends comprise a claripy `Solver`.

Internally, Claripy seamlessly mediates the co-operation of multiple disparate backends – concrete bitvectors, VSA constructs, and SAT solvers. It is pretty badass.

Most users of angr will not need to interact directly with Claripy (except for, maybe, claripy AST objects, which represent symbolic expressions) – angr handles most interactions with Claripy internally. However, for dealing with expressions, an understanding of Claripy might be useful.

<a id="s48--claripy-asts"></a>

### Claripy ASTs

Claripy ASTs abstract away the differences between mathematical constructs that Claripy supports. They define a tree of operations (i.e., `(a + b) / c)` on any type of underlying data. Claripy handles the application of these operations on the underlying objects themselves by dispatching requests to the backends.

Currently, Claripy supports the following types of ASTs:

| Name | Description | Supported By (Claripy Backends) | Example Code |
|----|----|----|----|
| BV | This is a bitvector, whether symbolic (with a name) or concrete (with a value). It has a size (in bits). | BackendConcrete, BackendVSA, BackendZ3 | Create a 32-bit symbolic bitvector “x”: claripy.BVS(‘x’, 32) Create a 32-bit bitvector with the value 0xc001b3475: claripy.BVV(0xc001b3a75, 32)\`\</li\>\<li\>Create a 32-bit “strided interval” (see VSA documentation) that can be any divisible-by-10 number between 1000 and 2000: \`claripy.SI(name=’x’, bits=32, lower_bound=1000, upper_bound=2000, stride=10)\`\</li\>\</ul\> |
| FP | This is a floating-point number, whether symbolic (with a name) or concrete (with a value). | BackendConcrete, BackendZ3 | Create a `claripy.fp.FSORT_DOUBLE` symbolic floating point “b”: `claripy.FPS('b', claripy.fp.FSORT_DOUBLE)`. Create a `claripy.fp.FSORT_FLOAT` floating point with value `3.2`: `claripy.FPV(3.2, claripy.fp.FSORT_FLOAT)`. |
| Bool | This is a boolean operation (True or False). | BackendConcrete, BackendVSA, BackendZ3 | `claripy.BoolV(True)`, or `claripy.true` or `claripy.false`, or by comparing two ASTs (i.e., `claripy.BVS('x', 32) < claripy.BVS('y', 32)` |

All of the above creation code returns claripy.AST objects, on which operations can then be carried out.

ASTs provide several useful operations.

```python
>>> import claripy

>>> bv = claripy.BVV(0x41424344, 32)

# Size - you can get the size of an AST with .size()
>>> assert bv.size() == 32

# Reversing - .reversed is the reversed version of the BVV
>>> assert bv.reversed is claripy.BVV(0x44434241, 32)
>>> assert bv.reversed.reversed is bv

# Depth - you can get the depth of the AST
>>> print(bv.depth)
>>> assert bv.depth == 1
>>> x = claripy.BVS('x', 32)
>>> assert (x+bv).depth == 2
>>> assert ((x+bv)/10).depth == 3
```

Applying a condition (==, !=, etc) on ASTs will return an AST that represents the condition being carried out. For example:

```python
>>> r = bv == x
>>> assert isinstance(r, claripy.ast.Bool)

>>> p = bv == bv
>>> assert isinstance(p, claripy.ast.Bool)
>>> assert p.is_true()
```

You can combine these conditions in different ways.

```python
>>> q = claripy.And(claripy.Or(bv == x, bv * 2 == x, bv * 3 == x), x == 0)
>>> assert isinstance(p, claripy.ast.Bool)
```

The usefulness of this will become apparent when we discuss Claripy solvers.

In general, Claripy supports all of the normal Python operations (`+`, `-`, `|`, `==`, etc), and provides additional ones via the Claripy instance object. Here’s a list of available operations from the latter.

| Name | Description | Example |
|----|----|----|
| LShR | Logically shifts a bit expression (BVV, BV, SI) to the right. | `claripy.LShR(x, 10)` |
| SignExt | Sign-extends a bit expression. | `claripy.SignExt(32, x)` or `x.sign_extend(32)` |
| ZeroExt | Zero-extends a bit expression. | `claripy.ZeroExt(32, x)` or `x.zero_extend(32)` |
| Extract | Extracts the given bits (zero-indexed from the *right*, inclusive) from a bit expression. | Extract the rightmost byte of x: `claripy.Extract(7, 0, x)` or `x[7:0]` |
| Concat | Concatenates several bit expressions together into a new bit expression. | `claripy.Concat(x, y, z)` |
| RotateLeft | Rotates a bit expression left. | `claripy.RotateLeft(x, 8)` |
| RotateRight | Rotates a bit expression right. | `claripy.RotateRight(x, 8)` |
| Reverse | Endian-reverses a bit expression. | `claripy.Reverse(x)` or `x.reversed` |
| And | Logical And (on boolean expressions) | `claripy.And(x == y, x > 0)` |
| Or | Logical Or (on boolean expressions) | `claripy.Or(x == y, y < 10)` |
| Not | Logical Not (on a boolean expression) | `claripy.Not(x == y)` is the same as `x != y` |
| If | An If-then-else | Choose the maximum of two expressions: `claripy.If(x > y, x, y)` |
| ULE | Unsigned less than or equal to. | Check if x is less than or equal to y: `claripy.ULE(x, y)` |
| ULT | Unsigned less than. | Check if x is less than y: `claripy.ULT(x, y)` |
| UGE | Unsigned greater than or equal to. | Check if x is greater than or equal to y: `claripy.UGE(x, y)` |
| UGT | Unsigned greater than. | Check if x is greater than y: `claripy.UGT(x, y)` |
| SLE | Signed less than or equal to. | Check if x is less than or equal to y: `claripy.SLE(x, y)` |
| SLT | Signed less than. | Check if x is less than y: `claripy.SLT(x, y)` |
| SGE | Signed greater than or equal to. | Check if x is greater than or equal to y: `claripy.SGE(x, y)` |
| SGT | Signed greater than. | Check if x is greater than y: `claripy.SGT(x, y)` |

Note

The default Python `>`, `<`, `>=`, and `<=` are unsigned in Claripy. This is different than their behavior in Z3, because it seems more natural in binary analysis.

<a id="s48--solvers"></a>

### Solvers

The main point of interaction with Claripy are the Claripy Solvers. Solvers expose an API to interpret ASTs in different ways and return usable values. There are several different solvers.

| Name | Description |
|----|----|
| Solver | This is analogous to a `z3.Solver()`. It is a solver that tracks constraints on symbolic variables and uses a constraint solver (currently, Z3) to evaluate symbolic expressions. |
| SolverVSA | This solver uses VSA to reason about values. It is an *approximating* solver, but produces values without performing actual constraint solves. |
| SolverReplacement | This solver acts as a pass-through to a child solver, allowing the replacement of expressions on-the-fly. It is used as a helper by other solvers and can be used directly to implement exotic analyses. |
| SolverHybrid | This solver combines the SolverReplacement and the Solver (VSA and Z3) to allow for *approximating* values. You can specify whether or not you want an exact result from your evaluations, and this solver does the rest. |
| SolverComposite | This solver implements optimizations that solve smaller sets of constraints to speed up constraint solving. |

Some examples of solver usage:

```python
# create the solver and an expression
>>> s = claripy.Solver()
>>> x = claripy.BVS('x', 8)

# now let's add a constraint on x
>>> s.add(claripy.ULT(x, 5))

>>> assert sorted(s.eval(x, 10)) == [0, 1, 2, 3, 4]
>>> assert s.max(x) == 4
>>> assert s.min(x) == 0

# we can also get the values of complex expressions
>>> y = claripy.BVV(65, 8)
>>> z = claripy.If(x == 1, x, y)
>>> assert sorted(s.eval(z, 10)) == [1, 65]

# and, of course, we can add constraints on complex expressions
>>> s.add(z % 5 != 0)
>>> assert s.eval(z, 10) == (1,)
>>> assert s.eval(x, 10) == (1,) # interestingly enough, since z can't be y, x can only be 1!
```

Custom solvers can be built by combining a Claripy Frontend (the class that handles the actual interaction with SMT solver or the underlying data domain) and some combination of frontend mixins (that handle things like caching, filtering out duplicate constraints, doing opportunistic simplification, and so on).

<a id="s48--claripy-backends"></a>

### Claripy Backends

Backends are Claripy’s workhorses. Claripy exposes ASTs to the world, but when actual computation has to be done, it pushes those ASTs into objects that can be handled by the backends themselves. This provides a unified interface to the outside world while allowing Claripy to support different types of computation. For example, BackendConcrete provides computation support for concrete bitvectors and booleans, BackendVSA introduces VSA constructs such as StridedIntervals (and details what happens when operations are performed on them, and BackendZ3 provides support for symbolic variables and constraint solving.

There are a set of functions that a backend is expected to implement. For all of these functions, the “public” version is expected to be able to deal with claripy’s AST objects, while the “private” version should only deal with objects specific to the backend itself. This is distinguished with Python idioms: a public function will be named func() while a private function will be \_func(). All functions should return objects that are usable by the backend in its private methods. If this can’t be done (i.e., some functionality is being attempted that the backend can’t handle), the backend should raise a BackendError. In this case, Claripy will move on to the next backend in its list.

All backends must implement a `convert()` function. This function receives a claripy AST and should return an object that the backend can handle in its private methods. Backends should also implement a `convert()` method, which will receive anything that is *not* a claripy AST object (i.e., an integer or an object from a different backend). If `convert()` or `convert()` receives something that the backend can’t translate to a format that is usable internally, the backend should raise BackendError, and thus won’t be used for that object. All backends must also implement any functions of the base `Backend` abstract class that currently raise `NotImplementedError()`.

Claripy’s contract with its backends is as follows: backends should be able to handle, in their private functions, any object that they return from their private *or* public functions. Claripy will never pass an object to any backend private function that did not originate as a return value from a private or public function of that backend. One exception to this is `convert()` and `convert()`, as Claripy can try to stuff anything it feels like into \_convert() to see if the backend can handle that type of object.

<a id="s48--backend-objects"></a>

#### Backend Objects

To perform actual, useful computation on ASTs, Claripy uses backend objects. A `BackendObject` is a result of the operation represented by the AST. Claripy expects these objects to be returned from their respective backends, and will pass such objects into that backend’s other functions.


---

<a id="s49"></a>

<a id="s49--symbolic-memory-addressing"></a>

## [S49] Symbolic memory addressing

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr supports *symbolic memory addressing*, meaning that offsets into memory may be symbolic. Our implementation of this is inspired by “Mayhem”. Specifically, this means that angr concretizes symbolic addresses when they are used as the target of a write. This causes some surprises, as users tend to expect symbolic writes to be treated purely symbolically, or “as symbolically” as we treat symbolic reads, but that is not the default behavior. However, like most things in angr, this is configurable.

The address resolution behavior is governed by *concretization strategies*, which are subclasses of `angr.concretization_strategies.SimConcretizationStrategy`. Concretization strategies for reads are set in `state.memory.read_strategies` and for writes in `state.memory.write_strategies`. These strategies are called, in order, until one of them is able to resolve addresses for the symbolic index. By setting your own concretization strategies (or through the use of SimInspect `address_concretization` breakpoints, described above), you can change the way angr resolves symbolic addresses.

For example, angr’s default concretization strategies for writes are:

1.  A conditional concretization strategy that allows symbolic writes (with a maximum range of 128 possible solutions) for any indices that are annotated with `angr.plugins.symbolic_memory.MultiwriteAnnotation`.

2.  A concretization strategy that simply selects the maximum possible solution of the symbolic index.

To enable symbolic writes for all indices, you can either add the `SYMBOLIC_WRITE_ADDRESSES` state option at state creation time or manually insert a `angr.concretization_strategies.SimConcretizationStrategyRange` object into `state.memory.write_strategies`. The strategy object takes a single argument, which is the maximum range of possible solutions that it allows before giving up and moving on to the next (presumably non-symbolic) strategy.

<a id="s49--writing-concretization-strategies"></a>

### Writing concretization strategies

<a id="s49--id1"></a>

Todo

Write this section


---

<a id="s50"></a>

<a id="s50--debug-variable-resolution"></a>

## [S50] Debug variable resolution

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr now support resolve source level variable (debug variable) in binary with debug information. This article will introduce you how to use it.

<a id="s50--setting-up"></a>

### Setting up

To use it you need binary that is compiled with dwarf debugging information (ex: `gcc -g`) and load in angr with the option `load_debug_info`. After that you need to run `project.kb.dvars.load_from_dwarf()` to set up the feature and we’re set.

Overall it looks like this:

```text
# compile your binary with debug information
gcc -g -o debug_var debug_var.c
```

```python
>>> import angr
>>> project = angr.Project('./examples/debug_var/simple_var', load_debug_info = True)
>>> project.kb.dvars.load_from_dwarf()
```

<a id="s50--core-feature"></a>

### Core feature

With things now set up you can view the value in the angr memory view of the debug variable within a state with: `state.dvars['variable_name'].mem` or the value that it point to if it is a pointer with: `state.dvars['pointer_name'].deref.mem`. Here are some example:

Given the source code in `examples/debug_var/simple_var.c`

```c
#include<stdio.h>

int global_var = 100;
int main(void){
   int a = 10;
   int* b = &a;
   printf("%d\n", *b);
   {
      int a = 24;
      *b = *b + a;
      int c[] = {5, 6, 7, 8};
      printf("%d\n", a);
   }
   return 0;
}
```

```python
# Get a state before executing printf(%d\n", *b) (line 7)
# the addr to line 7 is 0x401193 you can search for it with
>>> project.loader.main_object.addr_to_line
{...}
>>> addr = 0x401193
# Create an simulation manager and run to that addr
>>> simgr = project.factory.simgr()
>>> simgr.explore(find = addr)
<SimulationManager with 1 found>
>>> state = simgr.found[0]
# Resolve 'a' in state
>>> state.dvars['a'].mem
<int (32 bits) <BV32 0xa> at 0x7fffffffffeff30>
# Dereference pointer b
>>> state.dvars['b'].deref.mem
<int (32 bits) <BV32 0xa> at 0x7fffffffffeff30>
# It works as expected when resolving the value of b gives the address of a
>>> state.dvars['b'].mem
<reg64_t <BV64 0x7fffffffffeff30> at 0x7fffffffffeff38>
```

Side-note: For string type you can use `.string` instead of `.mem` to resolve it. For struct type you can resolve its member by `.member("member_name").mem`. For array type you can use `.array(index).mem` to access the element in array.

<a id="s50--variable-visibility"></a>

## [S50] Variable visibility

If you have many variable with the same name but in different scope, calling `state.dvars['var_name']` would resolve the variable with the nearest scope.

Example:

```python
# Find the addr before executing printf("%d\n", a) (line 12)
# with the same method to find addr
>>> addr = 0x4011e0
# Explore until find state
>>> simgr.move(from_stash='found', to_stash='active')
<SimulationManager with 1 active>
>>> simgr.explore(find = addr)
<SimulationManager with 1 found>
>>> state = simgr.found[0]
# Resolve 'a' in state before execute line 10
>>> state.dvars['a'].mem
<int (32 bits) <BV32 0x18> at 0x7fffffffffeff34>
```

Congratulation, you’ve now know how to resolve debug variable using angr, for more info check out the api-doc.


---

<a id="s51"></a>

<a id="s51--working-with-file-system-sockets-and-pipes"></a>

## [S51] Working with File System, Sockets, and Pipes

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


It’s very important to be able to control the environment that emulated programs see, including how symbolic data is introduced from the environment! angr has a robust series of abstractions to help you set up the environment you want.

The root of any interaction with the filesystem, sockets, pipes, or terminals is a SimFile object. A SimFile is a *storage* abstraction that defines a sequence of bytes, symbolic or otherwise. There are several kinds of SimFiles which store their data very differently - the two easiest examples are `SimFile` (the base class is actually called `SimFileBase`), which stores files as a flat address-space of data, and `SimPackets`, which stores a sequence of variable-sized reads. The former is best for modeling programs that need to perform seeks on their files, and is the default storage for opened files, while the latter is best for modeling programs that depend on short-reads or use scanf, and is the default storage for stdin/stdout/stderr.

Because SimFiles can have such diverse storage mechanisms, the interface for interacting with them is *very* abstracted. You can read from the file from some position, you can write to the file at some position, you can ask how many bytes are currently stored in the file, and you can concretize the file, generating a testcase for it. If you know specifically which SimFile class you’re working with, you can take much more powerful control over it, and as a result you’re encouraged to manually create any files you want to work with when you create your initial state.

Specifically, each SimFile class creates its own abstraction of a “position” within the file - each read and write takes a position and returns a new position that you should use to continue from where you left off. If you’re working with SimFiles of unknown type you have to treat this position as a totally opaque object with no semantics other than the contract with the read/write functions.

However! This is a very poor match to how programs generally interact with files, so angr also has a SimFileDescriptor abstraction, which provides the familiar read/write/seek/tell interfaces but will also return error conditions when the underlying storage don’t support the appropriate operations - just like normal file descriptors!

You may access the mapping from file descriptor number to file descriptor object in `state.posix.fd`. See the API document for [`angr.storage.file.SimFileDescriptorBase`](https://docs.angr.io/en/latest/api/angr.storage.file.html#angr.storage.file.SimFileDescriptorBase) for more details.

<a id="s51--just-tell-me-how-to-do-what-i-want-to-do"></a>

### Just tell me how to do what I want to do!

Okay okay!!

To create a SimFile, you should just create an instance of the class you want to use. Refer to [`angr.storage.file`](https://docs.angr.io/en/latest/api/angr.storage.file.html#module-angr.storage.file) for the full instructions.

Let’s go through a few illustrative examples, which cover how you can work with a concrete file, a symbolic file, a file with mixed concrete and symbolic content, or streams.

<a id="s51--example-1-create-a-file-with-concrete-content"></a>

#### Example 1: Create a file with concrete content

```python
>>> import angr
>>> simfile = angr.SimFile('myconcretefile', content='hello world!\n')
```

Here’s a nuance - you can’t use SimFiles without a state attached, because reasons. You’ll **never** have to do this in a real scenario (this operation happens automatically when you pass a SimFile into a constructor or the filesystem) but let’s mock it up:

```python
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.blank_state()
>>> simfile.set_state(state)
```

To demonstrate the behavior of these files we’re going to use the fact that the default SimFile position is just the number of bytes from the start of the file. `SimFile.read` returns a tuple (bitvector data, actual size, new pos):

```python
>>> data, actual_size, new_pos = simfile.read(0, 5)
>>> import claripy
>>> assert claripy.is_true(data == 'hello')
>>> assert claripy.is_true(actual_size == 5)
>>> assert claripy.is_true(new_pos == 5)
```

Continue the read, trying to read way too much:

```python
>>> data, actual_size, new_pos = simfile.read(new_pos, 1000)
```

angr doesn’t try to sanitize the data returned, only the size - we returned 1000 bytes! The intent is that you’re only allowed to use up to actual_size of them.

```python
>>> assert len(data) == 1000*8  # bitvector sizes are in bits
>>> assert claripy.is_true(actual_size == 8)
>>> assert claripy.is_true(data.get_bytes(0, 8) == ' world!\n')
>>> assert claripy.is_true(new_pos == 13)
```

<a id="s51--example-2-create-a-file-with-symbolic-content-and-a-defined-size"></a>

#### Example 2: Create a file with symbolic content and a defined size

```python
>>> simfile = angr.SimFile('mysymbolicfile', size=0x20)
>>> simfile.set_state(state)

>>> data, actual_size, new_pos = simfile.read(0, 0x30)
>>> assert data.symbolic
>>> assert claripy.is_true(actual_size == 0x20)
```

The basic SimFile provides the same interface as `state.memory`, so you can load data directly:

```python
>>> assert simfile.load(0, actual_size) is data.get_bytes(0, 0x20)
```

<a id="s51--example-3-create-a-file-with-constrained-symbolic-content"></a>

#### Example 3: Create a file with constrained symbolic content

```python
>>> bytes_list = [claripy.BVS('byte_%d' % i, 8) for i in range(32)]
>>> bytes_ast = claripy.Concat(*bytes_list)
>>> mystate = proj.factory.entry_state(stdin=angr.SimFile('/dev/stdin', content=bytes_ast))
>>> for byte in bytes_list:
...     mystate.solver.add(byte >= 0x20)
...     mystate.solver.add(byte <= 0x7e)
```

<a id="s51--example-4-create-a-file-with-some-mixed-concrete-and-symbolic-content-but-no-eof"></a>

#### Example 4: Create a file with some mixed concrete and symbolic content, but no EOF

```python
>>> variable = claripy.BVS('myvar', 10*8)
>>> simfile = angr.SimFile('mymixedfile', content=variable.concat(claripy.BVV('\n')), has_end=False)
>>> simfile.set_state(state)
```

We can always query the number of bytes stored in the file:

```python
>>> assert claripy.is_true(simfile.size == 11)
```

Reads will generate additional symbolic data past the current frontier:

```python
>>> data, actual_size, new_pos = simfile.read(0, 15)
>>> assert claripy.is_true(actual_size == 15)
>>> assert claripy.is_true(new_pos == 15)

>>> assert claripy.is_true(data.get_bytes(0, 10) == variable)
>>> assert claripy.is_true(data.get_bytes(10, 1) == '\n')
>>> assert data.get_bytes(11, 4).symbolic
```

<a id="s51--example-5-create-a-file-with-a-symbolic-size-has-end-is-implicitly-true-here"></a>

#### Example 5: Create a file with a symbolic size (`has_end` is implicitly true here)

```python
>>> symsize = claripy.BVS('mysize', 64)
>>> state.solver.add(symsize >= 10)
>>> state.solver.add(symsize < 20)
>>> simfile = angr.SimFile('mysymsizefile', size=symsize)
>>> simfile.set_state(state)
```

Reads will encode all possibilities:

```python
>>> data, actual_size, new_pos = simfile.read(0, 30)
>>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(10, 20))
```

The maximum size can’t be easily resolved, so the data returned is 30 bytes long, and we’re supposed to use it conjunction with actual_size.

```python
>>> assert len(data) == 30*8
```

Symbolic read sizes work too!

```python
>>> symreadsize = claripy.BVS('myreadsize', 64)
>>> state.solver.add(symreadsize >= 5)
>>> state.solver.add(symreadsize < 30)
>>> data, actual_size, new_pos = simfile.read(0, symreadsize)
```

All sizes between 5 and 20 should be possible:

```python
>>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(5, 20))
```

<a id="s51--example-6-working-with-streams-simpackets"></a>

#### Example 6: Working with streams (`SimPackets`)

So far, we’ve only used the SimFile class, which models a random-accessible file object. However, in real life, files are not everything. Streams (standard I/O, TCP, etc.) are a great example: While they hold data like a normal file does, they do not support random accesses, e.g., you cannot read out the second byte of stdin if you have already read passed that position, and you cannot modify any byte that has been previously sent out to a network endpoint. This allows us to design a simpler abstraction for streams in angr.

Believe it or not, this simpler abstraction for streams will benefit symbolic execution. Consider an example program that calls `scanf` N times to read in N strings. With a traditional SimFile, as we do not know the length of each input string, there does not exist any clear boundary in the file between these symbolic input strings. In this case, angr will perform N symbolic reads where each read will generate a gigantic tree of claripy ASTs, with string lengths being symbolic. This is a nightmare for constraint solving. Nevertheless, the fact that `scanf` is used on a stream (stdin) dictates that there will be zero overlap between individual reads, regardless of the sizes of each symbolic input string. We may as well model stdin as a stream that comprises of *consecutive packets*, instead of a file containing a sequence of bytes. Each of the packet can be of a fixed length or a symbolic length. Since there will be absolutely no byte overlap between packets, the constraints that angr will produce after executing this example program will be a lot simpler.

The key concept involved is “short reads”, i.e. when you ask for `n` bytes but actually get back fewer bytes than that. We use a different class implementing SimFileBase, `SimPackets`, to automatically enable support for short reads. By default, stdin, stdout, and stderr are all SimPackets objects.

```python
>>> simfile = angr.SimPackets('mypackets')
>>> simfile.set_state(state)
```

This’ll just generate a single packet. For SimPackets, the position is just a packet number! If left unspecified, short_reads is determined from a state option.

```python
>>> data, actual_size, new_pos = simfile.read(0, 20, short_reads=True)
>>> assert len(data) == 20*8
>>> assert set(state.solver.eval_upto(actual_size, 30)) == set(range(21))
```

Data in a SimPackets is stored as tuples of (packet data, packet size) in `.content`.

```python
>>> print(simfile.content)
[(<BV160 packet_0_mypackets>, <BV64 packetsize_0_mypackets>)]

>>> simfile.read(0, 1, short_reads=False)
>>> print(simfile.content)
[(<BV160 packet_0_mypackets>, <BV64 packetsize_0_mypackets>), (<BV8 packet_1_mypackets>, <BV64 0x1>)]
```

So hopefully you understand sort of the kind of data that a SimFile can store and what’ll happen when a program tries to interact with it with various combinations of symbolic and concrete data. Those examples only covered reads, but writes are pretty similar.

<a id="s51--the-filesystem-for-real-now"></a>

### The filesystem, for real now

If you want to make a SimFile available to the program, we need to either stick it in the filesystem or serve stdin/stdout from it.

The simulated filesystem is the `state.fs` plugin. You can store, load, and delete files from the filesystem, with the `insert`, `get`, and `delete` methods. Refer to [`angr.state_plugins.filesystem`](https://docs.angr.io/en/latest/api/angr.state_plugins.filesystem.html#module-angr.state_plugins.filesystem) for details.

So to make our file available as `/tmp/myfile`:

```python
>>> state.fs.insert('/tmp/myfile', simfile)
>>> assert state.fs.get('/tmp/myfile') is simfile
```

Then, after execution, we would extract the file from the result state and use `simfile.concretize()` to generate a testcase to reach that state. Keep in mind that `concretize()` returns different types depending on the file type - for a SimFile it’s a bytestring and for SimPackets it’s a list of bytestrings.

The simulated filesystem supports a fun concept of “mounts”, where you can designate a subtree as instrumented by a particular provider. The most common mount is to expose a part of the host filesystem to the guest, lazily importing file data when the program asks for it:

```python
>>> state.fs.mount('/', angr.SimHostFilesystem('./guest_chroot'))
```

You can write whatever kind of mount you want to instrument filesystem access by subclassing `angr.SimMount`!

The filesystem also has a root directory, which `state.fs.chroot` changes - this is what the `chroot` simprocedure calls. The new root is resolved inside the filesystem the state already has, so a guest calling `chroot` can only reduce what it is able to reach; it never gains access to anything you did not mount yourself.

<a id="s51--stdio-streams"></a>

### Stdio streams

For stdin and friends, it’s a little more complicated. The relevant plugin is `state.posix`, which stores all abstractions relevant to a POSIX-compliant environment. You can always get a state’s stdin SimFile with `state.posix.stdin`, but you can’t just replace it - as soon as the state is created, references to this file are created in the file descriptors. Because of this you need to specify it at the time the POSIX plugin is created:

```python
>>> state.register_plugin('posix', angr.state_plugins.posix.SimSystemPosix(stdin=simfile, stdout=simfile, stderr=simfile))
>>> assert state.posix.stdin is simfile
>>> assert state.posix.stdout is simfile
>>> assert state.posix.stderr is simfile
```

Or, there’s a nice shortcut while creating the state if you only need to specify stdin:

```python
>>> state = proj.factory.entry_state(stdin=simfile)
>>> assert state.posix.stdin is simfile
```

Any of those places you can specify a SimFileBase, you can also specify a string or a bitvector (a flat SimFile with fixed size will be created to hold it) or a SimFile type (it’ll be instantiated for you).


---

<a id="s52"></a>

<a id="s52--gotchas-when-using-angr"></a>

## [S52] Gotchas when using angr

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


This section contains a list of gotchas that users/victims of angr frequently run into.

<a id="s52--simprocedure-inaccuracy"></a>

### SimProcedure inaccuracy

To make symbolic execution more tractable, angr replaces common library functions with summaries written in Python. We call these summaries SimProcedures. SimProcedures allow us to mitigate path explosion that would otherwise be introduced by, for example, `strlen` running on a symbolic string.

Unfortunately, our SimProcedures are far from perfect. If angr is displaying unexpected behavior, it might be caused by a buggy/incomplete SimProcedure. There are several things that you can do:

1.  Disable the SimProcedure (you can exclude specific SimProcedures by passing options to the `angr.Project` class. This has the drawback of likely leading to a path explosion, unless you are very careful about constraining the input to the function in question. The path explosion can be partially mitigated with other angr capabilities (such as Veritesting).

2.  Replace the SimProcedure with something written directly to the situation in question. For example, our `scanf` implementation is not complete, but if you just need to support a single, known format string, you can write a hook to do exactly that.

3.  Fix the SimProcedure.

<a id="s52--unsupported-syscalls"></a>

### Unsupported syscalls

System calls are also implemented as SimProcedures. Unfortunately, there are system calls that we have not yet implemented in angr. There are several workarounds for an unsupported system call:

1.  Implement the system call.

    <a id="s52--id1"></a>

    Todo

    document this process

2.  Hook the callsite of the system call (using `project.hook`) to make the required modifications to the state in an ad-hoc way.

3.  Use the `state.posix.queued_syscall_returns` list to queue syscall return values. If a return value is queued, the system call will not be executed, and the value will be used instead. Furthermore, a function can be queued instead as the “return value”, which will result in that function being applied to the state when the system call is triggered.

<a id="s52--symbolic-memory-model"></a>

### Symbolic memory model

The default memory model used by angr is inspired by [Mayhem](https://users.ece.cmu.edu/~dbrumley/pdf/Cha%20et%20al._2012_Unleashing%20Mayhem%20on%20Binary%20Code.pdf). This memory model supports limited symbolic reads and writes. If the memory index of a read is symbolic and the range of possible values of this index is too wide, the index is concretized to a single value. If the memory index of a write is symbolic at all, the index is concretized to a single value. This is configurable by changing the memory concretization strategies of `state.memory`.

<a id="s52--symbolic-lengths"></a>

### Symbolic lengths

SimProcedures, and especially system calls such as `read()` and `write()` might run into a situation where the *length* of a buffer is symbolic. In general, this is handled very poorly: in many cases, this length will end up being concretized outright or retroactively concretized in later steps of execution. Even in cases when it is not, the source or destination file might end up looking a bit “weird”.

<a id="s52--division-by-zero"></a>

### Division by Zero

Z3 has some issues with divisions by zero. For example:

```text
>>> z = z3.Solver()
>>> a = z3.BitVec('a', 32)
>>> b = z3.BitVec('b', 32)
>>> c = z3.BitVec('c', 32)
>>> z.add(a/b == c)
>>> z.add(b == 0)
>>> z.check()
>>> print(z.model().eval(b), z.model().eval(a/b))
0 4294967295
```

This makes it very difficult to handle certain situations in Claripy. We post-process the VEX IR itself to explicitly check for zero-divisions and create IRSB side-exits corresponding to the exceptional case, but SimProcedures and custom analysis code may let occurrences of zero divisions split through, which will then cause weird issues in your analysis. Be safe — when dividing, add a constraint against the denominator being zero.


---

<a id="s53"></a>

<a id="s53--intermediate-representation"></a>

## [S53] Intermediate Representation

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


In order to be able to analyze and execute machine code from different CPU architectures, such as MIPS, ARM, and PowerPC in addition to the classic x86, angr performs most of its analysis on an *intermediate representation*, a structured description of the fundamental actions performed by each CPU instruction. By understanding angr’s IR, VEX (which we borrowed from Valgrind), you will be able to write very quick static analyses and have a better understanding of how angr works.

The VEX IR abstracts away several architecture differences when dealing with different architectures, allowing a single analysis to be run on all of them:

- **Register names.** The quantity and names of registers differ between architectures, but modern CPU designs hold to a common theme: each CPU contains several general purpose registers, a register to hold the stack pointer, a set of registers to store condition flags, and so forth. The IR provides a consistent, abstracted interface to registers on different platforms. Specifically, VEX models the registers as a separate memory space, with integer offsets (e.g., AMD64’s `rax` is stored starting at address 16 in this memory space).

- **Memory access.** Different architectures access memory in different ways. For example, ARM can access memory in both little-endian and big-endian modes. The IR abstracts away these differences.

- **Memory segmentation.** Some architectures, such as x86, support memory segmentation through the use of special segment registers. The IR understands such memory access mechanisms.

- **Instruction side-effects.** Most instructions have side-effects. For example, most operations in Thumb mode on ARM update the condition flags, and stack push/pop instructions update the stack pointer. Tracking these side-effects in an *ad hoc* manner in the analysis would be crazy, so the IR makes these effects explicit.

There are lots of choices for an IR. We use VEX, since the uplifting of binary code into VEX is quite well supported. VEX is an architecture-agnostic, side-effects-free representation of a number of target machine languages. It abstracts machine code into a representation designed to make program analysis easier. This representation has four main classes of objects:

- **Expressions.** IR Expressions represent a calculated or constant value. This includes memory loads, register reads, and results of arithmetic operations.

- **Operations.** IR Operations describe a *modification* of IR Expressions. This includes integer arithmetic, floating-point arithmetic, bit operations, and so forth. An IR Operation applied to IR Expressions yields an IR Expression as a result.

- **Temporary variables.** VEX uses temporary variables as internal registers: IR Expressions are stored in temporary variables between use. The content of a temporary variable can be retrieved using an IR Expression. These temporaries are numbered, starting at `t0`. These temporaries are strongly typed (e.g., “64-bit integer” or “32-bit float”).

- **Statements.** IR Statements model changes in the state of the target machine, such as the effect of memory stores and register writes. IR Statements use IR Expressions for values they may need. For example, a memory store *IR Statement* uses an *IR Expression* for the target address of the write, and another *IR Expression* for the content.

- **Blocks.** An IR Block is a collection of IR Statements, representing an extended basic block (termed “IR Super Block” or “IRSB”) in the target architecture. A block can have several exits. For conditional exits from the middle of a basic block, a special *Exit* IR Statement is used. An IR Expression is used to represent the target of the unconditional exit at the end of the block.

VEX IR is actually quite well documented in the `libvex_ir.h` file (<https://github.com/angr/vex/blob/master/pub/libvex_ir.h>) in the VEX repository. For the lazy, we’ll detail some parts of VEX that you’ll likely interact with fairly frequently. To begin with, here are some IR Expressions:

| IR Expression | Evaluated Value | VEX Output Example |
|----|----|----|
| Constant | A constant value. | 0x4:I32 |
| Read Temp | The value stored in a VEX temporary variable. | RdTmp(t10) |
| Get Register | The value stored in a register. | GET:I32(16) |
| Load Memory | The value stored at a memory address, with the address specified by another IR Expression. | LDle:I32 / LDbe:I64 |
| Operation | A result of a specified IR Operation, applied to specified IR Expression arguments. | Add32 |
| If-Then-Else | If a given IR Expression evaluates to 0, return one IR Expression. Otherwise, return another. | ITE |
| Helper Function | VEX uses C helper functions for certain operations, such as computing the conditional flags registers of certain architectures. These functions return IR Expressions. | function_name() |

These expressions are then, in turn, used in IR Statements. Here are some common ones:

| IR Statement | Meaning | VEX Output Example |
|----|----|----|
| Write Temp | Set a VEX temporary variable to the value of the given IR Expression. | WrTmp(t1) = (IR Expression) |
| Put Register | Update a register with the value of the given IR Expression. | PUT(16) = (IR Expression) |
| Store Memory | Update a location in memory, given as an IR Expression, with a value, also given as an IR Expression. | STle(0x1000) = (IR Expression) |
| Exit | A conditional exit from a basic block, with the jump target specified by an IR Expression. The condition is specified by an IR Expression. | if (condition) goto (Boring) 0x4000A00:I32 |

An example of an IR translation, on ARM, is produced below. In the example, the subtraction operation is translated into a single IR block comprising 5 IR Statements, each of which contains at least one IR Expression (although, in real life, an IR block would typically consist of more than one instruction). Register names are translated into numerical indices given to the *GET* Expression and *PUT* Statement. The astute reader will observe that the actual subtraction is modeled by the first 4 IR Statements of the block, and the incrementing of the program counter to point to the next instruction (which, in this case, is located at `0x59FC8`) is modeled by the last statement.

The following ARM instruction:

```text
subs R2, R2, #8
```

Becomes this VEX IR:

```text
t0 = GET:I32(16)
t1 = 0x8:I32
t3 = Sub32(t0,t1)
PUT(16) = t3
PUT(68) = 0x59FC8:I32
```

Now that you understand VEX, you can actually play with some VEX in angr: We use a library called [PyVEX](https://github.com/angr/pyvex) that exposes VEX into Python. In addition, PyVEX implements its own pretty-printing so that it can show register names instead of register offsets in PUT and GET instructions.

PyVEX is accessible through angr through the `Project.factory.block` interface. There are many different representations you could use to access syntactic properties of a block of code, but they all have in common the trait of analyzing a particular sequence of bytes. Through the `factory.block` constructor, you get a `Block` object that can be easily turned into several different representations. Try `.vex` for a PyVEX IRSB, or `.capstone` for a Capstone block.

Let’s play with PyVEX:

```python
>>> import angr

# load the program binary
>>> proj = angr.Project("/bin/true")

# translate the starting basic block
>>> irsb = proj.factory.block(proj.entry).vex
# and then pretty-print it
>>> irsb.pp()

# translate and pretty-print a basic block starting at an address
>>> irsb = proj.factory.block(0x401340).vex
>>> irsb.pp()

# this is the IR Expression of the jump target of the unconditional exit at the end of the basic block
>>> print(irsb.next)

# this is the type of the unconditional exit (e.g., a call, ret, syscall, etc)
>>> print(irsb.jumpkind)

# you can also pretty-print it
>>> irsb.next.pp()

# iterate through each statement and print all the statements
>>> for stmt in irsb.statements:
...     stmt.pp()

# pretty-print the IR expression representing the data, and the *type* of that IR expression written by every store statement
>>> import pyvex
>>> for stmt in irsb.statements:
...     if isinstance(stmt, pyvex.IRStmt.Store):
...         print("Data:",)
...         stmt.data.pp()
...         print("")
...         print("Type:",)
...         print(stmt.data.result_type)
...         print("")

# pretty-print the condition and jump target of every conditional exit from the basic block
>>> for stmt in irsb.statements:
...     if isinstance(stmt, pyvex.IRStmt.Exit):
...         print("Condition:",)
...         stmt.guard.pp()
...         print("")
...         print("Target:",)
...         stmt.dst.pp()
...         print("")

# these are the types of every temp in the IRSB
>>> print(irsb.tyenv.types)

# here is one way to get the type of temp 0
>>> print(irsb.tyenv.types[0])
```

<a id="s53--condition-flags-computation-for-x86-and-arm"></a>

### Condition flags computation (for x86 and ARM)

One of the most common instruction side-effects on x86 and ARM CPUs is updating condition flags, such as the zero flag, the carry flag, or the overflow flag. Computer architects usually put the concatenation of these flags (yes, concatenation of the flags, since each condition flag is 1 bit wide) into a special register (i.e. `EFLAGS`/`RFLAGS` on x86, `APSR`/`CPSR` on ARM). This special register stores important information about the program state, and is critical for correct emulation of the CPU.

VEX uses 4 registers as its “Flag thunk descriptors” to record details of the latest flag-setting operation. VEX has a lazy strategy to compute the flags: when an operation that would update the flags happens, instead of computing the flags, VEX stores a code representing this operation to the `cc_op` pseudo-register, and the arguments to the operation in `cc_dep1` and `cc_dep2`. Then, whenever VEX needs to get the actual flag values, it can figure out what the one bit corresponding to the flag in question actually is, based on its flag thunk descriptors. This is an optimization in the flags computation, as VEX can now just directly perform the relevant operation in the IR without bothering to compute and update the flags’ value.

Amongst different operations that can be placed in `cc_op`, there is a special value 0 which corresponds to `OP_COPY` operation. This operation is supposed to copy the value in `cc_dep1` to the flags. It simply means that `cc_dep1` contains the flags’ value. angr uses this fact to let us efficiently retrieve the flags’ value: whenever we ask for the actual flags, angr computes their value, then dumps them back into `cc_dep1` and sets `cc_op = OP_COPY` in order to cache the computation. We can also use this operation to allow the user to write to the flags: we just set `cc_op = OP_COPY` to say that a new value being set to the flags, then set `cc_dep1` to that new value.


---

<a id="s54"></a>

<a id="s54--java-support"></a>

## [S54] Java Support

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


`angr` also supports symbolically executing Java code and Android apps! This also includes Android apps using a combination of compiled Java and native (C/C++) code.

Warning

Java support is experimental! Contribution from the community is highly encouraged! Pull requests are very welcomed!

We implemented Java support by lifting the compiled Java code, both Java and DEX bytecode, leveraging our Soot Python wrapper: [pysoot](https://github.com/angr/pysoot). `pysoot` extracts a fully serializable interface from Android apps and Java code (unfortunately, as of now, it only works on Linux). For every class of the generated IR (for instance, `SootMethod`), you can nicely print its instructions (in a format similar to `Soot` `shimple`) using `print()` or `str()`.

Note

Windows and macOS support is available on a branch. It should pass all tests and generally work well, but due to issues integrating JPype into CI infrastructure, it has not yet been merged.

We then leverage the generated IR in a new angr engine able to run code in Soot IR: [angr/engines/soot/engine.py](https://github.com/angr/angr/blob/master/angr/engines/soot/engine.py). This engine is also able to automatically switch to executing native code if the Java code calls any native method using the JNI interface.

Together with the symbolic execution, we also implemented some basic static analysis, specifically a basic CFG reconstruction analysis. Moreover, we added support for string constraint solving, modifying claripy and using the CVC4 solver.

<a id="s54--how-to-install"></a>

### How to install

Java support requires the `pysoot` package, which is not included in the default angr installation. You can install it from GitHub using pip:

```bash
git clone https://github.com/angr/pysoot.git
cd pysoot
pip install -e .
```

Alternatively, pysoot can be installed with the setup script in angr-dev:

```bash
./setup.sh pysoot
```

<a id="s54--analyzing-android-apps"></a>

#### Analyzing Android apps.

Analyzing Android apps (`.APK` files, containing Java code compiled to the `DEX` format) requires the Android SDK. Typically, it is installed in `<HOME>/Android/SDK/platforms/platform-XX/android.jar`, where `XX` is the Android SDK version used by the app you want to analyze (you may want to install all the platforms required by the Android apps you want to analyze).

<a id="s54--examples"></a>

### Examples

There are multiple examples available:

- Easy Java crackmes: [java_crackme1](https://github.com/angr/angr-examples/tree/master/examples/java_crackme1), [java_simple3](https://github.com/angr/angr-examples/tree/master/examples/java_simple3), [java_simple4](https://github.com/angr/angr-examples/tree/master/examples/java_simple4)

- A more complex example (solving a CTF challenge): [ictf2017_javaisnotfun](https://github.com/angr/angr-examples/tree/master/examples/ictf2017_javaisnotfun), [blogpost](https://angr.io/blog/java_angr/)

- Symbolically executing an Android app (using a mix of Java and native code): [java_androidnative1](https://github.com/angr/angr-examples/tree/master/examples/java_androidnative1)

- Many other low-level tests: [test_java](https://github.com/angr/angr/blob/master/tests/engines/test_java.py)


---

<a id="s55"></a>

<a id="s55--what-s-up-with-mixins-anyway"></a>

## [S55] What’s Up With Mixins, Anyway?

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


If you are trying to work more intently with the deeper parts of angr, you will need to understand one of the design patterns we use frequently: the mixin pattern.

In brief, the mixin pattern is where Python’s subclassing features is used not to implement IS-A relationships (a Child is a kind of Person) but instead to implement pieces of functionality for a type in different classes to make more modular and maintainable code. Here’s an example of the mixin pattern in action:

```python
class Base:
    def add_one(self, v):
        return v + 1

class StringsMixin(Base):
    def add_one(self, v):
        coerce = type(v) is str
        if coerce:
            v = int(v)
        result = super().add_one(v)
        if coerce:
            result = str(result)
        return result

class ArraysMixin(Base):
    def add_one(self, v):
        if type(v) is list:
            return [super().add_one(v_x) for v_x in v]
        else:
            return super().add_one(v)

class FinalClass(ArraysMixin, StringsMixin, Base):
    pass
```

With this construction, we are able to define a very simple interface in the `Base` class, and by “mixing in” two mixins, we can create the `FinalClass` which has the same interface but with additional features. This is accomplished through Python’s powerful multiple inheritance model, which handles method dispatch by creating a *method resolution order*, or MRO, which is unsurprisingly a list which determines the order in which methods are called as execution proceeds through `super()` calls. You can view a class’ MRO as such:

```python
FinalClass.__mro__

(FinalClass, ArraysMixin, StringsMixin, Base, object)
```

This means that when we take an instance of `FinalClass` and call `add_one()`, Python first checks to see if `FinalClass` defines an `add_one`, and then `ArraysMixin`, and so on and so forth. Furthermore, when `ArraysMixin` calls `super().add_one()`, Python will skip past `ArraysMixin` in the MRO, first checking if `StringsMixin` defines an `add_one`, and so forth.

Because multiple inheritance can create strange dependency graphs in the subclass relationship, there are rules for generating the MRO and for determining if a given mix of mixins is even allowed. This is important to understand when building complex classes with many mixins which have dependencies on each other. In short: left-to-right, depth-first, but deferring any base classes which are shared by multiple subclasses (the merge point of a diamond pattern in the inheritance graph) until the last point where they would be encountered in this depth-first search. For example, if you have classes A, B(A), C(B), D(A), E(C, D), then the method resolution order will be E, C, B, D, A. If there is any case in which the MRO would be ambiguous, the class construction is illegal and will throw an exception at import time.

This is complicated! If you find yourself confused, the canonical document explaining the rationale, history, and mechanics of Python’s multiple inheritance can be found [here](https://www.python.org/download/releases/2.3/mro/).

<a id="s55--mixins-in-claripy-solvers"></a>

### Mixins in Claripy Solvers

<a id="s55--id1"></a>

Todo

Write this section

<a id="s55--mixins-in-angr-engines"></a>

### Mixins in angr Engines

The main entry point to a SimEngine is `process()`, but how do we determine what that does?

The mixin model is used in SimEngine and friends in order to allow pieces of functionality to be reused between static and symbolic analyses. The default engine, `UberEngine`, is defined as follows:

```python
class UberEngine(SimEngineFailure,
   SimEngineSyscall,
   HooksMixin,
   SimEngineUnicorn,
   SuperFastpathMixin,
   TrackActionsMixin,
   SimInspectMixin,
   HeavyResilienceMixin,
   SootMixin,
   HeavyVEXMixin
):
    pass
```

Each of these mixins provides either execution through a different medium or some additional instrumentation feature. Though they are not listed here explicitly, there are some base classes implicit to this hierarchy which set up the way this class is traversed. Most of these mixins inherit from `SuccessorsMixin`, which is what provides the basic `process()` implementation. This function sets up the `SimSuccessors` for the rest of the mixins to fill in, and then calls `process_successors()`, which each of the mixins which provide some mode of execution implement. If the mixin can handle the step, it does so and returns, otherwise it calls `super().process_successors()`. In this way, the MRO for the engine class determines what the order of precedence for the engine’s pieces is.

<a id="s55--heavyvexmixin-and-friends"></a>

#### HeavyVEXMixin and friends

Let’s take a closer look at the last mixin, `HeavyVEXMixin`. If you look at the module hierarchy of the angr `engines` submodule, you will see that the `vex` submodule has a lot of pieces in it which are organized by how tightly tied to particular state types or data types they are. The heavy VEX mixin is one version of the culmination of all of these. Let’s look at its definition:

```python
class HeavyVEXMixin(SuccessorsMixin, ClaripyDataMixin, SimStateStorageMixin, VEXMixin, VEXLifter):
    ...
    # a WHOLE lot of implementation
```

So, the heavy VEX mixin is meant to provide fully instrumented symbolic execution on a SimState. What does this entail? The mixins tell the tale.

First, the plain `VEXMixin`. This mixin is designed to provide the barest-bones framework for processing a VEX block. Take a look at its [source code](https://github.com/angr/angr/blob/master/angr/engines/vex/light/light.py). Its main purpose is to perform the preliminary digestion of the VEX IRSB and dispatch processing of it to methods which are provided by mixins - look at the methods which are either `pass` or `return NotImplemented`. Notice that absolutely none of its code makes any assumption whatsoever of what the type of `state` is or even what the type of the data words inside `state` are. This job is delegated to other mixins, making the `VEXMixin` an appropriate base class for literally any analysis on VEX blocks.

The next-most interesting mixin is the `ClaripyDataMixin`, whose source code is [here](https://github.com/angr/angr/blob/master/angr/engines/vex/claripy/datalayer.py). This mixin actually integrates the fact that we are executing over the domain of Claripy ASTs. It does this by implementing some of the methods which are unimplemented in the `VEXMixin`, most importantly the `ITE` expression, all the operations, and the clean helpers.

In terms of what it looks like to actually touch the SimState, the `SimStateStorageMixin` provides the glue between the `VEXMixin`’s interface for memory writes et al and SimState’s interface for memory writes and such. It is unremarkable, except for a small interaction between it and the `ClaripyDataMixin`. The Claripy mixin also overrides the memory/register read/write functions, for the purpose of converting between the bitvector and floating-point types, since the vex interface expects to be able to load and store floats, but the SimState interface wants to load and store only bitvectors. Because of this, *the claripy mixin must come before the storage mixin in the MRO*. This is very much an interaction like the one in the add_one example at the start of this page - one mixin serves as a data filtering layer for another mixin.

<a id="s55--instrumenting-the-data-layer"></a>

#### Instrumenting the data layer

Let’s turn our attention to a mixin which is not included in the `HeavyVEXMixin` but rather mixed into the `UberEngine` formula explicitly: the `TrackActionsMixin`. This mixin implements “SimActions”, which is angr parlance for dataflow tracking. Again, look at the [source code](https://github.com/angr/angr/blob/master/angr/engines/vex/heavy/actions.py). The way it does this is that it *wraps and unwraps the data layer* to pass around additional information about data flows. Look at how it instruments `RdTmp`, for instance. It immediately `super()`-calls to the next method in the MRO, but instead of returning that data it returns a tuple of the data and its dependencies, which depending on whether you want temporary variables to be atoms in the dataflow model, will either be just the tmp which was read or the dependencies of the value written to that tmp.

This pattern continues for every single method that this mixin touches - any expression it receives must be unpacked into the expression and its dependencies, and any result must be packaged with its dependencies before it is returned. This works because the mixin above it makes no assumptions about what data it is passing around, and the mixin below it never gets to see any dependencies whatsoever. In fact, there could be multiple mixins performing this kind of wrap-unwrap trick and they could all coexist peacefully!

Note that a mixin which instruments the data layer in this way is *obligated* to override *every single method which takes or returns an expression value*, even if it doesn’t perform any operation on the expression other than doing the wrapping and unwrapping. To understand why, imagine that the mixin does not override the `handle_vex_const` expression, so immediate value loads are not annotated with dependencies. The expression value which will be returned from the mixin which does provide `handle_vex_const` will not be a tuple of (expression, deps), it will just be the expression. Imagine this execution is taking place in the context of a `WrTmp(t0, Const(0))`. The const expression will be passed down to the `WrTmp` handler along with the identifier of the tmp to write to. However, since `handle_vex_stmt_WrTmp` *will* be overridden by our mixin which touches the data layer, it expects to be passed the tuple including the deps, and so it will crash when trying to unpack the not-a-tuple value.

In this way, you can sort of imagine that a mixin which instruments the data layer in this way is actually creating a contract within Python’s nonexistent typesystem - you are guaranteed to receive back any types you return, but you must pass down any types you receive as return values from below.

<a id="s55--mixins-in-the-memory-model"></a>

### Mixins in the memory model

<a id="s55--id4"></a>

Todo

write this section


---

<a id="s56"></a>

<a id="s56--understanding-the-execution-pipeline"></a>

## [S56] Understanding the Execution Pipeline

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


If you’ve made it this far you know that at its core, angr is a highly flexible and intensely instrumentable emulator. In order to get the most mileage out of it, you’ll want to know what happens at every step of the way when you say `simgr.run()`.

This is intended to be a more advanced document; you’ll need to understand the function and intent of `SimulationManager`, `ExplorationTechnique`, `SimState`, and `SimEngine` in order to understand what we’re talking about at times! You may want to have the angr source open to follow along with this.

At every step along the way, each function will take `**kwargs` and pass them along to the next function in the hierarchy, so you can pass parameters to any point in the hierarchy and they will trickle down to everything below.

<a id="s56--simulation-managers"></a>

### Simulation Managers

So you’ve set your analysis in motion. Time to begin our journey.

<a id="s56--run"></a>

#### `run()`

`SimulationManager.run()` takes several optional parameters, all of which control when to break out of the stepping loop. Notably, `n`, and `until`. `n` is used immediately - the run function loops, calling the `step()` function and passing on all its parameters until either `n` steps have happened or some other termination condition has occurred. If `n` is not provided, it defaults to 1, unless an `until` function is provided, in which case there will be no numerical cap on the loop. Additionally, the stash that is being used is taken into consideration, as if it becomes empty execution must terminate.

So, in summary, when you call `run()`, `step()` will be called in a loop until any of the following:

1.  The `n` number of steps have elapsed

2.  The `until` function returns true

3.  The exploration techniques `complete()` hooks (combined via the `SimulationManager.completion_mode` parameter/attribute - it is by default the `any` builtin function but can be changed to `all` for example) indicate that the analysis is complete

4.  The stash being executed becomes empty

<a id="s56--an-aside-explore"></a>

##### An aside: `explore()`

`SimulationManager.explore()` is a very thin wrapper around `run()` which adds the `Explorer` exploration technique, since performing one-off explorations is a very common action. Its code in its entirety is below:

```text
num_find += len(self._stashes[find_stash]) if find_stash in self._stashes else 0
tech = self.use_technique(Explorer(find, avoid, find_stash, avoid_stash, cfg, num_find))

try:
    self.run(stash=stash, n=n, **kwargs)
finally:
    self.remove_technique(tech)

return self
```

<a id="s56--exploration-technique-hooking"></a>

#### Exploration technique hooking

From here down, every function in the simulation manager can be instrumented by an exploration technique. The exact mechanism through which this works is that when you call `SimulationManager.use_technique()`, angr monkeypatches the simulation manager to replace any function implemented in the exploration technique’s body with a function which will first call the exploration technique’s function, and then on the second call will call the original function. This is somewhat messy to implement and certainly not thread safe by any means, but does produce a clean and powerful interface for exploration techniques to instrument stepping behavior, either before or after the original function is called, even choosing whether or not to call the original function whatsoever. Additionally, it allows multiple exploration techniques to hook the same function, as the monkeypatched function simply becomes the “original” function for the next-applied hook.

<a id="s56--step"></a>

#### `step()`

There is a lot of complicated logic in `step()` to handle degenerate cases - mostly implementing the population of the `deadended` stash, the `save_unsat` option, and calling the `filter()` exploration technique hooks. Beyond this, though, most of the logic is looping through the stash specified by the `stash` argument and calling `step_state()` on each state, then applying the dict result of `step_state()` to the stash list. Finally, if the `step_func` parameter is provided, it is called with the simulation manager as a parameter before the step ends.

<a id="s56--step-state"></a>

#### `step_state()`

The default `step_state()`, which can be overridden or instrumented by exploration techniques, is also simple - it calls `successors()`, which returns a `SimSuccessors` object, and then translates it into a dict mapping stash names to new states which should be added to that stash. It also implements error handling - if `successors()` throws an error, it will be caught and an `ErrorRecord` will be inserted into `SimulationManager.errored`.

<a id="s56--successors"></a>

#### `successors()`

We’ve almost made it out of SimulationManager. `successors()`, which can also be instrumented by exploration techniques, is supposed to take a state and step it forward, returning a `SimSuccessors` object categorizing its successors independently of any stash logic. If the `successor_func` parameter was provided, it is used and its return value is returned directly. If this parameter was not provided, we use the `project.factory.successors` method to tick the state forward and get our `SimSuccessors`.

<a id="s56--the-engine"></a>

### The Engine

When we get to the actual successors generation, we need to figure out how to actually perform the execution. Hopefully, the angr documentation has been organized in a way such that by the time you reach this page, you know that a `SimEngine` is a device that knows how to take a state and produce its successors. There is only one “default engine” per project, but you can provide the `engine` parameter to specify which engine will be used to perform the step.

Keep in mind that this parameter can be provided way at the top, to `.step()`, `.explore()`, `.run()` or anything else that starts execution, and they will be filtered down to this level. Any additional parameters will continue being passed down, until they reach the part of the engine they are intended for. The engine will discard any parameters it doesn’t understand.

Generally, the main entry point of an engine is `SimEngine.process()`, which can return whatever result it likes, but for simulation managers, engines are required to use `SuccessorsMixin`, which provides a `process()` method, which creates a `SimSuccessors` object and then calls `process_successors()` so that other mixins can fill it out.

angr’s default engine, the `UberEngine`, contains several mixins which provide the `process_successors()` method:

- `SimEngineFailure` - handles stepping states with degenerate jumpkinds

- `SimEngineSyscall` - handles stepping states which have performed a syscall and need it executed

- `HooksMixin` - handles stepping states which have reached a hooked address and need the hook executed

- `SimEngineUnicorn` - executes machine code via the unicorn engine

- `SootMixin` - executes java bytecode via the SOOT IR

- `HeavyVEXMixin` - executes machine code via the VEX IR

Each of these mixins is implemented to fill out the `SimSuccessors` object if they can handle the current state, otherwise they call `super()` to pass the job on to the next class in the stack.

<a id="s56--engine-mixins"></a>

### Engine mixins

`SimEngineFailure` handles error cases. It is only used when the previous jumpkind is one of `Ijk_EmFail`, `Ijk_MapFail`, `Ijk_Sig*`, `Ijk_NoDecode` (but only if the address is not hooked), or `Ijk_Exit`. In the first four cases, its action is to raise an exception. In the last case, its action is to simply produce no successors.

`SimEngineSyscall` services syscalls. It is used when the previous jumpkind is anything of the form `Ijk_Sys*`. It works by making a call into `SimOS` to retrieve the SimProcedure that should be run to respond to this syscall, and then running it! Pretty simple.

`HooksMixin` provides the hooking functionality in angr. It is used when a state is at an address that is hooked, and the previous jumpkind is *not* `Ijk_NoHook`. It simply looks up the associated SimProcedure and runs it on the state! It also takes the parameter `procedure`, which will cause the given procedure to be run for the current step even if the address is not hooked.

`SimEngineUnicorn` performs concrete execution with the Unicorn Engine. It is used when the state option `o.UNICORN` is enabled, and a myriad of other conditions designed for maximum efficiency (described below) are met.

`SootMixin` performs execution over the SOOT IR. Not very important unless you are analyzing java bytecode, in which case it is very important.

`SimEngineVEX` is the big fellow. It is used whenever any of the previous can’t be used. It attempts to lift bytes from the current address into an IRSB, and then executes that IRSB symbolically. There are a huge number of parameters that can control this process, so it is best to reference the API doc for `angr.engines.vex.engine.SimEngineVEX.process()` describing them.

The exact process by which SimEngineVEX digs into an IRSB is a little complicated, but essentially it runs all the block’s statements in order. This code is worth reading if you want to see the true inner core of angr’s symbolic execution.

<a id="s56--when-using-unicorn-engine"></a>

### When using Unicorn Engine

If you add the `o.UNICORN` state option, at every step `SimEngineUnicorn` will be invoked, and try to see if it is allowed to use Unicorn to execute concretely.

What you REALLY want to do is to add the predefined set `o.unicorn` (lowercase) of options to your state:

```python
unicorn = { UNICORN, UNICORN_SYM_REGS_SUPPORT, INITIALIZE_ZERO_REGISTERS, UNICORN_HANDLE_TRANSMIT_SYSCALL }
```

These will enable some additional functionalities and defaults which will greatly enhance your experience. Additionally, there are a lot of options you can tune on the `state.unicorn` plugin.

A good way to understand how unicorn works is by examining the logging output (`logging.getLogger('angr.engines.unicorn_engine').setLevel('DEBUG'); logging.getLogger('angr.state_plugins.unicorn_engine').setLevel('DEBUG')` from a sample run of unicorn.

```text
INFO    | 2017-02-25 08:19:48,012 | angr.state_plugins.unicorn | started emulation at 0x4012f9 (1000000 steps)
```

Here, angr diverts to unicorn engine, beginning with the basic block at 0x4012f9. The maximum step count is set to 1000000, so if execution stays in Unicorn for 1000000 blocks, it’ll automatically pop out. This is to avoid hanging in an infinite loop. The block count is configurable via the `state.unicorn.max_steps` variable.

```text
INFO    | 2017-02-25 08:19:48,014 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,016 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,019 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
INFO    | 2017-02-25 08:19:48,022 | angr.state_plugins.unicorn | mmap [0x602000, 0x602fff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,023 | angr.state_plugins.unicorn | mmap [0x400000, 0x400fff], 5
INFO    | 2017-02-25 08:19:48,025 | angr.state_plugins.unicorn | mmap [0x7000000, 0x7000fff], 5
```

angr performs lazy mapping of data that is accessed by unicorn engine, as it is accessed. 0x401000 is the page of instructions that it is executing, 0x7fffffffffe0000 is the stack, and so on. Some of these pages are symbolic, meaning that they contain at least some data that, when accessed, will cause execution to abort out of Unicorn.

```text
INFO    | 2017-02-25 08:19:48,037 | angr.state_plugins.unicorn | finished emulation at 0x7000080 after 3 steps: STOP_STOPPOINT
```

Execution stays in Unicorn for 3 basic blocks (a computational waste, considering the required setup), after which it reaches a simprocedure location and jumps out to execute the simproc in angr.

```text
INFO    | 2017-02-25 08:19:48,076 | angr.state_plugins.unicorn | started emulation at 0x40175d (1000000 steps)
INFO    | 2017-02-25 08:19:48,077 | angr.state_plugins.unicorn | mmap [0x401000, 0x401fff], 5 (symbolic)
INFO    | 2017-02-25 08:19:48,079 | angr.state_plugins.unicorn | mmap [0x7fffffffffe0000, 0x7fffffffffeffff], 3 (symbolic)
INFO    | 2017-02-25 08:19:48,081 | angr.state_plugins.unicorn | mmap [0x6010000, 0x601ffff], 3
```

After the simprocedure, execution jumps back into Unicorn.

```text
WARNING | 2017-02-25 08:19:48,082 | angr.state_plugins.unicorn | fetching empty page [0x0, 0xfff]
INFO    | 2017-02-25 08:19:48,103 | angr.state_plugins.unicorn | finished emulation at 0x401777 after 1 steps: STOP_EXECNONE
```

Execution bounces out of Unicorn almost right away because the binary accessed the zero-page.

```text
INFO    | 2017-02-25 08:19:48,120 | angr.engines.unicorn_engine | not enough runs since last unicorn (100)
INFO    | 2017-02-25 08:19:48,125 | angr.engines.unicorn_engine | not enough runs since last unicorn (99)
```

To avoid thrashing in and out of Unicorn (which is expensive), we have cooldowns (attributes of the `state.unicorn` plugin) that wait for certain conditions to hold (i.e., no symbolic memory accesses for X blocks) before jumping back into unicorn when a unicorn run is aborted due to anything but a simprocedure or syscall. Here, the condition it’s waiting for is for 100 blocks to be executed before jumping back in.


---

<a id="s57"></a>

<a id="s57--optimization-considerations"></a>

## [S57] Optimization considerations

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


The performance of angr as an analysis tool or emulator is greatly handicapped by the fact that lots of it is written in Python. Regardless, there are a lot of optimizations and tweaks you can use to make angr faster and lighter.

<a id="s57--general-speed-tips"></a>

### General speed tips

- *Use pypy*. [Pypy](http://pypy.org/) is an alternate Python interpreter that performs optimized jitting of Python code. In our tests, it’s a 10x speedup out of the box.

- *Only use the SimEngine mixins that you need*. SimEngine uses a mixin model which allows you to add and remove features by constructing new classes. The default engine mixes in every possible features, and the consequence of that is that it is slower than it needs to be. Look at the definition for `UberEngine` (the default SimEngine), copy its declaration, and remove all the base classes which provide features you don’t need.

- *Don’t load shared libraries unless you need them*. The default setting in angr is to try at all costs to find shared libraries that are compatible with the binary you’ve loaded, including loading them straight out of your OS libraries. This can complicate things in a lot of scenarios. If you’re performing an analysis that’s anything more abstract than bare-bones symbolic execution, ESPECIALLY control-flow graph construction, you might want to make the tradeoff of sacrificing accuracy for tractability. angr does a reasonable job of making sane things happen when library calls to functions that don’t exist try to happen.

- *Use hooking and SimProcedures*. If you’re enabling shared libraries, then you definitely want to have SimProcedures written for any complicated library function you’re jumping into. If there’s no autonomy requirement for this project, you can often isolate individual problem spots where analysis hangs up and summarize them with a hook.

- *Use SimInspect*. [SimInspect](#s75--breakpoints) is the most underused and one of the most powerful features of angr. You can hook and modify almost any behavior of angr, including memory index resolution (which is often the slowest part of any angr analysis).

- *Write a concretization strategy*. A more powerful solution to the problem of memory index resolution is a [concretization strategy](https://github.com/angr/angr/tree/master/angr/concretization_strategies).

- *Use the Replacement Solver*. You can enable it with the `angr.options.REPLACEMENT_SOLVER` state option. The replacement solver allows you to specify AST replacements that are applied at solve-time. If you add replacements so that all symbolic data is replaced with concrete data when it comes time to do the solve, the runtime is greatly reduced. The API for adding a replacement is `state.se._solver.add_replacement(old, new)`. The replacement solver is a bit finicky, so there are some gotchas, but it’ll definitely help.

<a id="s57--if-you-re-performing-lots-of-concrete-or-partially-concrete-execution"></a>

### If you’re performing lots of concrete or partially-concrete execution

- *Use the unicorn engine*. If you have [unicorn engine](https://github.com/unicorn-engine/unicorn/) installed, angr can be built to take advantage of it for concrete emulation. To enable it, add the options in the set `angr.options.unicorn` to your state. Keep in mind that while most items under `angr.options` are individual options, `angr.options.unicorn` is a bundle of options, and is thus a set. *NOTE*: At time of writing the official version of unicorn engine will not work with angr - we have a lot of patches to it to make it work well with angr. They’re all pending pull requests at this time, so sit tight. If you’re really impatient, ping us about uploading our fork!

- *Enable fast memory and fast registers*. The state options `angr.options.FAST_MEMORY` and `angr.options.FAST_REGISTERS` will do this. These will switch the memory/registers over to a less intensive memory model that sacrifices accuracy for speed. TODO: document the specific sacrifices. Should be safe for mostly concrete access though. NOTE: not compatible with concretization strategies.

- *Concretize your input ahead of time*. This is the approach taken by [driller](https://sites.cs.ucsb.edu/~vigna/publications/2016_NDSS_Driller.pdf). When creating a state with `entry_state` or the like, you can create a SimFile filled with symbolic data, pass it to the initialization function as an argument `entry_state(..., stdin=my_simfile)`, and then constrain the symbolic data in the SimFile to what you want the input to be. If you don’t require any tracking of the data coming from stdin, you can forego the symbolic part and just fill it with concrete data. If there are other sources of input besides standard input, do the same for those.

- *Use the afterburner*. While using unicorn, if you add the `UNICORN_THRESHOLD_CONCRETIZATION` state option, angr will accept thresholds after which it causes symbolic values to be concretized so that execution can spend more time in Unicorn. Specifically, the following thresholds exist:

  - `state.unicorn.concretization_threshold_memory` - this is the number of times a symbolic variable, stored in memory, is allowed to kick execution out of Unicorn before it is forcefully concretized and forced into Unicorn anyways.

  - `state.unicorn.concretization_threshold_registers` - this is the number of times a symbolic variable, stored in a register, is allowed to kick execution out of Unicorn before it is forcefully concretized and forced into Unicorn anyways.

  - `state.unicorn.concretization_threshold_instruction` - this is the number of times that any given instruction can force execution out of Unicorn (by running into symbolic data) before any symbolic data encountered at that instruction is concretized to force execution into Unicorn.

  You can get further control of what is and isn’t concretized with the following sets:

  - `state.unicorn.always_concretize` - a set of variable names that will always be concretized to force execution into unicorn (in fact, the memory and register thresholds just end up causing variables to be added to this list).

  - `state.unicorn.never_concretize` - a set of variable names that will never be concretized and forced into Unicorn under any condition.

  - `state.unicorn.concretize_at` - a set of instruction addresses at which data should be concretized and forced into Unicorn. The instruction threshold causes addresses to be added to this set.

  Once something is concretized with the afterburner, you will lose track of that variable. The state will still be consistent, but you’ll lose dependencies, as the stuff that comes out of Unicorn is just concrete bits with no memory of what variables they came from. Still, this might be worth it for the speed in some cases, if you know what you want to (or do not want to) concretize.

<a id="s57--memory-optimization"></a>

### Memory optimization

The golden rule for memory optimization is to make sure you’re not keeping any references to data you don’t care about anymore, especially related to states which have been left behind. If you find yourself running out of memory during analysis, the first thing you want to do is make sure you haven’t caused a state explosion, meaning that the analysis is accumulating program states too quickly. If the state count is in control, then you can start looking for reference leaks. A good tool to do this with is <https://github.com/rhelmot/dumpsterdiver>, which gives you an interactive prompt for exploring the reference graph of a Python process.

One specific consideration that should be made when analyzing programs with very long paths is that the state history is designed to accumulate data infinitely. This is less of a problem than it could be because the data is stored in a smart tree structure and never copied, but it will accumulate infinitely. To downsize a state’s history and free all data related to old steps, call `state.history.trim()`.

One *particularly* problematic member of the history dataset is the basic block trace and the stack pointer trace. When using unicorn engine, these lists of ints can become huge very very quickly. To disable unicorn’s capture of ip and sp data, remove the state options `UNICORN_TRACK_BBL_ADDRS` and `UNICORN_TRACK_STACK_POINTERS`.


---

<a id="s58"></a>

<a id="s58--working-with-data-and-conventions"></a>

## [S58] Working with Data and Conventions

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


Frequently, you’ll want to access structured data from the program you’re analyzing. angr has several features to make this less of a headache.

<a id="s58--working-with-types"></a>

### Working with types

angr has a system for representing types. These SimTypes are found in `angr.types` - an instance of any of these classes represents a type. Many of the types are incomplete unless they are supplemented with a SimState - their size depends on the architecture you’re running under. You may do this with `ty.with_arch(arch)`, which returns a copy of itself, with the architecture specified.

angr also has a light wrapper around `pycparser`, which is a C parser. This helps with getting instances of type objects:

```python
>>> import angr, monkeyhex

# note that SimType objects have their __repr__ defined to return their c type name,
# so this function actually returned a SimType instance.
>>> angr.types.parse_type('int')
int

>>> angr.types.parse_type('char **')
char**

>>> angr.types.parse_type('struct aa {int x; long y;}')
struct aa

>>> angr.types.parse_type('struct aa {int x; long y;}').fields
OrderedDict([('x', int), ('y', long)])
```

Additionally, you may parse C definitions and have them returned to you in a dict, either of variable/function declarations or of newly defined types:

```python
>>> angr.types.parse_defns("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
{'x': int, 'y': struct llist*}

>>> defs = angr.types.parse_types("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
>>> defs
{'struct llist': struct llist, 'list_node': struct llist}

# if you want to get both of these dicts at once, use parse_file, which returns both in a tuple.
>>> angr.types.parse_file("int x; typedef struct llist { char* str; struct llist *next; } list_node; list_node *y;")
({'x': int, 'y': struct llist*},
 {'struct llist': struct llist, 'list_node': struct llist})

>>> defs['list_node'].fields
OrderedDict([('str', char*), ('next', struct llist*)])

>>> defs['list_node'].fields['next'].pts_to.fields
OrderedDict([('str', char*), ('next', struct llist*)])

# If you want to get a function type and you don't want to construct it manually,
# you can use parse_type
>>> angr.types.parse_type("int (int y, double z)")
(int, double) -> int
```

And finally, you can register struct definitions for future use:

```python
>>> angr.types.register_types(angr.types.parse_type('struct abcd { int x; int y; }'))
>>> angr.types.register_types(angr.types.parse_types('typedef long time_t;'))
>>> angr.types.parse_defns('struct abcd a; time_t b;')
{'a': struct abcd, 'b': long}
```

These type objects aren’t all that useful on their own, but they can be passed to other parts of angr to specify data types.

<a id="s58--accessing-typed-data-from-memory"></a>

### Accessing typed data from memory

Now that you know how angr’s type system works, you can unlock the full power of the `state.mem` interface! Any type that’s registered with the types module can be used to extract data from memory.

```python
>>> p = angr.Project('examples/fauxware/fauxware')
>>> s = p.factory.entry_state()
>>> s.mem[0x601048]
<<untyped> <unresolvable> at 0x601048>

>>> s.mem[0x601048].long
<long (64 bits) <BV64 0x4008d0> at 0x601048>

>>> s.mem[0x601048].long.resolved
<BV64 0x4008d0>

>>> s.mem[0x601048].long.concrete
0x4008d0

>>> s.mem[0x601048].struct.abcd
<struct abcd {
  .x = <BV32 0x4008d0>,
  .y = <BV32 0x0>
} at 0x601048>

>>> s.mem[0x601048].struct.abcd.x
<int (32 bits) <BV32 0x4008d0> at 0x601048>

>>> s.mem[0x601048].struct.abcd.y
<int (32 bits) <BV32 0x0> at 0x60104c>

>>> s.mem[0x601048].deref
<<untyped> <unresolvable> at 0x4008d0>

>>> s.mem[0x601048].deref.string
<string_t <BV64 0x534f534e45414b59> at 0x4008d0>

>>> s.mem[0x601048].deref.string.resolved
<BV64 0x534f534e45414b59>

>>> s.mem[0x601048].deref.string.concrete
b'SOSNEAKY'
```

The interface works like this:

- You first use \[array index notation\] to specify the address you’d like to load from

- If at that address is a pointer, you may access the `deref` property to return a SimMemView at the address present in memory.

- You then specify a type for the data by simply accessing a property of that name. For a list of supported types, look at `state.mem.types`.

- You can then *refine* the type. Any type may support any refinement it likes. Right now the only refinements supported are that you may access any member of a struct by its member name, and you may index into a string or array to access that element.

- If the address you specified initially points to an array of that type, you can say `.array(n)` to view the data as an array of n elements.

- Finally, extract the structured data with `.resolved` or `.concrete`. `.resolved` will return bitvector values, while `.concrete` will return integer, string, array, etc values, whatever best represents the data.

- Alternately, you may store a value to memory, by assigning to the chain of properties that you’ve constructed. Note that because of the way Python works, `x = s.mem[...].prop; x = val` will NOT work, you must say `s.mem[...].prop = val`.

If you define a struct using `register_types(parse_type(struct_expr))`, you can access it here as a type:

```python
>>> s.mem[p.entry].struct.abcd
<struct abcd {
  .x = <BV32 0x8949ed31>,
  .y = <BV32 0x89485ed1>
} at 0x400580>
```

<a id="s58--working-with-calling-conventions"></a>

### Working with Calling Conventions

A calling convention is the specific means by which code passes arguments and return values through function calls. angr’s abstraction of calling conventions is called SimCC. You can construct new SimCC instances through the angr object factory, with `p.factory.cc(...)`. This will give a calling convention which is guessed based your guest architecture and OS. If angr guesses wrong, you can explicitly pick one of the calling conventions in the `angr.calling_conventions` module.

If you have a very wacky calling convention, you can use `angr.calling_conventions.SimCCUsercall`. This will ask you to specify locations for the arguments and the return value. To do this, use instances of the `SimRegArg` or `SimStackArg` classes. You can find them in the factory - `p.factory.cc.Sim*Arg`.

Once you have a SimCC object, you can use it along with a SimState object and a function prototype (a SimTypeFunction) to extract or store function arguments more cleanly. Take a look at the `angr.calling_conventions.SimCC>` for details. Alternately, you can pass it to an interface that can use it to modify its own behavior, like `p.factory.call_state`, or…

<a id="s58--callables"></a>

### Callables

Callables are a Foreign Functions Interface (FFI) for symbolic execution. Basic callable usage is to create one with `myfunc = p.factory.callable(addr)`, and then call it! `result = myfunc(args, ...)` When you call the callable, angr will set up a `call_state` at the given address, dump the given arguments into memory, and run a `path_group` based on this state until all the paths have exited from the function. Then, it merges all the result states together, pulls the return value out of that state, and returns it.

All the interaction with the state happens with the aid of a `SimCC` and a `SimTypeFunction`, to tell where to put the arguments and where to get the return value. It will try to use a sane default for the architecture, but if you’d like to customize it, you can pass a `SimCC` object in the `cc` keyword argument when constructing the callable. The `SimTypeFunction` is required - you must pass the `prototype` parameter. If you pass a string to this parameter it will be parsed as a function declaration.

You can pass symbolic data as function arguments, and everything will work fine. You can even pass more complicated data, like strings, lists, and structures as native Python data (use tuples for structures), and it’ll be serialized as cleanly as possible into the state. If you’d like to specify a pointer to a certain value, you can wrap it in a `PointerWrapper` object, available as `p.factory.callable.PointerWrapper`. The exact semantics of how pointer-wrapping work are a little confusing, but they can be boiled down to “unless you specify it with a PointerWrapper or a specific SimArrayType, nothing will be wrapped in a pointer automatically unless it gets to the end and it hasn’t yet been wrapped in a pointer yet and the original type is a string, array, or tuple.” The relevant code is actually in SimCC - it’s the `setup_callsite` function.

If you don’t care for the actual return value of the call, you can say `func.perform_call(arg, ...)`, and then the properties `func.result_state` and `func.result_path_group` will be populated. They will actually be populated even if you call the callable normally, but you probably care about them more in this case!


---

<a id="s59"></a>

<a id="s59--backward-slicing"></a>

## [S59] Backward Slicing

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


A *program slice* is a subset of statements that is obtained from the original program, usually by removing zero or more statements. Slicing is often helpful in debugging and program understanding. For instance, it’s usually easier to locate the source of a variable on a program slice.

A backward slice is constructed from a *target* in the program, and all data flows in this slice end at the *target*.

angr has a built-in analysis, called `BackwardSlice`, to construct a backward program slice. This section will act as a how-to for angr’s `BackwardSlice` analysis, and followed by some in-depth discussion over the implementation choices and limitations.

<a id="s59--first-step-first"></a>

### First Step First

To build a `BackwardSlice`, you will need the following information as input.

- **Required** CFG. A control flow graph (CFG) of the program. This CFG must be an accurate CFG (CFGEmulated).

- **Required** Target, which is the final destination that your backward slice terminates at.

- **Optional** CDG. A control dependence graph (CDG) derived from the CFG. angr has a built-in analysis `CDG` for that purpose.

- **Optional** DDG. A data dependence graph (DDG) built on top of the CFG. angr has a built-in analysis `DDG` for that purpose.

A `BackwardSlice` can be constructed with the following code:

```python
>>> import angr
# Load the project
>>> b = angr.Project("examples/fauxware/fauxware", load_options={"auto_load_libs": False})

# Generate a CFG first. In order to generate data dependence graph afterwards, you'll have to:
# - keep all input states by specifying keep_state=True.
# - store memory, register and temporary values accesses by adding the angr.options.refs option set.
# Feel free to provide more parameters (for example, context_sensitivity_level) for CFG
# recovery based on your needs.
>>> cfg = b.analyses.CFGEmulated(keep_state=True,
...                              state_add_options=angr.sim_options.refs,
...                              context_sensitivity_level=2)

# Generate the control dependence graph
>>> cdg = b.analyses.CDG(cfg)

# Build the data dependence graph. It might take a while. Be patient!
>>> ddg = b.analyses.DDG(cfg)

# See where we wanna go... let's go to the exit() call, which is modeled as a
# SimProcedure.
>>> target_func = cfg.kb.functions.function(name="exit")
# We need the CFGNode instance
>>> target_node = cfg.model.get_any_node(target_func.addr)

# Let's get a BackwardSlice out of them!
# ``targets`` is a list of objects, where each one is either a CodeLocation
# object, or a tuple of CFGNode instance and a statement ID. Setting statement
# ID to -1 means the very beginning of that CFGNode. A SimProcedure does not
# have any statement, so you should always specify -1 for it.
>>> bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

# Here is our awesome program slice!
>>> print(bs)
```

Sometimes it’s difficult to get a data dependence graph, or you may simply want build a program slice on top of a CFG. That’s basically why DDG is an optional parameter. You can build a `BackwardSlice` solely based on CFG by doing:

```text
>>> bs = b.analyses.BackwardSlice(cfg, control_flow_slice=True)
BackwardSlice (to [(<CFGNode exit (0x10000a0) [0]>, -1)])
```

<a id="s59--using-the-backwardslice-object"></a>

### Using The `BackwardSlice` Object

Before you go ahead and use `BackwardSlice` object, you should notice that the design of this class is fairly arbitrary right now, and it is still subject to change in the near future. We’ll try our best to keep this documentation up-to-date.

<a id="s59--members"></a>

#### Members

After construction, a `BackwardSlice` has the following members which describe a program slice:

| Member | Mode | Meaning |
|----|----|----|
| runs_in_slice | CFG-only | A `networkx.DiGraph` instance showing addresses of blocks and SimProcedures in the program slice, as well as transitions between them |
| cfg_nodes_in_slice | CFG-only | A `networkx.DiGraph` instance showing CFGNodes in the program slice and transitions in between |
| chosen_statements | With DDG | A dict mapping basic block addresses to lists of statement IDs that are part of the program slice |
| chosen_exits | With DDG | A dict mapping basic block addresses to a list of “exits”. Each exit in the list is a valid transition in the program slice |

Each “exit” in `chosen_exit` is a tuple including a statement ID and a list of target addresses. For example, an “exit” might look like the following:

```text
(35, [ 0x400020 ])
```

If the “exit” is the default exit of a basic block, it’ll look like the following:

```text
("default", [ 0x400085 ])
```

<a id="s59--export-an-annotated-control-flow-graph"></a>

#### Export an Annotated Control Flow Graph

<a id="s59--id1"></a>

Todo

Document this.

<a id="s59--user-friendly-representation"></a>

#### User-friendly Representation

Take a look at `BackwardSlice.dbg_repr()`!

<a id="s59--implementation-choices"></a>

### Implementation Choices

<a id="s59--id2"></a>

Todo

Document this.

<a id="s59--limitations"></a>

### Limitations

<a id="s59--completeness"></a>

#### Completeness

<a id="s59--id3"></a>

Todo

Document this.

<a id="s59--soundness"></a>

#### Soundness

<a id="s59--id4"></a>

Todo

Document this.


---

<a id="s60"></a>

<a id="s60--control-flow-graph-recovery-cfg"></a>

## [S60] Control-flow Graph Recovery (CFG)

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr includes analyses to recover the control-flow graph of a binary program. This also includes recovery of function boundaries, as well as reasoning about indirect jumps and other useful metadata.

<a id="s60--general-ideas"></a>

### General ideas

A basic analysis that one might carry out on a binary is a Control Flow Graph. A CFG is a graph with (conceptually) basic blocks as nodes and jumps/calls/rets/etc as edges.

In angr, there are two types of CFG that can be generated: a static CFG (CFGFast) and a dynamic CFG (CFGEmulated).

CFGFast uses static analysis to generate a CFG. It is significantly faster, but is theoretically bounded by the fact that some control-flow transitions can only be resolved at execution-time. This is the same sort of CFG analysis performed by other popular reverse-engineering tools, and its results are comparable with their output.

CFGEmulated uses symbolic execution to capture the CFG. While it is theoretically more accurate, it is dramatically slower. It is also typically less complete, due to issues with the accuracy of emulation (system calls, missing hardware features, and so on)

*If you are unsure which CFG to use, or are having problems with CFGEmulated, try CFGFast first.*

A CFG can be constructed by doing:

```python
>>> import angr
# load your project
>>> p = angr.Project('/bin/true', load_options={'auto_load_libs': False})

# Generate a static CFG
>>> cfg = p.analyses.CFGFast()

# generate a dynamic CFG
>>> cfg = p.analyses.CFGEmulated(keep_state=True)
```

<a id="s60--using-the-cfg"></a>

### Using the CFG

The CFG, at its core, is a [NetworkX](https://networkx.github.io/) di-graph. This means that all of the normal NetworkX APIs are available:

```python
>>> print("This is the graph:", cfg.model.graph)
>>> print("It has %d nodes and %d edges" % (len(cfg.model.graph.nodes()), len(cfg.model.graph.edges())))
```

The nodes of the CFG graph are instances of class `CFGNode`. Due to context sensitivity, a given basic block can have multiple nodes in the graph (for multiple contexts).

```python
# this grabs *any* node at a given location:
>>> entry_node = cfg.model.get_any_node(p.entry)

# on the other hand, this grabs all of the nodes
>>> print("There were %d contexts for the entry block" % len(cfg.model.get_all_nodes(p.entry)))

# we can also look up predecessors and successors
>>> print("Predecessors of the entry point:", entry_node.predecessors)
>>> print("Successors of the entry point:", entry_node.successors)
>>> print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.model.get_successors_and_jumpkind(entry_node) ])
```

<a id="s60--viewing-the-cfg"></a>

#### Viewing the CFG

Control-flow graph rendering is a hard problem. angr does not provide any built-in mechanism for rendering the output of a CFG analysis, and attempting to use a traditional graph rendering library, like matplotlib, will result in an unusable image.

One solution for viewing angr CFGs is found in [axt’s angr-utils repository](https://github.com/axt/angr-utils).

<a id="s60--shared-libraries"></a>

### Shared Libraries

The CFG analysis does not distinguish between code from different binary objects. This means that by default, it will try to analyze control flow through loaded shared libraries. This is almost never intended behavior, since this will extend the analysis time to several days, probably. To load a binary without shared libraries, add the following keyword argument to the `Project` constructor: `load_options={'auto_load_libs': False}`

<a id="s60--function-manager"></a>

### Function Manager

The CFG result produces an object called the *Function Manager*, accessible through `cfg.kb.functions`. The most common use case for this object is to access it like a dictionary. It maps addresses to `Function` objects, which can tell you properties about a function.

```python
>>> entry_func = cfg.kb.functions[p.entry]
```

Functions have several important properties!

- `entry_func.block_addrs` is a set of addresses at which basic blocks belonging to the function begin.

- `entry_func.blocks` is the set of basic blocks belonging to the function, that you can explore and disassemble using capstone.

- `entry_func.string_references()` returns a list of all the constant strings that were referred to at any point in the function. They are formatted as `(addr, string)` tuples, where addr is the address in the binary’s data section the string lives, and string is a Python string that contains the value of the string.

- `entry_func.returning` is a boolean value signifying whether or not the function can return. `False` indicates that all paths do not return.

- `entry_func.callable` is an angr Callable object referring to this function. You can call it like a Python function with Python arguments and get back an actual result (may be symbolic) as if you ran the function with those arguments!

- `entry_func.transition_graph` is a NetworkX DiGraph describing control flow within the function itself. It resembles the control-flow graphs IDA displays on a per-function level.

- `entry_func.name` is the name of the function.

- `entry_func.has_unresolved_calls` and `entry.has_unresolved_jumps` have to do with detecting imprecision within the CFG. Sometimes, the analysis cannot detect what the possible target of an indirect call or jump could be. If this occurs within a function, that function will have the appropriate `has_unresolved_*` value set to `True`.

- `entry_func.get_call_sites()` returns a list of all the addresses of basic blocks which end in calls out to other functions.

- `entry_func.get_call_target(callsite_addr)` will, given `callsite_addr` from the list of call site addresses, return where that callsite will call out to.

- `entry_func.get_call_return(callsite_addr)` will, given `callsite_addr` from the list of call site addresses, return where that callsite should return to.

and many more !

<a id="s60--cfgfast-details"></a>

### CFGFast details

CFGFast performs a static control-flow and function recovery. Starting with the entry point (or any user-defined points) roughly the following procedure is performed:

1.  The basic block is lifted to VEX IR, and all its exits (jumps, calls, returns, or continuation to the next block) are collected

2.  For each exit, if this exit is a constant address, we add an edge to the CFG of the correct type, and add the destination block to the set of blocks to be analyzed.

3.  In the event of a function call, the destination block is also considered the start of a new function. If the target function is known to return, the block after the call is also analyzed.

4.  In the event of a return, the current function is marked as returning, and the appropriate edges in the callgraph and CFG are updated.

5.  For all indirect jumps (block exits with a non-constant destination) Indirect Jump Resolution is performed.

<a id="s60--finding-function-starts"></a>

#### Finding function starts

CFGFast supports multiple ways of deciding where a function starts and ends.

First the binary’s main entry point will be analyzed. For binaries with symbols (e.g., non-stripped ELF and PE binaries) all function symbols will be used as possible starting points. For binaries without symbols, such as stripped binaries, or binaries loaded using the `blob` loader backend, CFG will scan the binary for a set of function prologues defined for the binary’s architecture. Finally, by default, the binary’s entire code section will be scanned for executable contents, regardless of prologues or symbols.

In addition to these, as with CFGEmulated, function starts will also be considered when they are the target of a “call” instruction on the given architecture.

All of these options can be disabled

<a id="s60--fakerets-and-function-returns"></a>

#### FakeRets and function returns

When a function call is observed, we first assume that the callee function eventually returns, and treat the block after it as part of the caller function. This inferred control-flow edge is known as a “FakeRet”. If, in analyzing the callee, we find this not to be true, we update the CFG, removing this “FakeRet”, and updating the callgraph and function blocks accordingly. As such, the CFG is recovered *twice*. In doing this, the set of blocks in each function, and whether the function returns, can be recovered and propagated directly.

<a id="s60--indirect-jump-resolution"></a>

#### Indirect Jump Resolution

<a id="s60--id1"></a>

Todo

Document this.

<a id="s60--cfgfast-options"></a>

#### CFGFast Options

These are the most useful options when working with CFGFast:

| Option | Description |
|----|----|
| force_complete_scan | (Default: True) Treat the entire binary as code for the purposes of function detection. If you have a blob (e.g., mixed code and data) *you want to turn this off*. |
| function_starts | A list of addresses, to use as entry points into the analysis. |
| normalize | (Default: False) Normalize the resulting functions (e.g., each basic block belongs to at most one function, back-edges point to the start of basic blocks) |
| resolve_indirect_jumps | (Default: True) Perform additional analysis to attempt to find targets for every indirect jump found during CFG creation. |
| more! | Examine the docstring on p.analyses.CFGFast for more up-to-date options |

<a id="s60--cfgemulated-details"></a>

### CFGEmulated details

<a id="s60--cfgemulated-options"></a>

#### CFGEmulated Options

The most common options for CFGEmulated include:

| Option | Description |
|----|----|
| context_sensitivity_level | This sets the context sensitivity level of the analysis. See the context sensitivity level section below for more information. This is 1 by default. |
| starts | A list of addresses, to use as entry points into the analysis. |
| avoid_runs | A list of addresses to ignore in the analysis. |
| call_depth | Limit the depth of the analysis to some number calls. This is useful for checking which functions a specific function can directly jump to (by setting `call_depth` to 1). |
| initial_state | An initial state can be provided to the CFG, which it will use throughout its analysis. |
| keep_state | To save memory, the state at each basic block is discarded by default. If `keep_state` is True, the state is saved in the CFGNode. |
| enable_symbolic_back_traversal | Whether to enable an intensive technique for resolving indirect jumps |
| enable_advanced_backward_slicing | Whether to enable another intensive technique for resolving direct jumps |
| more! | Examine the docstring on p.analyses.CFGEmulated for more up-to-date options |

<a id="s60--context-sensitivity-level"></a>

#### Context Sensitivity Level

angr constructs a CFG by executing every basic block and seeing where it goes. This introduces some challenges: a basic block can act differently in different *contexts*. For example, if a block ends in a function return, the target of that return will be different, depending on different callers of the function containing that basic block.

The context sensitivity level is, conceptually, the number of such callers to keep on the callstack. To explain this concept, let’s look at the following code:

```c
void error(char *error)
{
    puts(error);
}

void alpha()
{
    puts("alpha");
    error("alpha!");
}

void beta()
{
    puts("beta");
    error("beta!");
}

void main()
{
    alpha();
    beta();
}
```

The above sample has four call chains: `main>alpha>puts`, `main>alpha>error>puts` and `main>beta>puts`, and `main>beta>error>puts`. While, in this case, angr can probably execute both call chains, this becomes unfeasible for larger binaries. Thus, angr executes the blocks with states limited by the context sensitivity level. That is, each function is re-analyzed for each unique context that it is called in.

For example, the `puts()` function above will be analyzed with the following contexts, given different context sensitivity levels:

| Level | Meaning | Contexts |
|----|----|----|
| 0 | Callee-only | `puts` |
| 1 | One caller, plus callee | `alpha>puts` `beta>puts` `error>puts` |
| 2 | Two callers, plus callee | `alpha>error>puts` `main>alpha>puts` `beta>error>puts` `main>beta>puts` |
| 3 | Three callers, plus callee | `main>alpha>error>puts` `main>alpha>puts` `main>beta>error>puts` `main>beta>puts` |

The upside of increasing the context sensitivity level is that more information can be gleaned from the CFG. For example, with context sensitivity of 1, the CFG will show that, when called from `alpha`, `puts` returns to `alpha`, when called from `error`, `puts` returns to `error`, and so forth. With context sensitivity of 0, the CFG simply shows that `puts` returns to `alpha`, `beta`, and `error`. This, specifically, is the context sensitivity level used in IDA. The downside of increasing the context sensitivity level is that it exponentially increases the analysis time.


---

<a id="s61"></a>

<a id="s61--angr-decompiler"></a>

## [S61] angr Decompiler

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


<a id="s61--analysis-passes"></a>

### Analysis Passes

| Name | Description | Sub-analysis |
|----|----|----|
| CFG recovery | Recover the control flow graph. | Indirect branch resolving |
| Indirect branch resolving | Resolve the targets of indirect branches. | Jump table resolving |
| Removing alignment blocks |  |  |
| Calling convention recovery |  |  |
| Stack pointer analysis | Determine values of stack pointer at each instruction. |  |
| IR Lifting | Lift the original representation to AIL, block by block. |  |
| AIL graph building |  |  |
| Rewriting single-target indirect branches | Replace single-target indirect branches with direct branches. |  |
| Making return statements | Convert Ijk_Ret jump kinds into AIL Return statements. |  |
| Simplifying AIL blocks | Simplify each AIL block. | Constant folding, copy propagation, dead assignment elimination, peephole optimizations |
| Reaching definition analysis |  |  |
| Constant folding |  |  |
| Copy propagation |  |  |
| Dead assignment elimination |  |  |
| Peephole optimizations |  |  |
| Simplifying AIL function | Simplify the entire AIL function. | Assignment expression folding, unifying local variables, call expression folding, reaching definition analysis |
| Assignment expression folding | Eliminate variables that are assigned to once and used once. | Copy propagation |
| Unifying local variables | Find local variables that are always equivalent and eliminate redundant copies. | Copy propagation |
| Call expression folding | Fold call expressions into the variable where its return value is stored. | Copy propagation |
| Call site building | Apply calling conventions to each call site and rewrite call statements to ones with arguments | Reaching definition analysis |
| Variable recovery | Identify local and global variables. |  |
| Variable type inference | Collect type constraints and infer variable types. |  |
| Simplification passes |  |  |
| Region identification | Identify single-entry, single-exit regions. |  |
| Structure analysis | Structure each identified region to create high-level control flow structures. |  |
| Code generation |  |  |


---

<a id="s62"></a>

<a id="s62--identifier"></a>

## [S62] Identifier

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


The identifier uses test cases to identify common library functions in CGC binaries. It prefilters by finding some basic information about stack variables/arguments. The information of about stack variables can be generally useful in other projects.

```python
>>> import angr

# get all the matches
>>> p = angr.Project("../binaries/tests/i386/identifiable")
# note analysis is executed via the Identifier call
>>> idfer = p.analyses.Identifier()
>>> for funcInfo in idfer.func_info:
...     print(hex(funcInfo.addr), funcInfo.name)

0x8048e60 memcmp
0x8048ef0 memcpy
0x8048f60 memmove
0x8049030 memset
0x8049320 fdprintf
0x8049a70 sprintf
0x8049f40 strcasecmp
0x804a0f0 strcmp
0x804a190 strcpy
0x804a260 strlen
0x804a3d0 strncmp
0x804a620 strtol
0x804aa00 strtol
0x80485b0 free
0x804aab0 free
0x804aad0 free
0x8048660 malloc
0x80485b0 free
```


---

<a id="s63"></a>

<a id="s63--changelog"></a>

## [S63] Changelog

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


This lists the *major* changes in angr. Tracking minor changes are left as an exercise for the reader :-)

<a id="s63--angr-9-1"></a>

### angr 9.1

- (#2961) Refactored SimCC to support passing and returning structs and arrays by value

- (#2964) Functions from the knowledge base may now be pretty-printed, showing colors and reference arrows

- Improved `import angr` speed substantially

- (#2948) RDA’s `dep_graph` can now be used to track dependencies between temporaries, constants, guard conditions, and function calls - if you want it!

- (#2929) Basic support for structs with bitfields in SimType

- There’s a decompiler now

<a id="s63--angr-9-0"></a>

### angr 9.0

- Switched to a new versioning scheme: major.minor.build_id

<a id="s63--angr-8-19-7-25"></a>

### angr 8.19.7.25

- (#1503) Implement necessary helpers and information storage for call pretty printing

- (#1546) Add a new state option MEMORY_FIND_STRICT_SIZE_LIMIT

- (#1548) SimProcedure.static_exits: Allow providing name hints

- (cle#177) Use Enums for Symbol Types

- (cle#193) Add support for “named regions”

- (claripy#151) Implement operator precedence in claripy op rendering

- Added support for interaction recording in angr-management

- Several new simprocedure implementations

- Substantial imporvments to our CFG

<a id="s63--angr-8-19-4-5"></a>

### angr 8.19.4.5

- (#1234) Massive improvements to CFG recovery for ARM and ARM cortex-m binaries.

- (#1416) Added support for analyzing Java programs via the Soot IR, including the ability to analyze interplay between Java code and JNI libraries. This branch was two years old!

- (#1427) Added a MemoryWatcher exploration technique to take action when the system is running out of RAM. Thanks @bannsec.

- (#1432) Added a `state.heap` plugin which manages the heap (with pluggable heap schemes!) and provides malloc functionality. Thanks @tgduckworth.

- Speed improvements for using the VEX engine and working with concrete data.

- Added SimLightRegisters, an alternate registers plugin that eliminates the abstraction of the register file for performance improvements at the cost of removing all instrumentability.

- `version__` variable has been added to all modules.

- The `stack_base` kwarg for `call_state` is not broken for the first time ever

- <https://github.com/python/cpython/pull/11384>

<a id="s63--angr-8-19-2-4"></a>

### angr 8.19.2.4

- (#1279) Support C++ function name demangling via itanium-demangler. Thanks @fmagin.

- (#1283) `security_cookie` is initialized for SimWindows. Thanks @zeroSteiner.

- (#1298) Introduce `SimData`. It’s a cleaner interface to deal with data imports in CLE – especially for those data entries that are not imported because of missing or unloaded libraries. This commit fixes long-standing issues \#151 and \#693.

- (#1299, \#1300, \#1301, \#1313, \#1314, \#1315, \#1336, \#1337, \#1343, …) Multiple CFGFast-related improvements and bug fixes.

- (#1332) `UnresolvableTarget` is now split into two classes: `UnresolvableJumpTarget` and `UnresolvableCallTarget`. Thanks @Kyle-Kyle.

- (#1382) Add a preliminary implementation of angr decompiler. Give it a try! `p = angr.Project("cfg_loop_unrolling", auto_load_libs=False); p.analyses.CFG(); print(p.analyses.Decompiler(p.kb.functions['test_func']).codegen.text)`.

- (#1421) `SimAction`s now have incrementing IDs. Thanks @bannsec.

- (#1408) `ANA`, angr’s old identity-aware serialization backend, has been removed. Instead of non-obvious serialization behavior, all angr objects should now be pickleable. If one is not, please file an issue. For use-cases that require identity-awareness (i.e., deduplicating ASTs across states serialized at different times), an `angr.vaults` module has been introduced.

- Added a [facility to synchronize state between angr and a running target a la avatar2](http://angr.io/blog/angr_symbion/)

- Changed unconstrained registers/memory warning to be less obnoxious and contain useful information. Also added `SYMBOL_FILL_UNCONSTRAINED_REGISTERS` and `SYMBOL_FILL_UNCONSTRAINED_MEMORY` state options to silence them.

<a id="s63--angr-8-18-10-25"></a>

### angr 8.18.10.25

- The IDA backend for CLE has been removed. It has been broken for quite some time, but now it has been disabled for your own safety.

- Surveyors have been removed! Finally! This is thanks to @danse-macabre who contributed an Exploration Technique for the Slicecutor. Backwards slicing has now been brought out of the angr dark ages.

- SimCC can now be initialized with a string containing C function prototype in its `func_ty` argument

- Similarly, Callable can now be run with its arguments instantiated from a string containing C expressions

- Tracer has been substantially refactored - it will now handle more kinds of desyncs, ASLR slides, and is much more friendly for hacking. We will be continuing to improve it!

- The Oppologist and Driller have been refactored to play nice with other exploration techniques

- SimProcedure continuations now have symbols in the externs object, so `describe_addr` will work on them. Additionally, the representation for SimProcedure (appearing in `history.descriptions` and `project._sim_procedures` among other places) has been improved to show this information.

<a id="s63--angr-8-18-10-5"></a>

### angr 8.18.10.5

Largely a bugfix release, but with a few bonus treats:

- API documentation has been rewritten for Exploration Technique. It should be much easier to use now.

- Simulation Manager will throw an error if you pass incorrect keyword arguments (??? why was it like this)

- The `save_unconstrained` flag of Simulation Manager is now on by default

- If a step produces only unsatisfiable states, they will appear in the `'unsat'` stash regardless of the `save_unsat` setting, since this usually indicates a bug. Add `unsat` to the `auto_drop` parameter to restore the old behavior.

<a id="s63--angr-8-18-10-1"></a>

### angr 8.18.10.1

Welcome to angr 8! The biggest change for this major version bump is the transition to Python 3. You can read about this, as well as a few other breaking changes, in the [Migrating to angr 8](#s66--migrating-to-angr-8).

- Switch to Python 3

- Refactor to Clemory to clean up the API and speed things up drastically

- Remove `object.symbols_by_addr` (dict) and add `object.symbols` (sorted list); add `fuzzy` parameter to `loader.find_symbol`

- CFGFast is much, much faster now. CFGAccurate has been renamed to CFGEmulated.

- Support for avx2 unpack instructions, courtesy of D. J. Bernstein

- Removed support for immutable simulation managers

- angr will now show you a warning when using uninitialized memory or registers

- angr will now NOT show you a warning if you have a capstone 3.x install unless you’re actually interacting with the relevant missing parts

- Many, many, many bug fixes

<a id="s63--angr-7-8-7-1"></a>

### angr 7.8.7.1

- Remove `LoopLimiter` and `DFG`.

- (#1063) `CFGAccurate` can now leverage indirect jump resolvers to resolve indirect jumps.

<a id="s63--angr-7-8-6-23"></a>

### angr 7.8.6.23

- (PyVEX!#134) We now recognize LDMDB r11, {xxx, pc} as a ret instruction for ARM.

- (#1053) CFGFast spends less time running next_pos_with_sort_not_in(), thus it runs faster on large binaries.

- (#1080) Jump table resolvers now support resolving ARM jump tables.

- (#1081, together with the PyVEX commit 61efbdcf6303a936aa3de35011d2d1e3fe5fdea5) The memory footprint of CFGFast is noticeably smaller, especially on large binaries (over 10 MB in size).

- (#1034) Concretizing a SimFile with unconstrained size can no longer run you out of memory.

- Other minor changes and bug fixes.

<a id="s63--angr-7-8-6-16"></a>

### angr 7.8.6.16

- The modeling of file system is refactored.

- (#808) Add a new class Control flow blanket (CFBlanket) to support generating a linear view of a control flow graph.

- (#863) Add support to AIL, the new angr intermediate language (still pretty WIP though). Merged in several static analyses (reaching definition analysis, VEX-to-AIL translation, redundant assignment elimination, code region identification, control flow structuring, etc.) that support the development of decompilation in the near future.

- (#888) SimulationManager is extensively refactored and cleaned up.

- (#892) Keystone is integrated. You can assemble instructions inside angr now.

- (#897) A new class `PluginHub` is added. Plugins (analyses, engines) are refactored to be based on `PluginHub`.

- (#899) Support of bidirectional mapping between syscall numbers and syscalls.

- (#925, \#941, \#942) A bunch of library function prototypes (including glibc) are added to angr.

- (#953) Fix the issue where evaluating the jump target of a jump table that contains many entries (e.g., \> 512) is extremely slow.

- (#964) State options are now stored in insances of SimStateOptions. `state.options` is no longer a set of strings.

- (#973) Add two new exploration techniques: Stochastic and unique.

- (#996) SimType structs are now much easier to use.

- (#998) Add a new state option `PRODUCE_ZERODIV_SUCCESSORS` to generate divide-by-zero successors.

- Speed improvements and bug fixes in CFG generation (CFGFast and CFGAccurate).

<a id="s63--angr-7-8-2-21"></a>

### angr 7.8.2.21

- Refactor of how syscall handling and SimSyscallLibrary work - it is now possible to handle syscalls using multiple ABIs in the same process

- Added syscall name-number mappings from all linux ABIs, parsed from gdb

- Add `ManualMergepoint` exploration technique for when veritesting is too mysterious for your tastes

- Add `LoopSeer` exploration technique for managing loops during symbolic exploration (credit @tyb0807)

- Add `ProxyTechnique` exploration technique for easily composing simple lambda-based instrumentations (credit @danse-macabre)

<a id="s63--angr-7-7-12-16"></a>

### angr 7.7.12.16

- You can now tell where the variables implicitly created by angr come from! `state.solver.BVS` now can take a `key` parameter, which describes its meaning in relation to the emulated environment. You can then use `state.solver.get_variables(...)` and `state.solver.describe_variables(...)` to map tags and ASTs to and from each other. Check out the [API docs](http://angr.io/api-doc/angr.html#angr.state_plugins.solver.SimSolver)!

- The SimOS for a project is now a public property - `project.simos` instead of `project._simos`. Additionally, the SimOS code structure has been shuffled around a bit - it’s now a subpackage instead of a submodule.

- The core components of Tracer and Driller have been refactored into Exploration Techniques and integrated into angr proper, so you can now follow instruction traces without installing another repository! (credit @tyb0807)

- Archinfo now contains a `byte_width` parameter and angr supports emulation of platforms with non-octet bytes, lord help us

- Upgraded to networkx 2 (credit @tyb0807)

- Hopefully installation issues with capstone should be fixed FOREVER

- Minor fixes to gender

<a id="s63--angr-7-7-9-8"></a>

### angr 7.7.9.8

Welcome to angr 7! We worked long and hard all summer to make this release the best ever. It introduces several breaking changes, so for a quick guide on the most common ways you’ll need to update your scripts, take a look at the [Migrating to angr 7](#s65--migrating-to-angr-7).

- SimuVEX has been removed and its components have been integrated into angr

- Path has been removed and its components have been integrated into SimState, notably the new `history` state plugin

- PathGroup has been renamed to SimulationManager

- SimState and SimProcedure now have a reference to their parent Project, though it is verboten to use it in anything other than an append-only fashion

- A new class SimLibrary is used to track SimProcedure and metadata corresponding to an individual shared library

- Several CLE interfaces have been refactored up for consistency

- Hook has been removed. Hooking is now done with individual SimProcedure instances, which are shallow-copied at execution time for thread-safety.

- The `state.solver` interface has been cleaned up drastically

These are the major refactor-y points. As for the improvements:

- Greatly improved support for analyzing 32 bit windows binaries (partial credit @schieb)

- Unicorn will now stop for stop points and breakpoints in the middle of blocks (credit @bennofs)

- The processor flags for a state can now be accessed through `state.regs.eflags` on x86 and `state.regs.flags` on ARM (partial credit @tyb0807)

- Fledgling support for emulating exception handling. Currently the only implementation of this is support for Structured Exception Handling on Windows, see `angr.SimOS.handle_exception` for details

- Fledgling support for runtime library loading by treating the CLE loader as an append-only interface, though only implemented for windows. See `cle.Loader.dynamic_load` and `angr.procedures.win32.dynamic_loading` for details.

- The knowledge base has been refactored into a series of plugins similar to SimState (credit @danse-macabre)

- The testcase-based function identifier we wrote for CGC has been integrated into angr as the Identifier analysis

- Improved support for writing custom VEX lifters

<a id="s63--angr-6-7-6-9"></a>

### angr 6.7.6.9

- angr: A static data-flow analysis framework has been introduced, and implemented as part of the `ForwardAnalysis` class. Additionally, a few exemplary data-flow analyses, like `VariableRecovery` and `VariableRecoveryFast`, have been implemented in angr.

- angr: We introduced the notion of *variable* to the angr world. Now a VariableManager is available in the knowledge base. Variable information can be recovered by running a variable recovery analysis. Currently the variable information recovered for each function is still pretty coarse. More updates to it will arrive soon.

- angr: Fix a bug in the topological sorting in `CFGUtils`, which resulted in suboptimal graph node ordering after sorting.

- SimuVEX: `LAZY_SOLVES` is no longer enabled by default during symbolic execution. It’s still there if it’s wanted, but it just caused confusion when on by default.

- SimuVEX: Thanks to @ekilmer, a few new libc SimProcedures are added.

- SimuVEX: The default memory model has been refactored for expandability. Custom pages can now be created (derive the simuvex.storage.ListPage class) and used instead of the default page classes to implement custom memory behavior for specific pages. The user-friendly API for this is pending the next release.

- angr-management: Implemented our own graph layout and edge routing algorithm. We do not rely on grandalf anymore.

- angr-management: Added support for displaying variable information for operands.

- angr-management: Added support for highlighting dependent operands when an operand is highlighted.

<a id="s63--angr-6-7-3-26"></a>

### angr 6.7.3.26

Building off of the engine changes from the last release, we have begun to extend angr to other architectures. AVR and MSP430 are in progress. In the meantime, subwire has created a reference implementation of BrainFuck support in angr, done two different ways! Check out [angr-platforms](https://github.com/angr/angr-platforms) for more info!

- We have rebased our fork of VEX on the latest master branch from Valgrind (as of 2 months ago, at least…). We have also submitted our patches to VEX to upstream, so we should be able to stop maintaining a fork pretty soon.

- The way we interact with VEX has changed substantially, and should speed things up a bit.

- Loading sets of binaries with many import symbols has been sped up

- Many, many improvements to angr-management, including the switch away from enaml to using pyside directly.

<a id="s63--angr-6-7-1-13"></a>

### angr 6.7.1.13

For the last month, we have been working on a major refactor of the angr to change the way that angr reasons about the code that it analyzes. Until now, angr has been bound to the VEX intermediate representation to lift native code, supporting a wide range of architectures but not being very expandable past them. This release represents the ground work for what we call translation and execution engines. These engines are independent backends, pluggable into the angr framework, that will allow angr to reason about a wide range of targets. For now, we have restructured the existing VEX and Unicorn Engine support into this engine paradigm, but as we discuss in [our blog post](http://angr.io/blog/2017_01_10.html), the plan is to create engines to enable angr’s reasoning of Java bytecode and source code, and to augment angr’s environment support through the use of external dynamic sandboxes.

For now, these changes are mostly internal. We have attempted to maintain compatibility for end-users, but those building systems atop angr will have to adapt to the modern codebase. The following are the major changes:

- simuvex: we have introduced SimEngine. SimEngine is a base class for abstractions over native code. For example, angr’s VEX-specific functionality is now concentrated in SimEngineVEX, and new engines (such as SimEngineLLVM) can be implemented (even outside of simuvex itself) to support the analysis of new types of code.

- simuvex: as part of the engines refactor, the SimRun class has been eliminated. Instead of different subclasses of SimRun that would be instantiated from an input state, engines each have a `process` function that, from an input state, produces a SimSuccessors instance containing lists of different successor states (normal, unsat, unconstrained, etc) and any engine-specific artifacts (such as the VEX statements. Take a look at `successors.artifacts`).

- simuvex: `state.mem[x:] = y` now *requires* a type for storage (for example `state.mem[x:].dword = y`).

- simuvex: the way of calling inline SimProcedures has been changed. Now you have to create a SimProcedure, and then call `execute()` on it and pass in a program state as well as the arguments.

- simuvex: accessing registers through `SimRegNameView` (like `state.regs.eax`) always triggers SimInspect breakpoints and creates new actions. Now you can access a register by prefixing its name with an underscore (e.g. `state.regs._eax` or `state._ip`) to avoid triggering breakpoints or creating actions.

- angr: the way hooks work has slightly changed, though is backwards-compatible. The new angr.Hook class acts as a wrapper for hooks (SimProcedures and functions), keeping things cleaner in the `project._sim_procedures` dict.

- angr: we have deprecated the keyword argument `max_size` and changed it to to `size` in the `angr.Block` constructor (i.e., the argument to `project.factory.block` and more upstream methods (`path.step`, `path_group.step`, etc).

- angr: we have deprecated `project.factory.sim_run` and changed it to to `project.factory.successors`, and it now generates a `SimSuccessors` object.

- angr: `project.factory.sim_block` has been deprecated and replaced with `project.factory.successors(default_engine=True)`.

- angr: angr syscalls are no longer hooks. Instead, the syscall table is now in `project._simos.syscall_table`. This will be made “public” after a usability refactor. If you were using `project.is_hooked(addr)` to see if an address has a related SimProcedure, now you probably want to check if there is a related syscall as well (using `project._simos.syscall_table.get_by_addr(addr) is not None`).

- pyvex: to support custom lifters to VEX, pyvex has introduced the concept of backend lifters. Lifters can be written in pure Python to produce VEX IR, allowing for extendability of angr’s VEX-based analyses to other hardware architectures.

As usual, there are many other improvements and minor bugfixes.

- claripy: support `unsat_core()` to get the core of unsatness of constraints. It is in fact a thin wrapper of the `unsat_core()` function provided by Z3. Also a new state option `CONSTRAINT_TRACKING_IN_SOLVER` is added to SimuVEX. That state option must be enabled if you want to use `unsat_core()` on any state.

- simuvex: `SimMemory.load()` and `SimMemory.store()` now takes a new parameter `disable_actions`. Setting it to True will prevent any SimAction creation.

- angr: CFGFast has a better support for ARM binaries, especially for code in THUMB mode.

- angr: thanks to an improvement in SimuVEX, CFGAccurate now uses slightly less memory than before.

- angr: `len()` on path `trace` or `addr_trace` is made much faster.

- angr: Fix a crash during CFG generation or symbolic execution on platforms/architectures with no syscall defined.

- angr: as part of the refactor, `BackwardSlicing` is temporarily disabled. It will be re-enabled once all DDG-related refactor are merged to master.

Additionally, packaging and build-system improvements coordinated between the angr and Unicorn Engine projects have allowed angr’s Unicorn support to be built on Windows. Because of this, `unicorn` is now a dependency for `simuvex`.

Looking forward, angr is poised to become a program analysis engine for binaries *and more*!

<a id="s63--angr-5-6-12-3"></a>

### angr 5.6.12.3

It has been over a month since the last release 5.6.10.12. Again, we’ve made some significant changes and improvements on the code base.

- angr: Labels are now stored in KnowledgeBase.

- angr: Add a new analysis: `Disassembly`. The new Disassembly analysis provides an easy-to-use interface to render assembly of functions.

- angr: Fix the issue that `ForwardAnalysis` may prematurely terminate while there are still un-processed jobs.

- angr: Many small improvements and bug fixes on `CFGFast`.

- angr: Many small improvements and bug fixes on `VFG`. Bring back widening support. Fix the issue that `VFG` may not terminate under certain cases. Implement a new graph traversal algorithm to have an optimal traversal order. Allow state merging at non-merge-points, which allows faster convergence.

- angr-management: Display a progress during initial CFG recovery.

- angr-management: Display a “Load binary” window upon binary loading. Some analysis options can be adjusted there.

- angr-management: Disassembly view: Edge routing on the graph is improved.

- angr-management: Disassembly view: Support starting a new symbolic execution task from an arbitrary address in the program.

- angr-management: Disassembly view: Support renaming of function names and labels.

- angr-management: Disassembly view: Support “Jump to address”.

- angr-management: Disassembly view: Display resolved and unresolved jump targets. All jump targets are double-clickable.

- SimuVEX: Move region mapping from `SimAbstractMemory` to `SimMemory`. This will allow an easier conversion between `SimAbstractMemory` and `SimSymbolicMemory`, which is to say, conversion between symbolic states and static states is now possible.

- SimuVEX & claripy: Provide support for `unsat_core` in Z3. It returns a set of constraints that led to unsatness of the constraint set on the current state.

- archinfo: Add a new Boolean variable `branch_delay_slot` for each architecture. It is set to True on MIPS32.

<a id="s63--angr-5-6-8-22"></a>

### angr 5.6.8.22

Major point release! An incredible number of things have changed in the month run-up to the Cyber Grand Challenge.

- Integration with [Unicorn Engine](https://github.com/unicorn-engine/unicorn) supported for concrete execution. A new SimRun type, SimUnicorn, may step through many basic blocks at once, so long as there is no operation on symbolic data. Please use [our fork of unicorn engine](https://github.com/angr/unicorn), which has many patches applied. All these patches are pending merge into upstream.

- Lots of improvements and bug fixes to CFGFast. Rumors are angr’s CFG was only “optimized” for x86-64 binaries (which is really because most of our test cases are compiled as 64-bit ELFs). Now it is also “optimized” for x86 binaries :) (editor’s note: angr is built with cross-architecture analysis in mind. CFG construction is pretty much the only component which has architecture-specific behavior.)

- Lots of improvements to the VFG analysis, including speed and accuracy. However, there is still a lot to be done.

- Lots of speed optimizations in general - CFGFast should be 3-6x faster under CPython with much less memory usage.

- Now data dependence graph gives you a real dependence graph between variable definitions. Try `data_graph` and `simplified_data_graph` on a DDG object!

- New state option `simuvex.o.STRICT_PAGE_ACCESS` will cause a `SimSegfaultError` to be raised whenever the guest reads/writes/executes memory that is either unmapped or doesn’t have the appropriate permissions.

- Merging of paths (as opposed to states) is performed in a much smarter way.

- The behavior of the `support_selfmodifying_code` project option is changed: Before, this would allow the state to be used as a fallback source of instruction bytes when no backer from CLE is available. Now, this option makes instruction lifting use the state as the source of bytes always. When the option is disabled and execution jumps outside the normal binary, the state will be used automatically.

- *Actually* support self-modifying code - if a basic block of code modifies itself, the block will be re-lifted before the next instruction starts.

- Syscalls are handled differently now - Before you would see a SimRun for a syscall helper, now you’ll just see a SimProcedure for the given syscall. Additionally, each syscall has its own address in a “syscalls segment”, and syscalls are treated as jumps to this segment. This simplifies a lot of things analysis-wise.

- CFGAccurate accepts a `base_graph` keyword to its constructor, e.g. `CFGFast().graph`, or even `.graph` of a function, to use as a base for analysis.

- New fast memory model for cases where symbolic-addressed reads and writes are unlikely.

- Conflicts between the `find` and `avoid` parameters to the Explorer otiegnqwvk are resolved correctly. (credit clslgrnc)

- New analysis `StaticHooker` which hooks library functions in unstripped statically linked binaries.

- `Lifter` can be used without creating an angr Project. You must manually specify the architecture and bytestring in calls to `.lift()` and `.fresh_block()`. If you like, you can also specify the architecture as a parameter to the constructor and omit it from the lifting calls.

- Add two new analyses developed for the CGC (mostly as examples of doing static analysis with angr): Reassembler and BinaryOptimizer.

<a id="s63--angr-4-6-6-28"></a>

### angr 4.6.6.28

In general, there have been enormous amounts of speed improvements in this release. Depending on the workload, angr should run about twice as fast. Aside from this, there have also been many submodule-specific changes:

<a id="s63--angr"></a>

#### angr

Quite a few changes and improvements are made to `CFGFast` and `CFGAccurate` in order to have better and faster CFG recovery. The two biggest changes in `CFGFast` are jump table resolution and data references collection, respectively. Now `CFGFast` resolves indirect jumps by default. You may get a list of indirect jumps recovered in `CFGFast` by accessing the `indirect_jumps` attribute. For many cases, it resolves the jump table accurately. Data references collection is still in alpha mode. To test data references collection, just pass `collect_data_references=True` when creating a fast CFG, and access the `memory_data` attribute after the CFG is constructed.

CFG recovery on ARM binaries is also improved.

A new paradigm called an “otiegnqwvk”, or an “exploration technique”, allows the packaging of special logic related to path group stepping.

<a id="s63--simuvex"></a>

#### SimuVEX

Reads/writes to the x87 fpu registers now work correctly - there is special logic that rotates a pointer into part of the register file to simulate the x87 stack.

With the recent changes to Claripy, we have configured SimuVEX to use the composite solver by default. This should be transparent, but should be considered if strange issues (or differences in behavior) arise during symbolic execution.

<a id="s63--claripy"></a>

#### Claripy

Fixed a bug in claripy where `div__` was not always doing unsigned division, and added new methods `SDiv` and `SMod` for signed division and signed remainder, respectively.

Claripy frontends have been completely rewritten into a mixin-centric solver design. Basic frontend functionality (i.e., calling into the solver or dealing with backends) is handled by frontends (in `claripy.frontends`), and additional functionality (such as caching, deciding when to simplify, etc) is handled by frontend mixins (in `claripy.frontend_mixins`). This makes it considerably easier to customize solvers to your specific needE. For examples, look at `claripy/solver.py`.

Alongside the solver rewrite, the composite solver (which splits constraints into independent constraint sets for faster solving) has been immensely improved and is now functional and fast.

<a id="s63--angr-4-6-6-4"></a>

### angr 4.6.6.4

Syscalls are no longer handled by `simuvex.procedures.syscalls.handler`. Instead, syscalls are now handled by `angr.SimOS.handle_syscall()`. Previously, the address of a syscall SimProcedure is the address right after the syscall instruction (e.g. `int 80h`), which collides with the real basic block starting at that address, and is very confusing. Now each syscall SimProcedure has its own address, just as a normal SimProcedure. To support this, there is another region mapped for the syscall addresses, `Project._syscall_obj`.

Some refactoring and bug fixes in `CFGFast`.

Claripy has been given the ability to handle *annotations* on ASTs. An annotation can be used to customize the behavior of some backends without impacting others. For more information, check the docstrings of `claripy.Annotation` and `claripy.Backend.apply_annotation`.

<a id="s63--angr-4-6-5-25"></a>

### angr 4.6.5.25

New state constructor - `call_state`. Comes with a refactor to `SimCC`, a refactor to `callable`, and the removal of `PathGroup.call`. All these changes are thoroughly documented, in `angr/docs/advanced-topics/structured_data.md`

Refactor of `SimType` to make it easier to use types - they can be instantiated without a SimState and one can be added later. Comes with some usability improvements to SimMemView. Also, there’s a better wrapper around PyCParser for generating SimType instances from c declarations and definitions. Again, thoroughly documented, still in the structured data doc.

`CFG` is now an alias to `CFGFast` instead of `CFGAccurate`. In general, `CFGFast` should work under most cases, and it’s way faster than `CFGAccurate`. We believe such a change is necessary, and will make angr more approachable to new users. You will have to change your code from `CFG` to `CFGAccurate` if you are relying on specific functionalities that only exist in `CFGAccurate`, for example, context-sensitivity and state-preserving. An exception will be raised by angr if any parameter passed to `CFG` is only supported by `CFGAccurate`. For more detailed explanation, please take a look at the documentation of `angr.analyses.CFG`.

<a id="s63--angr-4-6-3-28"></a>

### angr 4.6.3.28

PyVEX has a structural overhaul. The `IRExpr`, `IRStmt`, and `IRConst` modules no longer exist as submodules, and those module names are deprecated. Use `pyvex.expr`, `pyvex.stmt`, and `pyvex.const` if you need to access the members of those modules.

The names of the first three parameters to `pyvex.IRSB` (the required ones) have been changed. If you were passing the positional args to IRSB as keyword args, consider switching to positional args. The order is `data`, `mem_addr`, `arch`.

The optional parameter `sargc` to the `entry_state` and `full_init_state` constructors has been removed and replaced with an `argc` parameter. `sargc` predates being able to have claripy ASTs independent from a solver. The new system is to pass in the exact value, ast or integer, that you’d like to have as the guest program’s arg count.

CLE and angr can now accept file-like streams, that is, objects that support `stream.read()` and `stream.seek()` can be passed in wherever a filepath is expected.

Documentation is much more complete, especially for PyVEX and angr’s symbolic execution control components.

<a id="s63--angr-4-6-3-15"></a>

### angr 4.6.3.15

There have been several improvements to claripy that should be transparent to users:

- There’s been a refactoring of the VSA StridedInterval classes to fix cases where operations were not sound. Precision might suffer as a result, however.

- Some general speed improvements.

- We’ve introduced a new backend into claripy: the ReplacementBackend. This frontend generates replacement sets from constraints added to it, and uses these replacement sets to increase the precision of VSA. Additionally, we have introduced the HybridBackend, which combines this functionality with a constraint solver, allowing for memory index resolution using VSA.

angr itself has undergone some improvements, with API changes as a result:

- We are moving toward a new way to store information that angr has recovered about a program: the knowledge base. When an analysis recovers some truth about a program (i.e., “there’s a basic block at 0x400400”, or “the block at 0x400400 has a jump to 0x400500”), it gets stored in a knowledge-base. Analysis that used to store data (currently, the CFG) now store them in a knowledge base and can *share* the global knowledge base of the project, now accessible via `project.kb`. Over time, this knowledge base will be expanded in the course of any analysis or symbolic execution, so angr is constantly learning more information about the program it is analyzing.

- A forward data-flow analysis framework (called ForwardAnalysis) has been introduced, and the CFG was rewritten on top of it. The framework is still in alpha stage - expect more changes to be made. Documentation and more details will arrive shortly. The goal is to refactor other data-flow analysis, like CFGFast, VFG, DDG, etc. to use ForwardAnalysis.

- We refactored the CFG to a) improve code readability, and b) eliminate some bad designs that linger due to historical reasons.

<a id="s63--angr-4-5-12"></a>

### angr 4.5.12.?

Claripy has a new manager for backends, allowing external backends (i.e., those implemented by other modules) to be used. The result is that `claripy.backend_concrete` is now `claripy.backends.concrete`, `claripy.backend_vsa` is now `claripy.backends.vsa`, and so on.

<a id="s63--angr-4-5-12-12"></a>

### angr 4.5.12.12

Improved the ability to recover from failures in instruction decoding. You can now hook specific addresses at which VEX fails to decode with `project.hook`, even if those addresses are not the beginning of a basic block.

<a id="s63--angr-4-5-11-23"></a>

### angr 4.5.11.23

This is a pretty beefy release, with over half of claripy having been rewritten and major changes to other analyses. Internally, Claripy has been unified – the VSA mode and symbolic mode now work on the same structures instead of requiring structures to be created differently. This opens the door for awesome capabilities in the future, but could also result in unexpected behavior if we failed to account for something.

Claripy has had some major interface changes:

- claripy.BV has been renamed to claripy.BVS (bit-vector symbol). It can now create bitvectors out of strings (i.e., claripy.BVS(0x41, 8) and claripy.BVS(“A”) are identical).

- state.BV and state.BVV are deprecated. Please use state.se.BVS and state.se.BVV.

- BV.model is deprecated. If you’re using it, you’re doing something wrong, anyways. If you really need a specific model, convert it with the appropriate backend (i.e., claripy.backend_concrete.convert(bv)).

There have also been some changes to analyses:

- Interface: CFG argument `keep_input_state` has been renamed to `keep_state`. With this option enabled, both input and final states are kept.

- Interface: Two arguments `cfg_node` and `stmt_id` of `BackwardSlicing` have been deprecated. Instead, `BackwardSlicing` takes a single argument, `targets`. This means that we now support slicing from multiple sources.

- Performance: The speed of CFG recovery has been slightly improved. There is a noticeable speed improvement on MIPS binaries.

- Several bugs have been fixed in DDG, and some sanity checks were added to make it more usable.

And some general changes to angr itself:

- StringSpec is deprecated! You can now pass claripy bitvectors directly as arguments.


---

<a id="s64"></a>

<a id="s64--cheatsheet"></a>

## [S64] Cheatsheet

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


The following cheatsheet aims to give an overview of various things you can do with angr and act as a quick reference to check the syntax for something without having to dig through the deeper docs.

<a id="s64--general-getting-started"></a>

### General getting started

Some useful imports

```python
import angr #the main framework
import claripy #the solver engine
```

Loading the binary

```python
proj = angr.Project("/path/to/binary", auto_load_libs=False) # auto_load_libs False for improved performance
```

<a id="s64--states"></a>

### States

Create a SimState object

```python
state = proj.factory.entry_state()
```

<a id="s64--simulation-managers"></a>

### Simulation Managers

Generate a simulation manager object

```python
simgr = proj.factory.simulation_manager(state)
```

<a id="s64--exploring-and-analysing-states"></a>

### Exploring and analysing states

Choosing a different Exploring strategy

```python
simgr.use_technique(angr.exploration_techniques.DFS())
```

Symbolically execute until we find a state satisfying our `find=` and `avoid=` parameters

```python
avoid_addr = [0x400c06, 0x400bc7]
find_addr = 0x400c10d
simgr.explore(find=find_addr, avoid=avoid_addr)
```

```python
found = simgr.found[0] # A state that reached the find condition from explore
found.solver.eval(sym_arg, cast_to=bytes) # Return a concrete string value for the sym arg to reach this state
```

Symbolically execute until lambda expression is `True`

```python
simgr.step(until=lambda sm: sm.active[0].addr >= first_jmp)
```

This is especially useful with the ability to access the current STDOUT or STDERR (1 here is the File Descriptor for STDOUT)

```python
simgr.explore(find=lambda s: "correct" in s.posix.dumps(1))
```

Memory Management on big searches (Auto Drop Stashes):

```python
simgr.explore(find=find_addr, avoid=avoid_addr, step_func=lambda lsm: lsm.drop(stash='avoid'))
```

<a id="s64--manually-exploring"></a>

#### Manually Exploring

```python
simgr.step(step_func=step_func, until=lambda lsm: len(sm.found) > 0)

def step_func(lsm):
    lsm.stash(filter_func=lambda state: state.addr == 0x400c06, from_stash='active', to_stash='avoid')
    lsm.stash(filter_func=lambda state: state.addr == 0x400bc7, from_stash='active', to_stash='avoid')
    lsm.stash(filter_func=lambda state: state.addr == 0x400c10, from_stash='active', to_stash='found')
    return lsm
```

Enable Logging output from Simulation Manager:

```python
import logging
logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
```

<a id="s64--stashes"></a>

#### Stashes

Move Stash:

```python
simgr.stash(from_stash="found", to_stash="active")
```

Drop Stashes:

```python
simgr.drop(stash="avoid")
```

<a id="s64--constraint-solver-claripy"></a>

### Constraint Solver (claripy)

Create symbolic object

```python
sym_arg_size = 15 #Length in Bytes because we will multiply with 8 later
sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)
```

Restrict sym_arg to typical char range

```python
for byte in sym_arg.chop(8):
    initial_state.add_constraints(byte >= '\x20') # ' '
    initial_state.add_constraints(byte <= '\x7e') # '~'
```

Create a state with a symbolic argument

```python
argv = [proj.filename]
argv.append(sym_arg)
state = proj.factory.entry_state(args=argv)
```

Use argument for solving:

```python
sym_arg = angr.claripy.BVS("sym_arg", flag_size * 8)
argv = [proj.filename]
argv.append(sym_arg)
initial_state = proj.factory.full_init_state(args=argv, add_options=angr.options.unicorn, remove_options={angr.options.LAZY_SOLVES})
```

<a id="s64--ffi-and-hooking"></a>

### FFI and Hooking

Calling a function from ipython

```python
f = proj.factory.callable(address)
f(10)
x=claripy.BVS('x', 64)
f(x) #TODO: Find out how to make that result readable
```

If what you are interested in is not directly returned because for example the function returns the pointer to a buffer you can access the state after the function returns with

```python
>>> f.result_state
<SimState @ 0x1000550>
```

Hooking

There are already predefined hooks for libc functions (useful for statically compiled libraries)

```python
proj = angr.Project('/path/to/binary', use_sim_procedures=True)
proj.hook(addr, angr.SIM_PROCEDURES['libc']['atoi']())
```

Hooking with Simprocedure:

```python
class fixpid(angr.SimProcedure):
    def run(self):
            return 0x30

proj.hook(0x4008cd, fixpid())
```

<a id="s64--other-useful-tricks"></a>

### Other useful tricks

Drop into an ipython if a ctr+c is received (useful for debugging scripts that are running forever)

```python
import signal
def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print 'Stopping Execution for Debug. If you want to kill the program issue: killmyself()'
    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)
```

Get the calltrace of a state to find out where we got stuck

```python
state = simgr.active[0]
print state.callstack
```

Get a basic block

```python
block = proj.factory.block(address)
block.capstone.pp() # Capstone object has pretty print and other data about the disassembly
block.vex.pp()      # Print vex representation
```

<a id="s64--state-manipulation"></a>

### State manipulation

Write to state:

```python
aaaa = claripy.BVV(0x41414141, 32) # 32 = Bits
state.memory.store(0x6021f2, aaaa)
```

Read Pointer to Pointer from Frame:

```python
poi1 = new_state.solver.eval(new_state.regs.rbp)-0x10
poi1 = new_state.mem[poi1].long.concrete
poi1 += 0x8
ptr1 = new_state.mem[poi1].long.concrete
```

Read from State:

```python
key = []
for i in range(38):
    key.append(extractkey.mem[0x602140 + i*4].int.concrete)
```

Alternatively, the below expression is equivalent

```python
key = extractkey.mem[0x602140].int.array(38).concrete
```

<a id="s64--debugging-angr"></a>

### Debugging angr

Set Breakpoint at every Memory read/write:

```python
new_state.inspect.b('mem_read', when=angr.BP_AFTER, action=debug_funcRead)
def debug_funcRead(state):
    print 'Read', state.inspect.attrs.mem_read_expr, 'from', state.inspect.attrs.mem_read_address
```

Set Breakpoint at specific Memory location:

```python
new_state.inspect.b('mem_write', mem_write_address=0x6021f1, when=angr.BP_AFTER, action=debug_funcWrite)
```


---

<a id="s65"></a>

<a id="s65--migrating-to-angr-7"></a>

## [S65] Migrating to angr 7

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


The release of angr 7 introduces several departures from long-standing angr-isms. While the community has created a compatibility layer to give external code written for angr 6 a good chance of working on angr 7, the best thing to do is to port it to the new version. This document serves as a guide for this.

<a id="s65--simuvex-is-gone"></a>

### SimuVEX is gone

angr versions up through angr 6 split the program analysis into two modules: `simuvex`, which was responsible for analyzing the effects of a single piece of code (whether a basic block or a SimProcedure) on a program state, and `angr`, which aggregated analyses of these basic blocks into program-level analysis such as control-flow recovery, symbolic execution, and so forth. In theory, this would encourage for the encapsulation of block-level analyses, and allow other program analysis frameworks to build upon `simuvex` for their needs. In practice, no one (to our knowledge) used `simuvex` without `angr`, and the separation introduced frustrating limitations (such as not being able to reference the history of a state from a SimInspect breakpoint) and duplication of code (such as the need to synchronize data from `state.scratch` into `path.history`).

Realizing that SimuVEX wasn’t a usable independent package, we brainstormed about merging it into angr and further noticed that this would allow us to address the frustrations resulting from their separation.

All of the SimuVEX concepts (SimStates, SimProcedures, calling conventions, types, etc) have been migrated into angr. The migration guide for common classes is bellow:

| Before               | After             |
|----------------------|-------------------|
| simuvex.SimState     | angr.SimState     |
| simuvex.SimProcedure | angr.SimProcedure |
| simuvex.SimEngine    | angr.SimEngine    |
| simuvex.SimCC        | angr.SimCC        |

And for common modules:

| Before                            | After                          |
|-----------------------------------|--------------------------------|
| simuvex.s_cc                      | angr.calling_conventions       |
| simuvex.s_state                   | angr.sim_state                 |
| simuvex.s_procedure               | angr.sim_procedure             |
| simuvex.plugins                   | angr.state_plugins             |
| simuvex.engines                   | angr.engines                   |
| simuvex.concretization_strategies | angr.concretization_strategies |

Additionally, `simuvex.SimProcedures` has been renamed to `angr.SIM_PROCEDURES`, since it is a global variable and not a class. There have been some other changes to its semantics, see the section on SimProcedures for details.

<a id="s65--removal-of-angr-path"></a>

### Removal of angr.Path

In angr, a Path object maintained references to a SimState and its history. The fact that the history was separated from the state caused a lot of headaches when trying to analyze states inside a breakpoint, and caused overhead in synchronizing data from the state to its history.

In the new model, a state’s history is maintained in a SimState plugin: `state.history`. Since the path would now simply point to the state, we got rid of it. The mapping of concepts is roughly as follows:

| Before              | After                        |
|---------------------|------------------------------|
| path                | state                        |
| path.state          | state                        |
| path.history        | state.history                |
| path.callstack      | state.callstack              |
| path.trace          | state.history.descriptions   |
| path.addr_trace     | state.history.bbl_addrs      |
| path.jumpkinds      | state.history.jumpkinds      |
| path.guards         | state.history.jump_guards    |
| path.targets        | state.history.jump_targets   |
| path.actions        | state.history.actions        |
| path.events         | state.history.events         |
| path.recent_actions | state.history.recent_actions |
| path.reachable      | state.history.reachable()    |

An important behavior change about `path.actions` and `path.recent_actions` - actions are no longer tracked by default. If you would like them to be tracked again, please add `angr.options.refs` to your state.

<a id="s65--path-group-simulation-manager"></a>

#### Path Group -\> Simulation Manager

Since there are no paths, there cannot be a path group. Instead, we have a Simulation Manager now (we recommend using the abbreviation “simgr” in places you were previously using “pg”), which is exactly the same as a path group except it holds states instead of paths. You can make one with `project.factory.simulation_manager(...)`.

<a id="s65--errored-paths"></a>

#### Errored Paths

Before, error resilience was handled at the path level, where stepping a path that caused an error would return a subclass of Path called ErroredPath, and these paths would be put in the `errored` stash of a path group. Now, error resilience is handled at the simulation manager level, and any state that throws an error during stepping will be wrapped in an ErrorRecord object, which is *not* a subclass of SimState, and put into the `errored` list attribute of the simulation manager, which is *not* a stash.

An ErrorRecord object has attributes for `.state` (the initial state that caused the error), `.error` (the error that was thrown), and `.traceback` (the traceback from the error). To debug these errors you can call `.debug()`.

These changes are because we were uncomfortable making a subclass of SimState, and the ErrorRecord class then has sufficiently different semantics from a normal state that it cannot be placed in a stash.

<a id="s65--changes-to-simprocedures"></a>

### Changes to SimProcedures

The most noticeable difference from the old version to the new version is that the catalog of built-in simprocedures are no longer organized strictly according to which library they live in. Now, they are organized according to which *standards* they conform to, which helps with re-using procedures between different libraries. For instance, the old `SimProcedures['libc.so.6']` has been split up between `SIM_PROCEDURES['libc']`, `SIM_PROCEDURES['posix']`, and `SIM_PROCEDURES['glibc']`, depending on what specifications each function conforms to. This allows us to reuse the `libc` catalog in `msvcrt.dll` and the MUSL libc, for example.

In order to group SimProcedures together by libraries, we have introduced a new abstraction called the SimLibrary, the definitions for which are stored in `angr.procedures.definitions`. Each SimLibrary object stores information about a single shared library, and can contain SimProcedure implementations, calling convention information, and type information. SimLibraries are scraped from the filesystem at import time, just like SimProcedures, and placed into `angr.SIM_LIBRARIES`.

Syscalls are now categorized through a subclass of SimLibrary called SimSyscallLibrary. The API for managing syscalls through SimOS has been changed - check the API docs for the SimUserspace class.

One important implication of this change is that if you previously used a trick where you changed one of the SimProcedures present in the `SimProcedures` dict in order to change which SimProcedures would be used to hook over library functions by default, this will no longer work. Instead of `SimProcedures[lib][func_name] = proc`, you now need to say `SIM_LIBRARIES[lib].add(func_name, proc)`. But really you should just be using `hook_symbol` anyway.

<a id="s65--changes-to-hooking"></a>

### Changes to hooking

The `Hook` class is gone. Instead, we now can hook with individual instances of SimProcedure objects, as opposed to just the classes. A shallow copy of the SimProcedure will be made at runtime to preserve thread safety.

So, previously, where you would have done `project.hook(addr, Hook(proc, ...))` or `project.hook(addr, proc)`, you can now do `project.hook(addr, proc(...))`. In order to use simple functions as hooks, you can either say `project.hook(addr, func)` or decorate the declaration of your function with `@project.hook(addr)`.

Having simprocedures as instances and letting them have access to the project cleans up a lot of other hacks that were present in the codebase, mostly related to the `self.call(...)` SimProcedure continuation system. It is no longer required to set `IS_FUNCTION = True` if you intend to use `self.call()` while writing a SimProcedure, and each call-return target you use will have a unique address associated with it. These addresses will be allocated lazily, which does have the side effect of making address allocation nondeterministic, sometimes based on dictionary-iteration order.

<a id="s65--changes-to-loading"></a>

### Changes to loading

The `hook_symbol` method will no longer attempt to redo relocations for the given symbol, instead just hooking directly over the address of the symbol in whatever library it comes from. This speeds up loading substantially and ensures more consistent behavior for when mixing and matching native library code and SimProcedure summaries.

The angr externs object has been moved into CLE, which will ALWAYS make sure that every dependency is resolved to something, never left unrelocated. Similarly, CLE provides the “kernel object” used to provide addresses for syscalls now.

| Before                 | After                  |
|------------------------|------------------------|
| `project._extern_obj`  | `loader.extern_object` |
| `project._syscall_obj` | `loader.kernel_object` |

Several properties and methods have been renamed in CLE in order to maintain a more consistent and explicit API. The most common changes are listed below:

| Before | After |
|----|----|
| `loader.whats_at()` | `loader.describe_addr` |
| `loader.addr_belongs_to_object()` | `loader.find_object_containing()` |
| `loader.find_symbol_name()` | `loader.find_symbol().name` |
| whatever the hell you were doing before to look up a symbol | `loader.find_symbol(name or addr)` |
| `loader.find_module_name()` | `loader.find_object_containing().provides` |
| `loader.find_symbol_got_entry()` | `loader.find_relevant_relocations()` |
| `loader.main_bin` | `loader.main_object` |
| `anything.get_min_addr()` | `anything.min_addr` |
| `symbol.addr` | `symbol.linked_addr` |

<a id="s65--changes-to-the-solver-interface"></a>

### Changes to the solver interface

We cleaned up the menagerie of functions present on `state.solver` (if you’re still referring to it as `state.se` you should stop) and simplified it into a cleaner interface:

- `solver.eval(expression)` will give you one possible solution to the given expression.

- `solver.eval_one(expression)` will give you the solution to the given expression, or throw an error if more than one solution is possible.

- `solver.eval_upto(expression, n)` will give you up to n solutions to the given expression, returning fewer than n if fewer than n are possible.

- `solver.eval_atleast(expression, n)` will give you n solutions to the given expression, throwing an error if fewer than n are possible.

- `solver.eval_exact(expression, n)` will give you n solutions to the given expression, throwing an error if fewer or more than are possible.

- `solver.min(expression)` will give you the minimum possible solution to the given expression.

- `solver.max(expression)` will give you the maximum possible solution to the given expression.

Additionally, all of these methods can take the following keyword arguments:

- `extra_constraints` can be passed as a tuple of constraints. These constraints will be taken into account for this evaluation, but will not be added to the state.

- `cast_to` can be passed a data type to cast the result to. Currently, this can only be `str`, which will cause the method to return the byte representation of the underlying data. For example, `state.solver.eval(state.solver.BVV(0x41424344, 32, cast_to=str)` will return `"ABCD"`.


---

<a id="s66"></a>

<a id="s66--migrating-to-angr-8"></a>

## [S66] Migrating to angr 8

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr has moved from Python 2 to Python 3! We took this opportunity of a major version bump to make a few breaking API changes that improve quality-of-life.

<a id="s66--what-do-i-need-to-know-for-migrating-my-scripts-to-python-3"></a>

### What do I need to know for migrating my scripts to Python 3?

To begin, just the standard py3k changes, the relevant parts of which we’ll rehash here as a reference guide:

- Strings and bytestrings

  - Strings are now unicode by default, a new `bytes` type holds bytestrings

  - Bytestring literals can be constructed with the b prefix, like `b'ABCD'`

  - Conversion between strings and bytestrings happens with `.encode()` and `.decode()`, which use utf-8 as a default. The `latin-1` codec will map byte values to their equivalent unicode codepoints

  - The `ord()` and `chr()` functions operate on strings, not bytestrings

  - Enumerating over or indexing into bytestrings produces an unsigned 8 bit integer, not a 1-byte bytestring

  - Bytestrings have all the string manipulation functions present on strings, including `join`, `upper`/`lower`, `translate`, etc

  - `hex` and `base64` are no longer string encoding codecs. For hex, use `bytes.fromhex()` and `bytes.hex()`. For base64 use the `base64` module.

- Builtin functions

  - `print` and `exec` are now builtin functions instead of statements

  - Many builtin functions previously returning lists now return iterators, such as `map`, `filter`, and `zip`. `reduce` is no longer a builtin; you have to import it from `functools`.

- Numbers

  - The `/` operator is explicitly floating-point division, the `//` operator is expliclty integer division. The magic functions for overriding these ops are `truediv__` and `floordiv__`

  - The int and long types have been merged, there is only int now

- Dictionary objects have had their `.iterkeys`, `.itervalues`, and `.iteritems` methods removed, and then non-iter versions have been made to return efficient iterators

- Comparisons between objects of very different types (such as between strings and ints) will raise an exception

In terms of how this has affected angr, any string that represents data from the emulated program will be a bytestring. This means that where you previously said `state.solver.eval(x, cast_to=str)` you should now say `cast_to=bytes`. When creating concrete bitvectors from strings (including implicitly by just making a comparison against a string) these should be bytestrings. If they are not they will be utf-8 converted and a warning will be printed. Symbol names should be unicode strings.

For division, however, ASTs are strongly typed so they will treat both division operators as the kind of division that makes sense for their type.

<a id="s66--clemory-api-changes"></a>

### Clemory API changes

The memory object in CLE (project.loader.memory, not state.memory) has had a few breaking API changes since the bytes type is much nicer to work with than the py2 string for this specific case, and the old API was an inconsistent mess.

| Before | After |
|----|----|
| `memory.read_bytes(addr, n) -> list[str]` | `memory.load(addr, n) -> bytes` |
| `memory.write_bytes(addr, list[str])` | `memory.store(addr, bytes)` |
| `memory.get_byte(addr) -> str` | `memory[addr] -> int` |
| `memory.read_addr_at(addr) -> int` | `memory.unpack_word(addr) -> int` |
| `memory.write_addr_at(addr, value) -> int` | `memory.pack_word(addr, value)` |
| `memory.stride_repr -> list[(start, end, str)]` | `memory.backers() -> iter[(start, bytearray)]` |

Additionally, `pack_word` and `unpack_word` now take optional `size`, `endness`, and `signed` parameters. We have also added `memory.pack(addr, fmt, *data)` and `memory.unpack(addr, fmt)`, which take format strings for use with the `struct` module.

If you were using the `cbackers` or `read_bytes_c` functions, the conversion is a little more complicated - we were able to remove the split notion of “backers” and “updates” and replaced all backers with bytearrays that we mutate, so we can work directly with the backer objects. The `backers()` function iterates through all bottom-level backer objects and their start addresses. You can provide an optional address to the function, and it will skip over all backers that end before that address.

Here is some sample code for producing a C-pointer to a given address:

```python
import cffi, cle
ffi = cffi.FFI()
ld = cle.Loader('/bin/true')

addr = ld.main_object.entry
try:
    backer_start, backer = next(ld.memory.backers(addr))
except StopIteration:
    raise Exception("not mapped")

if backer_start > addr:
    raise Exception("not mapped")

cbacker = ffi.from_buffer(backer)
addr_pointer = cbacker + (addr - backer_start)
```

You should not have to use this if you aren’t passing the data to a native library - the normal load methods should now be more than fast enough for intensive use.

<a id="s66--cle-symbols-changes"></a>

### CLE symbols changes

Previously, your mechanisms for looking up symbols by their address were `loader.find_symbol()` and `object.symbols_by_addr`, where there was clearly some overlap. However, `symbols_by_addr` stayed because it was the only way to enumerate symbols in an object. This has changed! `symbols_by_addr` is deprecated and here is now `object.symbols`, a sorted list of Symbol objects, to enumerate symbols in a binary.

Additionally, you can now enumerate all symbols in the entire project with `loader.symbols`. This change has also enabled us to add a `fuzzy` parameter to `find_symbol` (returns the first symbol before the given address) and make the output of `loader.describe_addr` much nicer (shows offset from closest symbol).

<a id="s66--deprecations-and-name-changes"></a>

### Deprecations and name changes

- All parameters in cle that started with `custom_` - so, `custom_base_addr`, `custom_entry_point`, `custom_offset`, `custom_arch`, and `custom_ld_path` - have had the `custom_` removed from the beginning of their names.

- All the functions that were deprecated more than a year ago (at or before the angr 7 release) have been removed.

- `state.se` has been deprecated. You should have been using `state.solver` for the past few years.

- Support for immutable simulation managers has been removed. So far as we’re aware, nobody was actually using this, and it was making debugging a pain.


---

<a id="s67"></a>

<a id="s67--migrating-to-angr-9-1"></a>

## [S67] Migrating to angr 9.1

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr 9.1 is here!

<a id="s67--calling-conventions-and-prototypes"></a>

### Calling Conventions and Prototypes

The main change motivating angr 9.1 is [this large refactor of SimCC](https://github.com/angr/angr/pull/2961). Here are the breaking changes:

<a id="s67--simccs-can-no-longer-be-customized"></a>

#### SimCCs can no longer be customized

If you were using the `sp_delta`, `args`, or `ret_val` parameters to SimCC, you should use the new class `SimCCUsercall`, which lets (requires) you to be explicit about the locations of each argument.

<a id="s67--passing-simtypes-is-now-mandatory"></a>

#### Passing SimTypes is now mandatory

Every method call on SimCC which interacts with typed data now requires a SimType to be passed in. Previously, the use of `is_fp` and `size` was optional, but now these parameters will no longer be accepted and a `SimType` will be required.

This has some fairly non-intuitive consequences - in order to accommodate more esoteric calling conventions (think: passing large structs by value via an “invisible reference”) you have to specify a function’s return type before you can extract any of its arguments.

Additionally, some non-cc interfaces, such as `call_state` and `callable` and `SimProcedure.call()`, now *require* a prototype to be passed to them. You’d be surprised how many bugs we found in our own code from enforcing this requirement!

<a id="s67--pointerwrapper-has-a-new-parameter"></a>

#### PointerWrapper has a new parameter

Imagine you’re passing something into a function which has a parameter of type `char*`. Is this a pointer to a single char or a pointer to an array of chars? The answer changes how we typecheck the values you pass in. If you’re passing a PointerWrapper wrapping a large value which should be treated as an array of chars, you should construct your pointerwrapper as `PointerWrapper(foo, buffer=True)`. The buffer argument to PointerWrapper now instructs SimCC to treat the data to be serialized as an array of the child type instead of as a scalar.

<a id="s67--func-ty-prototype"></a>

#### `func_ty` -\> `prototype`

Every usage of the name func_ty has been replaced with the name prototype. This was done for consistency between the static analysis code and the dynamic FFI.


---

<a id="s68"></a>

<a id="s68--ctf-challenge-examples"></a>

## [S68] CTF Challenge Examples

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr is very often used in CTFs. These are example scripts resulting from that use, mostly from Shellphish but also from many others.

<a id="s68--reverseme-example-hackcon-2016-angry-reverser"></a>

### ReverseMe example: HackCon 2016 - angry-reverser

Script author: Stanislas Lejay (github: [@P1kachu](https://github.com/P1kachu))

Script runtime: ~31 minutes

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/hackcon2016_angry-reverser/yolomolo) and the [script](https://github.com/angr/angr-examples/tree/master/examples/hackcon2016_angry-reverser/solve.py)

<a id="s68--reverseme-example-securityfest-2016-fairlight"></a>

### ReverseMe example: SecurityFest 2016 - fairlight

Script author: chuckleberryfinn (github: [@chuckleberryfinn](https://github.com/chuckleberryfinn))

Script runtime: ~20 seconds

A simple reverse me that takes a key as a command line argument and checks it against 14 checks. Possible to solve the challenge using angr without reversing any of the checks.

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/securityfest_fairlight/fairlight) and the [script](https://github.com/angr/angr-examples/tree/master/examples/securityfest_fairlight/solve.py)

<a id="s68--reverseme-example-defcon-quals-2016-baby-re"></a>

### ReverseMe example: DEFCON Quals 2016 - baby-re

Authors David Manouchehri (github: [@Manouchehri](https://github.com/Manouchehri)), Stanislas Lejay (github: [@P1kachu](https://github.com/P1kachu)) and Audrey Dutcher (github: @rhelmot).

Script runtime: 10 sec

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/defcon2016quals_baby-re/baby-re) and the [script](https://github.com/angr/angr-examples/tree/master/examples/defcon2016quals_baby-re/solve.py)

<a id="s68--reverseme-example-google-ctf-unbreakable-enterprise-product-activation-150-points"></a>

### ReverseMe example: Google CTF - Unbreakable Enterprise Product Activation (150 points)

Script 0 author: David Manouchehri (github: [@Manouchehri](https://github.com/Manouchehri))

Script runtime: 4.5 sec

Script 1 author: Adam Van Prooyen (github: [@docileninja](https://github.com/docileninja))

Script runtime: 6.7 sec

A Linux binary that takes a key as a command line argument and checks it against a series of constraints.

Challenge Description:

> We need help activating this product – we’ve lost our license key :(
>
> You’re our only hope!

Here are the binary and scripts: [script 0](https://github.com/angr/angr-examples/tree/master/examples/google2016_unbreakable_0), [script_1](https://github.com/angr/angr-examples/tree/master/examples/google2016_unbreakable_1)

<a id="s68--reverseme-example-ekoparty-ctf-fuckzing-reverse-250-points"></a>

### ReverseMe example: EKOPARTY CTF - Fuckzing reverse (250 points)

Author: Adam Van Prooyen (github: [@docileninja](https://github.com/docileninja))

Script runtime: 29 sec

A Linux binary that takes a team name as input and checks it against a series of constraints.

Challenge Description:

> Hundreds of conditions to be meet, will you be able to surpass them?

Both sample binaries and the script are located [here](https://github.com/angr/angr-examples/tree/master/examples/ekopartyctf2016_rev250) and additional information be found at the author’s [write-up](http://van.prooyen.com/reversing/2016/10/30/Fuckzing-reverse-Writeup.html).

<a id="s68--reverseme-example-whitehat-grant-prix-global-challenge-2015-re400"></a>

### ReverseMe example: WhiteHat Grant Prix Global Challenge 2015 - Re400

Author: Fish Wang (github: @ltfish)

Script runtime: 5.5 sec

A Windows binary that takes a flag as argument, and tells you if the flag is correct or not.

“I have to patch out some checks that are difficult for angr to solve (e.g., it uses some bytes of the flag to decrypt some data, and see if those data are legit Windows APIs). Other than that, angr works really well for solving this challenge.”

The [binary](https://github.com/angr/angr-examples/tree/master/examples/whitehatvn2015_re400/re400.exe) and the [script](https://github.com/angr/angr-examples/tree/master/examples/whitehatvn2015_re400/solve.py).

<a id="s68--reverseme-example-ekoparty-ctf-2015-rev-100"></a>

### ReverseMe example: EKOPARTY CTF 2015 - rev 100

Author: Fish Wang (github: @ltfish)

Script runtime: 5.5 sec

This is a painful challenge to solve with angr. I should have done things in a smarter way.

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/ekopartyctf2015_rev100/counter) and the [script](https://github.com/angr/angr-examples/tree/master/examples/ekopartyctf2015_rev100/solve.py).

<a id="s68--reverseme-example-asis-ctf-finals-2015-fake"></a>

### ReverseMe example: ASIS CTF Finals 2015 - fake

Author: Fish Wang (github: @ltfish)

Script runtime: 1 min 57 sec

The solution is pretty straight-forward.

The [binary](https://github.com/angr/angr-examples/tree/master/examples/asisctffinals2015_fake/fake) and the [script](https://github.com/angr/angr-examples/tree/master/examples/asisctffinals2015_fake/solve.py).

<a id="s68--reverseme-example-defcamp-ctf-qualification-2015-reversing-100"></a>

### ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 100

Author: Fish Wang (github: @ltfish)

angr solves this challenge with almost zero user-interference.

See the [script](https://github.com/angr/angr-examples/tree/master/examples/defcamp_r100/solve.py) and the [binary](https://github.com/angr/angr-examples/tree/master/examples/defcamp_r100/r100).

<a id="s68--reverseme-example-defcamp-ctf-qualification-2015-reversing-200"></a>

### ReverseMe example: Defcamp CTF Qualification 2015 - Reversing 200

Author: Fish Wang (github: @ltfish)

angr solves this challenge with almost zero user-interference. Veritesting is required to retrieve the flag promptly.

The [script](https://github.com/angr/angr-examples/tree/master/examples/defcamp_r200/solve.py) and the [binary](https://github.com/angr/angr-examples/tree/master/examples/defcamp_r200/r200). It takes a few minutes to run on my laptop.

<a id="s68--reverseme-example-mma-ctf-2015-howtouse"></a>

### ReverseMe example: MMA CTF 2015 - HowToUse

Author: Audrey Dutcher (github: @rhelmot)

We solved this simple reversing challenge with angr, since we were too lazy to reverse it or run it in Windows. The resulting [script](https://github.com/angr/angr-examples/tree/master/examples/mma_howtouse/solve.py) shows how we grabbed the flag out of the [DLL](https://github.com/angr/angr-examples/tree/master/examples/mma_howtouse/howtouse.dll).

<a id="s68--crackme-example-mma-ctf-2015-simplehash"></a>

### CrackMe example: MMA CTF 2015 - SimpleHash

Author: Chris Salls (github: @salls)

This crackme is 95% solvable with angr, but we did have to overcome some difficulties. The [script](https://github.com/angr/angr-examples/tree/master/examples/mma_simplehash/solve.py) describes the difficulties that were encountered and how we worked around them. The binary can be found [here](https://github.com/angr/angr-examples/tree/master/examples/mma_simplehash/simple_hash).

<a id="s68--reverseme-example-flareon-2015-challenge-10"></a>

### ReverseMe example: FlareOn 2015 - Challenge 10

Author: Fish Wang (github: @ltfish)

angr acts as a binary loader and an emulator in solving this challenge. I didn’t have to load the driver onto my Windows box.

The [script](https://github.com/angr/angr-examples/tree/master/examples/flareon2015_10/solve.py) demonstrates how to hook at arbitrary program points without affecting the intended bytes to be executed (a zero-length hook). It also shows how to read bytes out of memory and decode as a string.

By the way, here is the [link](https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution10.pdf) to the intended solution from FireEye.

<a id="s68--reverseme-example-flareon-2015-challenge-2"></a>

### ReverseMe example: FlareOn 2015 - Challenge 2

Author: Chris Salls (github: @salls)

This [reversing challenge](https://github.com/angr/angr-examples/tree/master/examples/flareon2015_2/very_success) is simple to solve almost entirely with angr, and a lot faster than trying to reverse the password checking function. The script is [here](https://github.com/angr/angr-examples/tree/master/examples/flareon2015_2/solve.py)

<a id="s68--reverseme-example-0ctf-2016-momo"></a>

### ReverseMe example: 0ctf 2016 - momo

Author: Fish Wang (github: @ltfish), ocean (github: @ocean1)

This challenge is a [movfuscated](https://github.com/xoreaxeaxeax/movfuscator) binary. To find the correct password after exploring the binary with Qira it is possible to understand how to find the places in the binary where every character is checked using capstone and using angr to load the [binary](https://github.com/angr/angr-examples/tree/master/examples/0ctf_momo_3/solve.py) and brute-force the single characters of the flag. Be aware that the [script](https://github.com/angr/angr-examples/tree/master/examples/0ctf_momo_3/solve.py) is really slow. Runtime: \> 1 hour.

<a id="s68--crackme-example-9447-ctf-2015-reversing-330-nobranch"></a>

### CrackMe example: 9447 CTF 2015 - Reversing 330, “nobranch”

Author: Audrey Dutcher (github: @rhelmot)

angr cannot currently solve this problem natively, as the problem is too complex for z3 to solve. Formatting the constraints to z3 a little differently allows z3 to come up with an answer relatively quickly. (I was asleep while it was solving, so I don’t know exactly how long!) The script for this is [here](https://github.com/angr/angr-examples/tree/master/examples/9447_nobranch/solve.py) and the binary is [here](https://github.com/angr/angr-examples/tree/master/examples/9447_nobranch/nobranch).

<a id="s68--crackme-example-ais3-crackme"></a>

### CrackMe example: ais3_crackme

Author: Antonio Bianchi, Tyler Nighswander

ais3_crackme has been developed by Tyler Nighswander (tylerni7) for ais3 summer school. It is an easy crackme challenge, checking its command line argument.

<a id="s68--reverseme-modern-binary-exploitation-csci-4968"></a>

### ReverseMe: Modern Binary Exploitation - CSCI 4968

Author: David Manouchehri (GitHub [@Manouchehri](https://github.com/Manouchehri))

[This folder](https://github.com/angr/angr-examples/tree/master/examples/CSCI-4968-MBE/challenges) contains scripts used to solve some of the challenges with angr. At the moment it only contains the examples from the IOLI crackme suite, but eventually other solutions will be added.

<a id="s68--crackme-example-android-license-check"></a>

### CrackMe example: Android License Check

Author: Bernhard Mueller (GitHub [@b-mueller](https://github.com/angr/angr-examples/tree/master/examples/))

A [native binary for Android/ARM](https://github.com/angr/angr-examples/tree/master/examples/android_arm_license_validation) that validates a license key passed as a command line argument. It was created for the symbolic execution tutorial in the [OWASP Mobile Testing Guide](https://github.com/OWASP/owasp-mstg/).


---

<a id="s69"></a>

<a id="s69--list-of-claripy-operations"></a>

## [S69] List of Claripy Operations

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


<a id="s69--arithmetic-and-logic"></a>

### Arithmetic and Logic

| Name | Description | Example |
|----|----|----|
| LShR | Logically shifts an expression to the right. (the default shifts are arithmetic) | `x.LShR(10)` |
| RotateLeft | Rotates an expression left | `x.RotateLeft(8)` |
| RotateRight | Rotates an expression right | `x.RotateRight(8)` |
| And | Logical And (on boolean expressions) | `claripy.And(x == y, x > 0)` |
| Or | Logical Or (on boolean expressions) | `claripy.Or(x == y, y < 10)` |
| Not | Logical Not (on a boolean expression) | `claripy.Not(x == y)` is the same as `x != y` |
| If | An If-then-else | Choose the maximum of two expressions: `claripy.If(x > y, x, y)` |
| ULE | Unsigned less than or equal to | Check if x is less than or equal to y: `x.ULE(y)` |
| ULT | Unsigned less than | Check if x is less than y: `x.ULT(y)` |
| UGE | Unsigned greater than or equal to | Check if x is greater than or equal to y: `x.UGE(y)` |
| UGT | Unsigned greater than | Check if x is greater than y: `x.UGT(y)` |
| SLE | Signed less than or equal to | Check if x is less than or equal to y: `x.SLE(y)` |
| SLT | Signed less than | Check if x is less than y: `x.SLT(y)` |
| SGE | Signed greater than or equal to | Check if x is greater than or equal to y: `x.SGE(y)` |
| SGT | Signed greater than | Check if x is greater than y: `x.SGT(y)` |

<a id="s69--id1"></a>

Todo

Add the floating point ops

<a id="s69--bitvector-manipulation"></a>

### Bitvector Manipulation

| Name | Description | Example |
|----|----|----|
| SignExt | Pad a bitvector on the left with `n` sign bits | `x.sign_extend(n)` |
| ZeroExt | Pad a bitvector on the left with `n` zero bits | `x.zero_extend(n)` |
| Extract | Extracts the given bits (zero-indexed from the *right*, inclusive) from an expression. | Extract the least significant byte of x: `x[7:0]` |
| Concat | Concatenates any number of expressions together into a new expression. | `x.concat(y, ...)` |

<a id="s69--extra-functionality"></a>

### Extra Functionality

There’s a bunch of prepackaged behavior that you *could* implement by analyzing the ASTs and composing sets of operations, but here’s an easier way to do it:

- You can chop a bitvector into a list of chunks of `n` bits with `val.chop(n)`

- You can endian-reverse a bitvector with `x.reversed`

- You can get the width of a bitvector in bits with `val.length`

- You can test if an AST has any symbolic components with `val.symbolic`

- You can get a set of the names of all the symbolic variables implicated in the construction of an AST with `val.variables`


---

<a id="s70"></a>

<a id="s70--list-of-state-options"></a>

## [S70] List of State Options

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


<a id="s70--state-modes"></a>

### State Modes

These may be enabled by passing `mode=xxx` to a state constructor.

| Mode name | Description |
|----|----|
| `symbolic` | The default mode. Useful for most emulation and analysis tasks. |
| `symbolic_approximating` | Symbolic mode, but enables approximations for constraint solving. |
| `static` | A preset useful for static analysis. The memory model becomes an abstract region-mapping system, “fake return” successors skipping calls are added, and more. |
| `fastpath` | A preset for extremely lightweight static analysis. Executing will skip all intensive processing to give a quick view of the behavior of code. |
| `tracing` | A preset for attempting to execute concretely through a program with a given input. Enables unicorn, enables resilience options, and will attempt to emulate access violations correctly. |

<a id="s70--option-sets"></a>

### Option Sets

These are sets of options, found as `angr.options.xxx`.

| Set name | Description |
|----|----|
| `common_options` | Options necessary for basic execution |
| `symbolic` | Options necessary for basic symbolic execution |
| `resilience` | Options that harden angr’s emulation against unsupported operations, attempting to carry on by treating the result as an unconstrained symbolic value and logging the occasion to `state.history.events`. |
| `refs` | Options that cause angr to keep a log of all the memory, register, and temporary references complete with dependency information in `history.actions`. This option consumes a lot of memory, so be careful! |
| `approximation` | Options that enable approximations of constraint solves via value-set analysis instead of calling into z3 |
| `simplification` | Options that cause data to be run through z3’s simplifiers before it reaches memory or register storage |
| `unicorn` | Options that enable the unicorn engine for executing on concrete data |

<a id="s70--options"></a>

### Options

These are individual option objects, found as `angr.options.XXX`.

| Option name | Description | Sets | Modes | Implicit adds |
|----|----|----|----|----|
| `ABSTRACT_MEMORY` | Use `SimAbstractMemory` to model memory as discrete regions |  | `static` |  |
| `ABSTRACT_SOLVER` | Allow splitting constraint sets during simplification |  | `static` |  |
| `ACTION_DEPS` | Track dependencies in SimActions |  |  |  |
| `APPROXIMATE_GUARDS` | Use VSA when evaluating guard conditions |  |  |  |
| `APPROXIMATE_MEMORY_INDICES` | Use VSA when evaluating memory indices | `approximation` | `symbolic_approximating` |  |
| `APPROXIMATE_MEMORY_SIZES` | Use VSA when evaluating memory load/store sizes | `approximation` | `symbolic_approximating` |  |
| `APPROXIMATE_SATISFIABILITY` | Use VSA when evaluating state satisfiability | `approximation` | `symbolic_approximating` |  |
| `AST_DEPS` | Enables dependency tracking for all claripy ASTs |  |  | During execution |
| `AUTO_REFS` | An internal option used to track dependencies in SimProcedures |  |  | During execution |
| `AVOID_MULTIVALUED_READS` | Return a symbolic value without touching memory for any read that has a symbolic address |  | `fastpath` |  |
| `AVOID_MULTIVALUED_WRITES` | Do not perform any write that has a symbolic address |  | `fastpath` |  |
| `BEST_EFFORT_MEMORY_STORING` | Handle huge writes of symbolic size by pretending they are actually smaller |  | `static`, `fastpath` |  |
| `BREAK_SIRSB_END` | Debug: trigger a breakpoint at the end of each block |  |  |  |
| `BREAK_SIRSB_START` | Debug: trigger a breakpoint at the start of each block |  |  |  |
| `BREAK_SIRSTMT_END` | Debug: trigger a breakpoint at the end of each IR statement |  |  |  |
| `BREAK_SIRSTMT_START` | Debug: trigger a breakpoint at the start of each IR statement |  |  |  |
| `BYPASS_ERRORED_IRCCALL` | Treat clean helpers that fail with errors as returning unconstrained symbolic values | `resilience` | `fastpath`, `tracing` |  |
| `BYPASS_ERRORED_IROP` | Treat operations that fail with errors as returning unconstrained symbolic values | `resilience` | `fastpath`, `tracing` |  |
| `BYPASS_UNSUPPORTED_IRCCALL` | Treat unsupported clean helpers as returning unconstrained symbolic values | `resilience` | `fastpath`, `tracing` |  |
| `BYPASS_UNSUPPORTED_IRDIRTY` | Treat unsupported dirty helpers as returning unconstrained symbolic values | `resilience` | `fastpath`, `tracing` |  |
| `BYPASS_UNSUPPORTED_IREXPR` | Treat unsupported IR expressions as returning unconstrained symbolic values | `resilience` | `fastpath`, `tracing` |  |
| `BYPASS_UNSUPPORTED_IROP` | Treat unsupported operations as returning unconstrained symbolic values | `resilience` | `fastpath`, `tracing` |  |
| `BYPASS_UNSUPPORTED_IRSTMT` | Treat unsupported IR statements as returning unconstrained symbolic values | `resilience` | `fastpath`, `tracing` |  |
| `BYPASS_UNSUPPORTED_SYSCALL` | Treat unsupported syscalls as returning unconstrained symbolic values | `resilience` | `fastpath`, `tracing` |  |
| `BYPASS_VERITESTING_EXCEPTIONS` | Discard emulation errors during veritesting | `resilience` | `fastpath`, `tracing` |  |
| `CACHELESS_SOLVER` | enable `SolverCacheless` |  |  |  |
| `CALLLESS` | Emulate call instructions as an unconstraining of the return value register |  |  |  |
| `CGC_ENFORCE_FD` | CGC: make sure all reads and writes go to stdin and stdout, respectively |  |  |  |
| `CGC_NON_BLOCKING_FDS` | CGC: always report “data available” in fdwait |  |  |  |
| `CGC_NO_SYMBOLIC_RECEIVE_LENGTH` | CGC: always read the maximum amount of data requested in the receive syscall |  |  |  |
| `COMPOSITE_SOLVER` | Enable `SolverComposite` for independent constraint set optimization | `symbolic` | all except `static` |  |
| `CONCRETIZE` | Concretize all symbolic expressions encountered during emulation |  |  |  |
| `CONCRETIZE_SYMBOLIC_FILE_READ_SIZES` | Concreteize the sizes of file reads |  |  |  |
| `CONCRETIZE_SYMBOLIC_WRITE_SIZES` | Concretize the sizes of symbolic writes to memory |  |  |  |
| `CONSERVATIVE_READ_STRATEGY` | Do not use SimConcretizationStrategyAny for reads; in case of read address concretization failures, return an unconstrained symbolic value |  |  |  |
| `CONSERVATIVE_WRITE_STRATEGY` | Do not use SimConcretizationStrategyAny for writes; in case of write address concretization failures, treat the store as a no-op |  |  |  |
| `CONSTRAINT_TRACKING_IN_SOLVER` | Set `track=True` for making claripy Solvers; enable use of `unsat_core` |  |  |  |
| `COW_STATES` | Copy states instead of mutating the initial state directly | `common_options` | all |  |
| `DOWNSIZE_Z3` | Downsize the claripy solver whenever possible to save memory |  |  |  |
| `DO_CCALLS` | Perform IR clean calls | `symbolic` | all except `fastpath` |  |
| `DO_GETS` | Perform IR register reads | `common_options` | all |  |
| `DO_LOADS` | Perform IR memory loads | `common_options` | all |  |
| `DO_OPS` | Perform IR computation operations | `common_options` | all |  |
| `DO_PUTS` | Perform IR register writes | `common_options` | all |  |
| `DO_RET_EMULATION` | For each `Ijk_Call` successor, add a corresponding `Ijk_FakeRet` successor |  | `static`, `fastpath` |  |
| `DO_STORES` | Perform IR memory stores | `common_options` | all |  |
| `EFFICIENT_STATE_MERGING` | Keep in memory any state that might be a common ancestor in a merge |  |  | Veritesting |
| `ENABLE_NX` | When in conjunction with `STRICT_PAGE_ACCESS`, raise a SimSegfaultException on executing non-executable memory |  |  | Automatically if supported |
| `EXCEPTION_HANDLING` | Ask all SimExceptions raised during execution to be handled by the SimOS |  | `tracing` |  |
| `FAST_MEMORY` | Use `SimFastMemory` for memory storage |  |  |  |
| `FAST_REGISTERS` | Use `SimFastMemory` for register storage |  | `fastpath` |  |
| `INITIALIZE_ZERO_REGISTERS` | Treat the initial value of registers as zero instead of unconstrained symbolic | `unicorn` | `tracing` |  |
| `KEEP_IP_SYMBOLIC` | Don’t try to concretize successor states with symbolic instruction pointers |  |  |  |
| `KEEP_MEMORY_READS_DISCRETE` | In abstract memory, handle failed loads by returning a DCIS? |  |  |  |
| `LAZY_SOLVES` | Don’t check satisfiability until absolutely necessary |  |  |  |
| `MEMORY_SYMBOLIC_BYTES_MAP` | Maintain a mapping of symbolic variable to which memory address it “really” corresponds to, at the paged memory level? |  |  |  |
| `NO_SYMBOLIC_JUMP_RESOLUTION` | Do not attempt to flatten symbolic-ip successors into discrete targets |  | `fastpath` |  |
| `NO_SYMBOLIC_SYSCALL_RESOLUTION` | Do not attempt to flatten symbolic-syscall-number successors into discrete targets |  | `fastpath` |  |
| `OPTIMIZE_IR` | Use LibVEX’s optimization | `common_options` | all |  |
| `REGION_MAPPING` | Maintain a mapping of symbolic variable to which memory region it corresponds to, at the abstract memory level |  | `static` |  |
| `REPLACEMENT_SOLVER` | Enable `SolverReplacement` |  |  |  |
| `REVERSE_MEMORY_HASH_MAP` | Maintain a mapping from AST hash to which addresses it is present in |  |  |  |
| `REVERSE_MEMORY_NAME_MAP` | Maintain a mapping from symbolic variable name to which addresses it is present in, required for `memory.replace_all` |  | `static` |  |
| `SIMPLIFY_CONSTRAINTS` | Run added constraints through z3’s simplifcation |  |  |  |
| `SIMPLIFY_EXIT_GUARD` | Run branch guards through z3’s simplification |  |  |  |
| `SIMPLIFY_EXIT_STATE` | Perform simplification on all successor states generated |  |  |  |
| `SIMPLIFY_EXIT_TARGET` | Run jump/call/branch targets through z3’s simplification |  |  |  |
| `SIMPLIFY_EXPRS` | Run the results of IR expressions through z3’s simplification |  |  |  |
| `SIMPLIFY_MEMORY_READS` | Run the results of memory reads through z3’s simplification |  |  |  |
| `SIMPLIFY_MEMORY_WRITES` | Run values stored to memory through z3’s simplification | `simplification`, `common_options` | `symbolic`, `symbolic_approximating`, `tracing` |  |
| `SIMPLIFY_REGISTER_READS` | Run values read from registers through z3’s simplification |  |  |  |
| `SIMPLIFY_REGISTER_WRITES` | Run values written to registers through z3’s simplification | `simplification`, `common_options` | `symbolic`, `symbolic_approximating`, `tracing` |  |
| `SIMPLIFY_RETS` | Run values returned from SimProcedures through z3’s simplification |  |  |  |
| `STRICT_PAGE_ACCESS` | Raise a SimSegfaultException when attempting to interact with memory in a way not permitted by the current permissions |  | `tracing` |  |
| `SUPER_FASTPATH` | Only execute the last four instructions of each block |  |  |  |
| `SUPPORT_FLOATING_POINT` | When disabled, throw an UnsupportedIROpError when encountering floating point operations | `common_options` | all |  |
| `SYMBOLIC` | Enable constraint solving? | `symbolic` | `symbolic`, `symbolic_approximating`, `fastpath` |  |
| `SYMBOLIC_INITIAL_VALUES` | make `state.solver.Unconstrained` return a symbolic value instead of zero | `symbolic` | all |  |
| `SYMBOLIC_TEMPS` | Treat each IR temporary as a symbolic variable; treat stores to them as constraint addition |  |  |  |
| `SYMBOLIC_WRITE_ADDRESSES` | Allow writes with symbolic addresses to be processed by concretization strategies; when disabled, only allow for variables annotated with the “multiwrite” annotation |  |  |  |
| `TRACK_CONSTRAINTS` | When disabled, don’t keep any constraints added to the state | `symbolic` | all |  |
| `TRACK_CONSTRAINT_ACTIONS` | Keep a SimAction for each constraint added | `refs` |  |  |
| `TRACK_JMP_ACTIONS` | Keep a SimAction for each jump or branch | `refs` |  |  |
| `TRACK_MEMORY_ACTIONS` | Keep a SimAction for each memory read and write | `refs` |  |  |
| `TRACK_MEMORY_MAPPING` | Keep track of which pages are mapped into memory and which are not | `common_options` | all |  |
| `TRACK_OP_ACTIONS` | Keep a SimAction for each IR operation |  | `fastpath` |  |
| `TRACK_REGISTER_ACTIONS` | Keep a SimAction for each register read and write | `refs` |  |  |
| `TRACK_SOLVER_VARIABLES` | Maintain a listing of all the variables in all the constraints in the solver |  |  |  |
| `TRACK_TMP_ACTIONS` | Keep a SimAction for each temporary variable read and write | `refs` |  |  |
| `TRUE_RET_EMULATION_GUARD` | With `DO_RET_EMULATION`, add fake returns with guard condition true instead of false |  | `static` |  |
| `UNDER_CONSTRAINED_SYMEXEC` | Enable under-constrained symbolic execution |  |  |  |
| `UNICORN` | Use unicorn engine to execute symbolically when data is concrete | `unicorn` | `tracing` | Oppologist |
| `UNICORN_AGGRESSIVE_CONCRETIZATION` | Concretize any register variable unicorn tries to access |  |  | Oppologist |
| `UNICORN_HANDLE_TRANSMIT_SYSCALL` | CGC: handle the transmit syscall without leaving unicorn | `unicorn` | `tracing` |  |
| `UNICORN_SYM_REGS_SUPPORT` | Attempt to stay in unicorn even in the presence of symbolic registers by checking that the tainted registers are unused at every step | `unicorn` | `tracing` |  |
| `UNICORN_THRESHOLD_CONCRETIZATION` | Concretize variables if they prevent unicorn from executing too often |  |  |  |
| `UNICORN_TRACK_BBL_ADDRS` | Keep `state.history.bbl_addrs` up to date when using unicorn | `unicorn` | `tracing` |  |
| `UNICORN_TRACK_STACK_POINTERS` | Track a list of the stack pointer’s value at each block in `state.scratch.stack_pointer_list` | `unicorn` |  |  |
| `UNICORN_ZEROPAGE_GUARD` | Prevent unicorn from mapping the zero page into memory |  |  |  |
| `UNINITIALIZED_ACCESS_AWARENESS` | Broken/unused? |  |  |  |
| `UNSUPPORTED_BYPASS_ZERO_DEFAULT` | When using the resilience options, return zero instead of an unconstrained symbol |  |  |  |
| `USE_SIMPLIFIED_CCALLS` | Use a “simplified” set of ccalls optimized for specific cases |  | `static` |  |
| `USE_SYSTEM_TIMES` | In library functions and syscalls and hardware instructions accessing clock data, retrieve the real value from the host system. |  | `tracing` |  |
| `VALIDATE_APPROXIMATIONS` | Debug: When performing approximations, ensure that the approximation is sound by calling into z3 |  |  |  |
| `ZERO_FILL_UNCONSTRAINED_MEMORY` | Make the value of memory read from an uninitialized address zero instead of an unconstrained symbol |  | `tracing` |  |


---

<a id="s71"></a>

<a id="s71--analyses"></a>

## [S71] Analyses

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr’s goal is to make it easy to carry out useful analyses on binary programs. To this end, angr allows you to package analysis code in a common format that can be easily applied to any project. We will cover writing your own analyses [Writing Analyses](#s81--writing-analyses), but the idea is that all the analyses appear under `project.analyses` (for example, `project.analyses.CFGFast()`) and can be called as functions, returning analysis result instances.

<a id="s71--built-in-analyses"></a>

### Built-in Analyses

| Name | Description |
|----|----|
| CFGFast | Constructs a fast *Control Flow Graph* of the program |
| CFGEmulated | Constructs an accurate *Control Flow Graph* of the program |
| VFG | Performs VSA on every function of the program, creating a *Value Flow Graph* and detecting stack variables |
| DDG | Calculates a *Data Dependency Graph*, allowing one to determine what statements a given value depends on |
| BackwardSlice | Computes a *Backward Slice* of a program with respect to a certain target |
| Identifier | Identifies common library functions in CGC binaries |
| More! | angr has quite a few analyses, most of which work! If you’d like to know how to use one, please submit an issue requesting documentation. |

<a id="s71--resilience"></a>

### Resilience

Analyses can be written to be resilient, and catch and log basically any error. These errors, depending on how they’re caught, are logged to the `errors` or `named_errors` attribute of the analysis. However, you might want to run an analysis in “fail fast” mode, so that errors are not handled. To do this, the argument `fail_fast=True` can be passed into the analysis constructor.


---

<a id="s72"></a>

<a id="s72--a-final-word-of-advice"></a>

## [S72] A final word of advice

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


Congratulations! If you’ve read this far through the book (editor’s note: this comment only really applies when we’ve actually finished writing all the TODOs so far) then you’ve been introduced to all the fundamental components of angr necessary to get started with binary analysis.

Ultimately, angr is just an emulator. It is a highly instrumentable and very unique emulator with lots of considerations for environment, true, but at its core, the work you do with angr is about extracting knowledge about how a bunch of bytecode behaves on a CPU. In designing angr, we’ve tried to provide you with the tools and abstractions on top of this emulator to make certain common tasks more useful, but there’s no problem you can’t solve just by working with a SimState and observing the affects of `.step()`.

As you read further into this book, we’ll describe more technical subjects and how to tune angr’s behavior for complicated scenarios. This knowledge should inform your use of angr so you can take the quickest path to a solution to any given problem, but ultimately, you will want to solve problems by exercising creativity with the tools at your disposal. If you can take a problem and wrangle it into a form where it has defined and tractable inputs and outputs, you can absolutely use angr to achieve your goals, given that these goals involve analyzing binaries. None of the abstractions or instrumentations we provide are the end-all of how to use angr for a given task - angr is designed so it can be used in as integrated or as ad-hoc of a manner as you desire. If you see a path from problem to solution, take it.

Of course, it’s very difficult to become well-acquainted with such a huge piece of technology as angr. To this end you can absolutely lean on the community (through the [angr Discord server](http://discord.angr.io) is the best option) to discuss angr and solving problems with it.

Good luck!


---

<a id="s73"></a>

<a id="s73--loading-a-binary"></a>

## [S73] Loading a Binary

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


Previously, you saw just the barest taste of angr’s loading facilities - you loaded `/bin/true`, and then loaded it again without its shared libraries. You also saw `proj.loader` and a few things it could do. Now, we’ll dive into the nuances of these interfaces and the things they can tell you.

We briefly mentioned angr’s binary loading component, CLE. CLE stands for “CLE Loads Everything”, and is responsible for taking a binary (and any libraries that it depends on) and presenting it to the rest of angr in a way that is easy to work with.

<a id="s73--the-loader"></a>

### The Loader

Let’s load `examples/fauxware/fauxware` and take a deeper look at how to interact with the loader.

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>
```

<a id="s73--loaded-objects"></a>

#### Loaded Objects

The CLE loader (`cle.Loader`) represents an entire conglomerate of loaded *binary objects*, loaded and mapped into a single memory space. Each binary object is loaded by a loader backend that can handle its filetype (a subclass of `cle.Backend`). For example, `cle.ELF` is used to load ELF binaries.

There will also be objects in memory that don’t correspond to any loaded binary. For example, an object used to provide thread-local storage support, and an externs object used to provide unresolved symbols.

You can get the full list of objects that CLE has loaded with `loader.all_objects`, as well as several more targeted classifications:

```python
# All loaded objects
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
 <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
 <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]

# This is the "main" object, the one that you directly specified when loading the project
>>> proj.loader.main_object
<ELF Object fauxware, maps [0x400000:0x60105f]>

# This is a dictionary mapping from shared object name to object
>>> proj.loader.shared_objects
{ 'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
  'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
  'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]> }

# Here's all the objects that were loaded from ELF files
# If this were a windows program we'd use all_pe_objects!
>>> proj.loader.all_elf_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>]

# Here's the "externs object", which we use to provide addresses for unresolved imports and angr internals
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x4000000:0x4008000]>

# This object is used to provide addresses for emulated syscalls
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>

# Finally, you can to get a reference to an object given an address in it
>>> proj.loader.find_object_containing(0x400000)
<ELF Object fauxware, maps [0x400000:0x60105f]>
```

You can interact directly with these objects to extract metadata from them:

```python
>>> obj = proj.loader.main_object

# The entry point of the object
>>> obj.entry
0x400580

>>> obj.min_addr, obj.max_addr
(0x400000, 0x60105f)

# Retrieve this ELF's segments and sections
>>> obj.segments
<Regions: [<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>,
           <ELFSegment memsize=0x238, filesize=0x228, vaddr=0x600e28, flags=0x6, offset=0xe28>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc

# You can get an individual segment or section by an address it contains:
>>> obj.find_segment_containing(obj.entry)
<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# Get the address of the PLT stub for a symbol
>>> addr = obj.plt['strcmp']
>>> addr
0x400550
>>> obj.reverse_plt[addr]
'strcmp'

# Show the prelinked base of the object and the location it was actually mapped into memory by CLE
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```

<a id="s73--symbols-and-relocations"></a>

#### Symbols and Relocations

You can also work with symbols while using CLE. A symbol is a fundamental concept in the world of executable formats, effectively mapping a name to an address.

The easiest way to get a symbol from CLE is to use `loader.find_symbol`, which takes either a name or an address and returns a Symbol object.

```python
>>> strcmp = proj.loader.find_symbol('strcmp')
>>> strcmp
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```

The most useful attributes on a symbol are its name, its owner, and its address, but the “address” of a symbol can be ambiguous. The Symbol object has three ways of reporting its address:

- `.rebased_addr` is its address in the global address space. This is what is shown in the print output.

- `.linked_addr` is its address relative to the prelinked base of the binary. This is the address reported in, for example, `readelf(1)`.

- `.relative_addr` is its address relative to the object base. This is known in the literature (particularly the Windows literature) as an RVA (relative virtual address).

```python
>>> strcmp.name
'strcmp'

>>> strcmp.owner
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>

>>> strcmp.rebased_addr
0x1089cd0
>>> strcmp.linked_addr
0x89cd0
>>> strcmp.relative_addr
0x89cd0
```

In addition to providing debug information, symbols also support the notion of dynamic linking. libc provides the strcmp symbol as an export, and the main binary depends on it. If we ask CLE to give us a strcmp symbol from the main object directly, it’ll tell us that this is an *import symbol*. Import symbols do not have meaningful addresses associated with them, but they do provide a reference to the symbol that was used to resolve them, as `.resolvedby`.

```python
>>> strcmp.is_export
True
>>> strcmp.is_import
False

# On Loader, the method is find_symbol because it performs a search operation to find the symbol.
# On an individual object, the method is get_symbol because there can only be one symbol with a given name.
>>> main_strcmp = proj.loader.main_object.get_symbol('strcmp')
>>> main_strcmp
<Symbol "strcmp" in fauxware (import)>
>>> main_strcmp.is_export
False
>>> main_strcmp.is_import
True
>>> main_strcmp.resolvedby
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```

The specific ways that the links between imports and exports should be registered in memory are handled by another notion called *relocations*. A relocation says, “when you match *\[import\]* up with an export symbol, please write the export’s address to *\[location\]*, formatted as *\[format\]*.” We can see the full list of relocations for an object (as `Relocation` instances) as `obj.relocs`, or just a mapping from symbol name to Relocation as `obj.imports`. There is no corresponding list of export symbols.

A relocation’s corresponding import symbol can be accessed as `.symbol`. The address the relocation will write to is accessible through any of the address identifiers you can use for Symbol, and you can get a reference to the object requesting the relocation with `.owner` as well.

```python
# Relocations don't have a good pretty-printing, so those addresses are Python-internal, unrelated to our program
>>> proj.loader.shared_objects['libc.so.6'].imports
{'__libc_enable_secure': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce780>,
 '__tls_get_addr': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018358>,
 '_dl_argv': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2e48>,
 '_dl_find_dso_for_object': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018588>,
 '_dl_starting_up': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2550>,
 '_rtld_global': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce4e0>,
 '_rtld_global_ro': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fcea20>}
```

If an import cannot be resolved to any export, for example, because a shared library could not be found, CLE will automatically update the externs object (`loader.extern_obj`) to claim it provides the symbol as an export.

<a id="s73--loading-options"></a>

### Loading Options

If you are loading something with `angr.Project` and you want to pass an option to the `cle.Loader` instance that Project implicitly creates, you can just pass the keyword argument directly to the Project constructor, and it will be passed on to CLE. You should look at the [CLE API docs.](https://docs.angr.io/projects/cle/en/latest/api.html) if you want to know everything that could possibly be passed in as an option, but we will go over some important and frequently used options here.

<a id="s73--basic-options"></a>

#### Basic Options

We’ve discussed `auto_load_libs` already - it enables or disables CLE’s attempt to automatically resolve shared library dependencies, and is off by default. Additionally, there is the opposite, `except_missing_libs`, which, if set to true, will cause an exception to be thrown whenever a binary has a shared library dependency that cannot be resolved.

You can pass a list of strings to `force_load_libs` and anything listed will be treated as an unresolved shared library dependency right out of the gate, or you can pass a list of strings to `skip_libs` to prevent any library of that name from being resolved as a dependency. Additionally, you can pass a list of strings (or a single string) to `ld_path`, which will be used as an additional search path for shared libraries, before any of the defaults: the same directory as the loaded program, the current working directory, and your system libraries.

<a id="s73--per-binary-options"></a>

#### Per-Binary Options

If you want to specify some options that only apply to a specific binary object, CLE will let you do that too. The parameters `main_opts` and `lib_opts` do this by taking dictionaries of options. `main_opts` is a mapping from option names to option values, while `lib_opts` is a mapping from library name to dictionaries mapping option names to option values.

The options that you can use vary from backend to backend, but some common ones are:

- `backend` - which backend to use, as either a class or a name

- `base_addr` - a base address to use

- `entry_point` - an entry point to use

- `arch` - the name of an architecture to use

Example:

```python
>>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
<Project examples/fauxware/fauxware>
```

<a id="s73--backends"></a>

#### Backends

CLE currently has backends for statically loading ELF, PE, CGC, Mach-O and ELF core dump files, as well as loading files into a flat address space. CLE will automatically detect the correct backend to use in most cases, so you shouldn’t need to specify which backend you’re using unless you’re doing some pretty weird stuff.

You can force CLE to use a specific backend for an object by including a key in its options dictionary, as described above. Some backends cannot autodetect which architecture to use and *must* have a `arch` specified. The key doesn’t need to match any list of architectures; angr will identify which architecture you mean given almost any common identifier for any supported arch.

To refer to a backend, use the name from this table:

| backend name | description | requires `arch`? |
|----|----|----|
| elf | Static loader for ELF files based on PyELFTools | no |
| pe | Static loader for PE files based on PEFile | no |
| mach-o | Static loader for Mach-O files. Does not support dynamic linking or rebasing. | no |
| cgc | Static loader for Cyber Grand Challenge binaries | no |
| backedcgc | Static loader for CGC binaries that allows specifying memory and register backers | no |
| elfcore | Static loader for ELF core dumps | no |
| blob | Loads the file into memory as a flat image | yes |

<a id="s73--symbolic-function-summaries"></a>

### Symbolic Function Summaries

By default, Project tries to replace external calls to library functions by using symbolic summaries termed *SimProcedures* - effectively just Python functions that imitate the library function’s effect on the state. We’ve implemented [a whole bunch of functions](https://github.com/angr/angr/tree/master/angr/procedures) as SimProcedures. These builtin procedures are available in the `angr.SIM_PROCEDURES` dictionary, which is two-leveled, keyed first on the package name (libc, posix, win32, stubs) and then on the name of the library function. Executing a SimProcedure instead of the actual library function that gets loaded from your system makes analysis a LOT more tractable, at the cost of [some potential inaccuracies](#s52--gotchas-when-using-angr).

When no such summary is available for a given function:

- if `auto_load_libs` is `True`, then the *real* library function is executed instead. This may or may not be what you want, depending on the actual function. For example, some of libc’s functions are extremely complex to analyze and will most likely cause an explosion of the number of states for the path trying to execute them.

- if `auto_load_libs` is `False` (this is the default), then external functions are unresolved, and Project will resolve them to a generic “stub” SimProcedure called `ReturnUnconstrained`. It does what its name says: it returns a unique unconstrained symbolic value each time it is called.

- if `use_sim_procedures` (this is a parameter to `angr.Project`, not `cle.Loader`) is `False` (it is `True` by default), then only symbols provided by the extern object will be replaced with SimProcedures, and they will be replaced by a stub `ReturnUnconstrained`, which does nothing but return a symbolic value.

- you may specify specific symbols to exclude from being replaced with SimProcedures with the parameters to `angr.Project`: `exclude_sim_procedures_list` and `exclude_sim_procedures_func`.

- Look at the code for `angr.Project._register_object` for the exact algorithm.

<a id="s73--hooking"></a>

#### Hooking

The mechanism by which angr replaces library code with a Python summary is called hooking, and you can do it too! When performing simulation, at every step angr checks if the current address has been hooked, and if so, runs the hook instead of the binary code at that address. The API to let you do this is `proj.hook(addr, hook)`, where `hook` is a SimProcedure instance. You can manage your project’s hooks with `.is_hooked`, `.unhook`, and `.hooked_by`, which should hopefully not require explanation.

There is an alternate API for hooking an address that lets you specify your own off-the-cuff function to use as a hook, by using `proj.hook(addr)` as a function decorator. If you do this, you can also optionally specify a `length` keyword argument to make execution jump some number of bytes forward after your hook finishes.

```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```

Furthermore, you can use `proj.hook_symbol(name, hook)`, providing the name of a symbol as the first argument, to hook the address where the symbol lives. One very important usage of this is to extend the behavior of angr’s built-in library SimProcedures. Since these library functions are just classes, you can subclass them, overriding pieces of their behavior, and then use your subclass in a hook.

<a id="s73--so-far-so-good"></a>

### So far so good!

By now, you should have a reasonable understanding of how to control the environment in which your analysis happens, on the level of the CLE loader and the angr Project. You should also understand that angr makes a reasonable attempt to simplify its analysis by hooking complex library functions with SimProcedures that summarize the effects of the functions.

In order to see all the things you can do with the CLE loader and its backends, look at the [CLE API docs.](https://docs.angr.io/projects/cle/en/latest/api.html)


---

<a id="s74"></a>

<a id="s74--simulation-managers"></a>

## [S74] Simulation Managers

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


The most important control interface in angr is the SimulationManager, which allows you to control symbolic execution over groups of states simultaneously, applying search strategies to explore a program’s state space. Here, you’ll learn how to use it.

Simulation managers let you wrangle multiple states in a slick way. States are organized into “stashes”, which you can step forward, filter, merge, and move around as you wish. This allows you to, for example, step two different stashes of states at different rates, then merge them together. The default stash for most operations is the `active` stash, which is where your states get put when you initialize a new simulation manager.

<a id="s74--stepping"></a>

### Stepping

The most basic capability of a simulation manager is to step forward all states in a given stash by one basic block. You do this with `.step()`.

```python
>>> import angr
>>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
>>> state = proj.factory.entry_state()
>>> simgr = proj.factory.simgr(state)
>>> simgr.active
[<SimState @ 0x400580>]

>>> simgr.step()
>>> simgr.active
[<SimState @ 0x400540>]
```

Of course, the real power of the stash model is that when a state encounters a symbolic branch condition, both of the successor states appear in the stash, and you can step both of them in sync. When you don’t really care about controlling analysis very carefully and you just want to step until there’s nothing left to step, you can just use the `.run()` method.

```python
# Step until the first symbolic branch
>>> while len(simgr.active) == 1:
...    simgr.step()

>>> simgr
<SimulationManager with 2 active>
>>> simgr.active
[<SimState @ 0x400692>, <SimState @ 0x400699>]

# Step until everything terminates
>>> simgr.run()
>>> simgr
<SimulationManager with 3 deadended>
```

We now have 3 deadended states! When a state fails to produce any successors during execution, for example, because it reached an `exit` syscall, it is removed from the active stash and placed in the `deadended` stash.

<a id="s74--stash-management"></a>

### Stash Management

Let’s see how to work with other stashes.

To move states between stashes, use `.move()`, which takes `from_stash`, `to_stash`, and `filter_func` (optional, default is to move everything). For example, let’s move everything that has a certain string in its output:

```python
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
>>> simgr
<SimulationManager with 2 authenticated, 1 deadended>
```

We were able to just create a new stash named “authenticated” just by asking for states to be moved to it. All the states in this stash have “Welcome” in their stdout, which is a fine metric for now.

Each stash is just a list, and you can index into or iterate over the list to access each of the individual states, but there are some alternate methods to access the states too. If you prepend the name of a stash with `one_`, you will be given the first state in the stash. If you prepend the name of a stash with `mp_`, you will be given a [mulpyplexed](https://github.com/zardus/mulpyplexer) version of the stash.

```python
>>> for s in simgr.deadended + simgr.authenticated:
...     print(hex(s.addr))
0x1000030
0x1000078
0x1000078

>>> simgr.one_deadended
<SimState @ 0x1000030>
>>> simgr.mp_authenticated
MP([<SimState @ 0x1000078>, <SimState @ 0x1000078>])
>>> simgr.mp_authenticated.posix.dumps(0)
MP(['\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x80\x80\x80\x80@\x80@\x00'])
```

Of course, `step`, `run`, and any other method that operates on a single stash of paths can take a `stash` argument, specifying which stash to operate on.

There are lots of fun tools that the simulation manager provides you for managing your stashes. We won’t go into the rest of them for now, but you should check out the [API documentation](https://docs.angr.io/en/latest/api/angr.sim_manager.html).

<a id="s74--stash-types"></a>

#### Stash types

You can use stashes for whatever you like, but there are a few stashes that will be used to categorize some special kinds of states. These are:

| Stash | Description |
|----|----|
| active | This stash contains the states that will be stepped by default, unless an alternate stash is specified. |
| deadended | A state goes to the deadended stash when it cannot continue the execution for some reason, including no more valid instructions, unsat state of all of its successors, or an invalid instruction pointer. |
| pruned | When using `LAZY_SOLVES`, states are not checked for satisfiability unless absolutely necessary. When a state is found to be unsat in the presence of `LAZY_SOLVES`, the state hierarchy is traversed to identify when, in its history, it initially became unsat. All states that are descendants of that point (which will also be unsat, since a state cannot become un-unsat) are pruned and put in this stash. |
| unconstrained | If the `save_unconstrained` option is provided to the SimulationManager constructor, states that are determined to be unconstrained (i.e., with the instruction pointer controlled by user data or some other source of symbolic data) are placed here. |
| unsat | If the `save_unsat` option is provided to the SimulationManager constructor, states that are determined to be unsatisfiable (i.e., they have constraints that are contradictory, like the input having to be both “AAAA” and “BBBB” at the same time) are placed here. |

There is another list of states that is not a stash: `errored`. If, during execution, an error is raised, then the state will be wrapped in an `ErrorRecord` object, which contains the state and the error it raised, and then the record will be inserted into `errored`. You can get at the state as it was at the beginning of the execution tick that caused the error with `record.state`, you can see the error that was raised with `record.error`, and you can launch a debug shell at the site of the error with `record.debug()`. This is an invaluable debugging tool!

<a id="s74--simple-exploration"></a>

### Simple Exploration

An extremely common operation in symbolic execution is to find a state that reaches a certain address, while discarding all states that go through another address. Simulation manager has a shortcut for this pattern, the `.explore()` method.

When launching `.explore()` with a `find` argument, execution will run until a state is found that matches the find condition, which can be the address of an instruction to stop at, a list of addresses to stop at, or a function which takes a state and returns whether it meets some criteria. When any of the states in the active stash match the `find` condition, they are placed in the `found` stash, and execution terminates. You can then explore the found state, or decide to discard it and continue with the other ones. You can also specify an `avoid` condition in the same format as `find`. When a state matches the avoid condition, it is put in the `avoided` stash, and execution continues. Finally, the `num_find` argument controls the number of states that should be found before returning, with a default of 1. Of course, if you run out of states in the active stash before finding this many solutions, execution will stop anyway.

Let’s look at a simple crackme [example](https://github.com/angr/angr-examples/tree/master/examples/CSCI-4968-MBE/challenges/crackme0x00a):

First, we load the binary.

```python
>>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')
```

Next, we create a SimulationManager.

```python
>>> simgr = proj.factory.simgr()
```

Now, we symbolically execute until we find a state that matches our condition (i.e., the “win” condition).

```python
>>> simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>
```

Now, we can get the flag out of that state!

```python
>>> s = simgr.found[0]
>>> print(s.posix.dumps(1))
Enter password: Congrats!

>>> flag = s.posix.dumps(0)
>>> print(flag)
g00dJ0B!
```

Pretty simple, isn’t it?

Other examples can be found by browsing the [examples](#s80--angr-examples).

<a id="s74--exploration-techniques"></a>

#### Exploration Techniques

angr ships with several pieces of canned functionality that let you customize the behavior of a simulation manager, called *exploration techniques*. The archetypical example of why you would want an exploration technique is to modify the pattern in which the state space of the program is explored - the default “step everything at once” strategy is effectively breadth-first search, but with an exploration technique you could implement, for example, depth-first search. However, the instrumentation power of these techniques is much more flexible than that - you can totally alter the behavior of angr’s stepping process. Writing your own exploration techniques will be covered in a later chapter.

To use an exploration technique, call `simgr.use_technique(tech)`, where tech is an instance of an ExplorationTechnique subclass. angr’s built-in exploration techniques can be found under `angr.exploration_techniques`.

Here’s a quick overview of some of the built-in ones:

- *DFS*: Depth first search, as mentioned earlier. Keeps only one state active at once, putting the rest in the `deferred` stash until it deadends or errors.

- *Explorer*: This technique implements the `.explore()` functionality, allowing you to search for and avoid addresses.

- *LengthLimiter*: Puts a cap on the maximum length of the path a state goes through.

- *LoopSeer*: Uses a reasonable approximation of loop counting to discard states that appear to be going through a loop too many times, putting them in a `spinning` stash and pulling them out again if we run out of otherwise viable states.

- *ManualMergepoint*: Marks an address in the program as a merge point, so states that reach that address will be briefly held, and any other states that reach that same point within a timeout will be merged together.

- *MemoryWatcher*: Monitors how much memory is free/available on the system between simgr steps and stops exploration if it gets too low.

- *Oppologist*: The “operation apologist” is an especially fun gadget - if this technique is enabled and angr encounters an unsupported instruction, for example a bizarre and foreign floating point SIMD op, it will concretize all the inputs to that instruction and emulate the single instruction using the unicorn engine, allowing execution to continue.

- *Spiller*: When there are too many states active, this technique can dump some of them to disk in order to keep memory consumption low.

- *Threading*: Adds thread-level parallelism to the stepping process. This doesn’t help much because of Python’s global interpreter locks, but if you have a program whose analysis spends a lot of time in angr’s native-code dependencies (unicorn, z3, libvex) you can seem some gains.

- *Tracer*: An exploration technique that causes execution to follow a dynamic trace recorded from some other source. The [dynamic tracer repository](https://github.com/angr/tracer) has some tools to generate those traces.

- *Veritesting*: An implementation of a [CMU paper](https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf) on automatically identifying useful merge points. This is so useful, you can enable it automatically with `veritesting=True` in the SimulationManager constructor! Note that it frequenly doesn’t play nice with other techniques due to the invasive way it implements static symbolic execution.

Look at the API documentation for the [`SimulationManager`](https://docs.angr.io/en/latest/api/angr.sim_manager.html#angr.sim_manager.SimulationManager) and `ExplorationTechnique` classes for more information.


---

<a id="s75"></a>

<a id="s75--simulation-and-instrumentation"></a>

## [S75] Simulation and Instrumentation

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


When you ask for a step of execution to happen in angr, something has to actually perform the step. angr uses a series of engines (subclasses of the `SimEngine` class) to emulate the effects that of a given section of code has on an input state. The execution core of angr simply tries all the available engines in sequence, taking the first one that is able to handle the step. The following is the default list of engines, in order:

- The failure engine kicks in when the previous step took us to some uncontinuable state

- The syscall engine kicks in when the previous step ended in a syscall

- The hook engine kicks in when the current address is hooked

- The unicorn engine kicks in when the `UNICORN` state option is enabled and there is no symbolic data in the state

- The VEX engine kicks in as the final fallback.

<a id="s75--simsuccessors"></a>

### SimSuccessors

The code that actually tries all the engines in turn is `project.factory.successors(state, **kwargs)`, which passes its arguments onto each of the engines. This function is at the heart of `state.step()` and `simulation_manager.step()`. It returns a SimSuccessors object, which we discussed briefly before. The purpose of SimSuccessors is to perform a simple categorization of the successor states, stored in various list attributes. They are:

| Attribute | Guard Condition | Instruction Pointer | Description |
|----|----|----|----|
| `successors` | True (can be symbolic, but constrained to True) | Can be symbolic (but 256 solutions or less; see `unconstrained_successors`). | A normal, satisfiable successor state to the state processed by the engine. The instruction pointer of this state may be symbolic (i.e., a computed jump based on user input), so the state might actually represent *several* potential continuations of execution going forward. |
| `unsat_successors` | False (can be symbolic, but constrained to False). | Can be symbolic. | Unsatisfiable successors. These are successors whose guard conditions can only be false (i.e., jumps that cannot be taken, or the default branch of jumps that *must* be taken). |
| `flat_successors` | True (can be symbolic, but constrained to True). | Concrete value. | As noted above, states in the `successors` list can have symbolic instruction pointers. This is rather confusing, as elsewhere in the code (i.e., in `SimEngineVEX.process`, when it’s time to step that state forward), we make assumptions that a single program state only represents the execution of a single spot in the code. To alleviate this, when we encounter states in `successors` with symbolic instruction pointers, we compute all possible concrete solutions (up to an arbitrary threshold of 256) for them, and make a copy of the state for each such solution. We call this process “flattening”. These `flat_successors` are states, each of which has a different, concrete instruction pointer. For example, if the instruction pointer of a state in `successors` was `X+5`, where `X` had constraints of `X > 0x800000` and `X <= 0x800010`, we would flatten it into 16 different `flat_successors` states, one with an instruction pointer of `0x800006`, one with `0x800007`, and so on until `0x800015`. |
| `unconstrained_successors` | True (can be symbolic, but constrained to True). | Symbolic (with more than 256 solutions). | During the flattening procedure described above, if it turns out that there are more than 256 possible solutions for the instruction pointer, we assume that the instruction pointer has been overwritten with unconstrained data (i.e., a stack overflow with user data). *This assumption is not sound in general*. Such states are placed in `unconstrained_successors` and not in `successors`. |
| `all_successors` | Anything | Can be symbolic. | This is `successors + unsat_successors + unconstrained_successors`. |

<a id="s75--breakpoints"></a>

### Breakpoints

<a id="s75--id1"></a>

Todo

rewrite this to fix the narrative

Like any decent execution engine, angr supports breakpoints. This is pretty cool! A point is set as follows:

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')

# get our state
>>> s = b.factory.entry_state()

# add a breakpoint. This breakpoint will drop into ipdb right before a memory write happens.
>>> s.inspect.b('mem_write')

# on the other hand, we can have a breakpoint trigger right *after* a memory write happens.
# we can also have a callback function run instead of opening ipdb.
>>> def debug_func(state):
...     print(f"State {state} is about to do a memory write!")

>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)

# or, you can have it drop you in an embedded IPython!
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=angr.BP_IPYTHON)
```

There are many other places to break than a memory write. Here is the list. You can break at BP_BEFORE or BP_AFTER for each of these events.

| Event type | Event meaning |
|----|----|
| mem_read | Memory is being read. |
| mem_write | Memory is being written. |
| address_concretization | A symbolic memory access is being resolved. |
| reg_read | A register is being read. |
| reg_write | A register is being written. |
| tmp_read | A temp is being read. |
| tmp_write | A temp is being written. |
| expr | An expression is being created (i.e., a result of an arithmetic operation or a constant in the IR). |
| statement | An IR statement is being translated. |
| instruction | A new (native) instruction is being translated. |
| irsb | A new basic block is being translated. |
| constraints | New constraints are being added to the state. |
| exit | A successor is being generated from execution. |
| fork | A symbolic execution state has forked into multiple states. |
| symbolic_variable | A new symbolic variable is being created. |
| call | A call instruction is hit. |
| return | A ret instruction is hit. |
| simprocedure | A simprocedure (or syscall) is executed. |
| dirty | A dirty IR callback is executed. |
| syscall | A syscall is executed (called in addition to the simprocedure event). |
| engine_process | A SimEngine is about to process some code. |

These events expose different attributes:

| Event type | Attribute name | Attribute availability | Attribute meaning |
|----|----|----|----|
| mem_read | mem_read_address | BP_BEFORE or BP_AFTER | The address at which memory is being read. |
| mem_read | mem_read_expr | BP_AFTER | The expression at that address. |
| mem_read | mem_read_length | BP_BEFORE or BP_AFTER | The length of the memory read. |
| mem_read | mem_read_condition | BP_BEFORE or BP_AFTER | The condition of the memory read. |
| mem_write | mem_write_address | BP_BEFORE or BP_AFTER | The address at which memory is being written. |
| mem_write | mem_write_length | BP_BEFORE or BP_AFTER | The length of the memory write. |
| mem_write | mem_write_expr | BP_BEFORE or BP_AFTER | The expression that is being written. |
| mem_write | mem_write_condition | BP_BEFORE or BP_AFTER | The condition of the memory write. |
| reg_read | reg_read_offset | BP_BEFORE or BP_AFTER | The offset of the register being read. |
| reg_read | reg_read_length | BP_BEFORE or BP_AFTER | The length of the register read. |
| reg_read | reg_read_expr | BP_AFTER | The expression in the register. |
| reg_read | reg_read_condition | BP_BEFORE or BP_AFTER | The condition of the register read. |
| reg_write | reg_write_offset | BP_BEFORE or BP_AFTER | The offset of the register being written. |
| reg_write | reg_write_length | BP_BEFORE or BP_AFTER | The length of the register write. |
| reg_write | reg_write_expr | BP_BEFORE or BP_AFTER | The expression that is being written. |
| reg_write | reg_write_condition | BP_BEFORE or BP_AFTER | The condition of the register write. |
| tmp_read | tmp_read_num | BP_BEFORE or BP_AFTER | The number of the temp being read. |
| tmp_read | tmp_read_expr | BP_AFTER | The expression of the temp. |
| tmp_write | tmp_write_num | BP_BEFORE or BP_AFTER | The number of the temp written. |
| tmp_write | tmp_write_expr | BP_AFTER | The expression written to the temp. |
| expr | expr | BP_BEFORE or BP_AFTER | The IR expression. |
| expr | expr_result | BP_AFTER | The value (e.g. AST) which the expression was evaluated to. |
| statement | statement | BP_BEFORE or BP_AFTER | The index of the IR statement (in the IR basic block). |
| instruction | instruction | BP_BEFORE or BP_AFTER | The address of the native instruction. |
| irsb | address | BP_BEFORE or BP_AFTER | The address of the basic block. |
| constraints | added_constraints | BP_BEFORE or BP_AFTER | The list of constraint expressions being added. |
| call | function_address | BP_BEFORE or BP_AFTER | The name of the function being called. |
| exit | exit_target | BP_BEFORE or BP_AFTER | The expression representing the target of a SimExit. |
| exit | exit_guard | BP_BEFORE or BP_AFTER | The expression representing the guard of a SimExit. |
| exit | exit_jumpkind | BP_BEFORE or BP_AFTER | The expression representing the kind of SimExit. |
| symbolic_variable | symbolic_name | BP_AFTER | The name of the symbolic variable being created. The solver engine might modify this name (by appending a unique ID and length). Check the symbolic_expr for the final symbolic expression. |
| symbolic_variable | symbolic_size | BP_AFTER | The size of the symbolic variable being created. |
| symbolic_variable | symbolic_expr | BP_AFTER | The expression representing the new symbolic variable. |
| address_concretization | address_concretization_strategy | BP_BEFORE or BP_AFTER | The SimConcretizationStrategy being used to resolve the address. This can be modified by the breakpoint handler to change the strategy that will be applied. If your breakpoint handler sets this to None, this strategy will be skipped. |
| address_concretization | address_concretization_action | BP_BEFORE or BP_AFTER | The SimAction object being used to record the memory action. |
| address_concretization | address_concretization_memory | BP_BEFORE or BP_AFTER | The SimMemory object on which the action was taken. |
| address_concretization | address_concretization_expr | BP_BEFORE or BP_AFTER | The AST representing the memory index being resolved. The breakpoint handler can modify this to affect the address being resolved. |
| address_concretization | address_concretization_add_constraints | BP_BEFORE or BP_AFTER | Whether or not constraints should/will be added for this read. |
| address_concretization | address_concretization_result | BP_AFTER | The list of resolved memory addresses (integers). The breakpoint handler can overwrite these to effect a different resolution result. |
| syscall | syscall_name | BP_BEFORE or BP_AFTER | The name of the system call. |
| simprocedure | simprocedure_name | BP_BEFORE or BP_AFTER | The name of the simprocedure. |
| simprocedure | simprocedure_addr | BP_BEFORE or BP_AFTER | The address of the simprocedure. |
| simprocedure | simprocedure_result | BP_AFTER | The return value of the simprocedure. You can also *override* it in BP_BEFORE, which will cause the actual simprocedure to be skipped and for your return value to be used instead. |
| simprocedure | simprocedure | BP_BEFORE or BP_AFTER | The actual SimProcedure object. |
| dirty | dirty_name | BP_BEFORE or BP_AFTER | The name of the dirty call. |
| dirty | dirty_handler | BP_BEFORE | The function that will be run to handle the dirty call. You can override this. |
| dirty | dirty_args | BP_BEFORE or BP_AFTER | The address of the dirty. |
| dirty | dirty_result | BP_AFTER | The return value of the dirty call. You can also *override* it in BP_BEFORE, which will cause the actual dirty call to be skipped and for your return value to be used instead. |
| engine_process | sim_engine | BP_BEFORE or BP_AFTER | The SimEngine that is processing. |
| engine_process | successors | BP_BEFORE or BP_AFTER | The SimSuccessors object defining the result of the engine. |

These attributes can be accessed as members of `state.inspect.attrs` during the appropriate breakpoint callback to access the appropriate values. You can even modify these value to modify further uses of the values!

```python
>>> def track_reads(state):
...     print('Read', state.inspect.attrs.mem_read_expr, 'from', state.inspect.attrs.mem_read_address)
...
>>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)
```

Additionally, each of these properties can be used as a keyword argument to `inspect.b` to make the breakpoint conditional:

```python
# This will break before a memory write if 0x1000 is a possible value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# This will break before a memory write if 0x1000 is the *only* value of its target expression
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# This will break after instruction 0x8000, but only 0x1000 is a possible value of the last expression that was read from memory
>>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

Cool stuff! In fact, we can even specify a function as a condition:

```python
# this is a complex condition that could do anything! In this case, it makes sure that RAX is 0x41414141 and
# that the basic block starting at 0x8004 was executed sometime in this path's history
>>> def cond(state):
...     return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.attrs.backtrace

>>> s.inspect.b('mem_write', condition=cond)
```

That is some cool stuff!

<a id="s75--caution-about-mem-read-breakpoint"></a>

#### Caution about `mem_read` breakpoint

The `mem_read` breakpoint gets triggered anytime there are memory reads by either the executing program or the binary analysis. If you are using breakpoint on `mem_read` and also using `state.mem` to load data from memory addresses, then know that the breakpoint will be fired as you are technically reading memory.

So if you want to load data from memory and not trigger any `mem_read` breakpoint you have had set up, then use `state.memory.load` with the keyword arguments `disable_actions=True` and `inspect=False`.

This is also true for `state.find` and you can use the same keyword arguments to prevent `mem_read` breakpoints from firing.


---

<a id="s76"></a>

<a id="s76--symbolic-expressions-and-constraint-solving"></a>

## [S76] Symbolic Expressions and Constraint Solving

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr’s power comes not from it being an emulator, but from being able to execute with what we call *symbolic variables*. Instead of saying that a variable has a *concrete* numerical value, we can say that it holds a *symbol*, effectively just a name. Then, performing arithmetic operations with that variable will yield a tree of operations (termed an *abstract syntax tree* or *AST*, from compiler theory). ASTs can be translated into constraints for an *SMT solver*, like z3, in order to ask questions like *“given the output of this sequence of operations, what must the input have been?”* Here, you’ll learn how to use angr to answer this.

<a id="s76--working-with-bitvectors"></a>

### Working with Bitvectors

Let’s get a dummy project and state so we can start playing with numbers.

```python
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()
```

A bitvector is just a sequence of bits, interpreted with the semantics of a bounded integer for arithmetic. Let’s make a few.

```python
# 64-bit bitvectors with concrete values 1 and 100
>>> one = claripy.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred =claripy.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# create a 27-bit bitvector with concrete value 9
>>> weird_nine = claripy.BVV(9, 27)
>>> weird_nine
<BV27 0x9>
```

As you can see, you can have any sequence of bits and call them a bitvector. You can do math with them too:

```python
>>> one + one_hundred
<BV64 0x65>

# You can provide normal Python integers and they will be coerced to the
appropriate type: >>> one_hundred + 0x100 <BV64 0x164>

# The semantics of normal wrapping arithmetic apply
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>
```

You *cannot* say `one + weird_nine`, though. It is a type error to perform an operation on bitvectors of differing lengths. You can, however, extend `weird_nine` so it has an appropriate number of bits:

```python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```

`zero_extend` will pad the bitvector on the left with the given number of zero bits. You can also use `sign_extend` to pad with a duplicate of the highest bit, preserving the value of the bitvector under two’s complement signed integer semantics.

Now, let’s introduce some symbols into the mix.

```python
# Create a bitvector symbol named "x" of length 64 bits
>>> x = claripy.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = claripy.BVS("y", 64)
>>> y
<BV64 y_10_64>
```

`x` and `y` are now *symbolic variables*, which are kind of like the variables you learned to work with in 7th grade algebra. Notice that the name you provided has been mangled by appending an incrementing counter and You can do as much arithmetic as you want with them, but you won’t get a number back, you’ll get an AST instead.

```python
>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>
```

Technically `x` and `y` and even `one` are also ASTs - any bitvector is a tree of operations, even if that tree is only one layer deep. To understand this, let’s learn how to process ASTs.

Each AST has a `.op` and a `.args`. The op is a string naming the operation being performed, and the args are the values the operation takes as input. Unless the op is `BVV` or `BVS` (or a few others…), the args are all other ASTs, the tree eventually terminating with BVVs or BVSs.

```python
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__floordiv__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
>>> tree.args[0].args[1].op
'BVV'
>>> tree.args[0].args[1].args
(1, 64)
```

From here on out, we will use the word “bitvector” to refer to any AST whose topmost operation produces a bitvector. There can be other data types represented through ASTs, including floating point numbers and, as we’re about to see, booleans.

<a id="s76--symbolic-constraints"></a>

### Symbolic Constraints

Performing comparison operations between any two similarly-typed ASTs will yield another AST - not a bitvector, but now a symbolic boolean.

```python
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>
```

One tidbit you can see from this is that the comparisons are unsigned by default. The -5 in the last example is coerced to `<BV64 0xfffffffffffffffb>`, which is definitely not less than one hundred. If you want the comparison to be signed, you can say `one_hundred.SGT(-5)` (that’s “signed greater-than”). A full list of operations can be found at the end of this chapter.

This snippet also illustrates an important point about working with angr - you should never directly use a comparison between variables in the condition for an if- or while-statement, since the answer might not have a concrete truth value. Even if there is a concrete truth value, `if one > one_hundred` will raise an exception. Instead, you should use `solver.is_true` and `solver.is_false`, which test for concrete truthyness/falsiness without performing a constraint solve.

```python
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes)
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False
```

<a id="s76--constraint-solving"></a>

### Constraint Solving

You can treat any symbolic boolean as an assertion about the valid values of a symbolic variable by adding it as a *constraint* to the state. You can then query for a valid value of a symbolic variable by asking for an evaluation of a symbolic expression.

An example will probably be more clear than an explanation here:

```python
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
4
```

By adding these constraints to the state, we’ve forced the constraint solver to consider them as assertions that must be satisfied about any values it returns. If you run this code, you might get a different value for x, but that value will definitely be greater than 3 (since y must be greater than 2 and x must be greater than y) and less than 10. Furthermore, if you then say `state.solver.eval(y)`, you’ll get a value of y which is consistent with the value of x that you got. If you don’t add any constraints between two queries, the results will be consistent with each other.

From here, it’s easy to see how to do the task we proposed at the beginning of the chapter - finding the input that produced a given output.

```python
# get a fresh state without constraints
>>> state = proj.factory.entry_state()
>>> input = claripy.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
```

Note that, again, this solution only works because of the bitvector semantics. If we were operating over the domain of integers, there would be no solutions!

If we add conflicting or contradictory constraints, such that there are no values that can be assigned to the variables such that the constraints are satisfied, the state becomes *unsatisfiable*, or unsat, and queries against it will raise an exception. You can check the satisfiability of a state with `state.satisfiable()`.

```python
>>> state.solver.add(input < 2**32)
>>> state.satisfiable()
False
```

You can also evaluate more complex expressions, not just single variables.

```python
# fresh state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

From this we can see that `eval` is a general purpose method to convert any bitvector into a Python primitive while respecting the integrity of the state. This is why we use `eval` to convert from concrete bitvectors to Python ints, too!

Also note that the x and y variables can be used in this new state despite having been created using an old state. Variables are not tied to any one state, and can exist freely.

<a id="s76--floating-point-numbers"></a>

### Floating point numbers

z3 has support for the theory of IEEE754 floating point numbers, and so angr can use them as well. The main difference is that instead of a width, a floating point number has a *sort*. You can create floating point symbols and values with `FPV` and `FPS`.

```python
# fresh state
>>> state = proj.factory.entry_state()
>>> a = claripy.FPV(3.2, claripy.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>

>>> b = claripy.FPS('b', claripy.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>

>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>

>>> b + 2 < 0
<Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>
```

So there’s a bit to unpack here - for starters the pretty-printing isn’t as smart about floating point numbers. But past that, most operations actually have a third parameter, implicitly added when you use the binary operators - the rounding mode. The IEEE754 spec supports multiple rounding modes (round-to-nearest, round-to-zero, round-to-positive, etc), so z3 has to support them. If you want to specify the rounding mode for an operation, use the fp operation explicitly (`claripy.fpAdd` for example) with a rounding mode (one of `claripy.fp.RM_*`) as the first argument.

Constraints and solving work in the same way, but with `eval` returning a floating point number:

```python
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996
```

This is nice, but sometimes we need to be able to work directly with the representation of the float as a bitvector. You can interpret bitvectors as floats and vice versa, with the methods `raw_to_bv` and `raw_to_fp`:

```python
>>> a.raw_to_bv()
<BV64 0x400999999999999a>
>>> b.raw_to_bv()
<BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>

>>> claripy.BVV(0, 64).raw_to_fp()
<FP64 FPV(0.0, DOUBLE)>
>>> claripy.BVS('x', 64).raw_to_fp()
<FP64 fpToFP(x_1_64, DOUBLE)>
```

These conversions preserve the bit-pattern, as if you casted a float pointer to an int pointer or vice versa. However, if you want to preserve the value as closely as possible, as if you casted a float to an int (or vice versa), you can use a different set of methods, `val_to_fp` and `val_to_bv`. These methods must take the size or sort of the target value as a parameter, due to the floating-point nature of floats.

```python
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> a.val_to_bv(12)
<BV12 0x3>
>>> a.val_to_bv(12).val_to_fp(claripy.fp.FSORT_FLOAT)
<FP32 FPV(3.0, FLOAT)>
```

These methods can also take a `signed` parameter, designating the signedness of the source or target bitvector.

<a id="s76--more-solving-methods"></a>

### More Solving Methods

`eval` will give you one possible solution to an expression, but what if you want several? What if you want to ensure that the solution is unique? The solver provides you with several methods for common solving patterns:

- `solver.eval(expression)` will give you one possible solution to the given expression.

- `solver.eval_one(expression)` will give you the solution to the given expression, or throw an error if more than one solution is possible.

- `solver.eval_upto(expression, n)` will give you up to n solutions to the given expression, returning fewer than n if fewer than n are possible.

- `solver.eval_atleast(expression, n)` will give you n solutions to the given expression, throwing an error if fewer than n are possible.

- `solver.eval_exact(expression, n)` will give you n solutions to the given expression, throwing an error if fewer or more than are possible.

- `solver.min(expression)` will give you the minimum possible solution to the given expression.

- `solver.max(expression)` will give you the maximum possible solution to the given expression.

Additionally, all of these methods can take the following keyword arguments:

- `extra_constraints` can be passed as a tuple of constraints. These constraints will be taken into account for this evaluation, but will not be added to the state.

- `cast_to` can be passed a data type to cast the result to. Currently, this can only be `int` and `bytes`, which will cause the method to return the corresponding representation of the underlying data. For example, `state.solver.eval(claripy.BVV(0x41424344, 32), cast_to=bytes)` will return `b'ABCD'`.

<a id="s76--summary"></a>

### Summary

That was a lot!! After reading this, you should be able to create and manipulate bitvectors, booleans, and floating point values to form trees of operations, and then query the constraint solver attached to a state for possible solutions under a set of constraints. Hopefully by this point you understand the power of using ASTs to represent computations, and the power of a constraint solver.

[In the appendix](#s69), you can find a reference for all the additional operations you can apply to ASTs, in case you ever need a quick table to look at.


---

<a id="s77"></a>

<a id="s77--machine-state-memory-registers-and-so-on"></a>

## [S77] Machine State - memory, registers, and so on

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


So far, we’ve only used angr’s simulated program states (`SimState` objects) in the barest possible way in order to demonstrate basic concepts about angr’s operation. Here, you’ll learn about the structure of a state object and how to interact with it in a variety of useful ways.

<a id="s77--review-reading-and-writing-memory-and-registers"></a>

### Review: Reading and writing memory and registers

If you’ve been reading this book in order (and you should be, at least for this first section), you already saw the basics of how to access memory and registers. `state.regs` provides read and write access to the registers through attributes with the names of each register, and `state.mem` provides typed read and write access to memory with index-access notation to specify the address followed by an attribute access to specify the type you would like to interpret the memory as.

Additionally, you should now know how to work with ASTs, so you can now understand that any bitvector-typed AST can be stored in registers or memory.

Here are some quick examples for copying and performing operations on data from the state:

```python
>>> import angr, claripy
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

# copy rsp to rbp
>>> state.regs.rbp = state.regs.rsp

# store rdx to memory at 0x1000
>>> state.mem[0x1000].uint64_t = state.regs.rdx

# dereference rbp
>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved
```

<a id="s77--basic-execution"></a>

### Basic Execution

Earlier, we showed how to use a Simulation Manager to do some basic execution. We’ll show off the full capabilities of the simulation manager in the next chapter, but for now we can use a much simpler interface to demonstrate how symbolic execution works: `state.step()`. This method will perform one step of symbolic execution and return an object called [`angr.engines.successors.SimSuccessors`](https://docs.angr.io/en/latest/api/angr.engines.successors.html#angr.engines.successors.SimSuccessors). Unlike normal emulation, symbolic execution can produce several successor states that can be classified in a number of ways. For now, what we care about is the `.successors` property of this object, which is a list containing all the “normal” successors of a given step.

Why a list, instead of just a single successor state? Well, angr’s process of symbolic execution is just the taking the operations of the individual instructions compiled into the program and performing them to mutate a SimState. When a line of code like `if (x > 4)` is reached, what happens if x is a symbolic bitvector? Somewhere in the depths of angr, the comparison `x > 4` is going to get performed, and the result is going to be `<Bool x_32_1 > 4>`.

That’s fine, but the next question is, do we take the “true” branch or the “false” one? The answer is, we take both! We generate two entirely separate successor states - one simulating the case where the condition was true and simulating the case where the condition was false. In the first state, we add `x > 4` as a constraint, and in the second state, we add `!(x > 4)` as a constraint. That way, whenever we perform a constraint solve using either of these successor states, *the conditions on the state ensure that any solutions we get are valid inputs that will cause execution to follow the same path that the given state has followed.*

To demonstrate this, let’s use a fake firmware image \<../examples/fauxware/fauxware\> as an example. If you look at the source code \<../examples/fauxware/fauxware.c\> for this binary, you’ll see that the authentication mechanism for the firmware is backdoored; any username can be authenticated as an administrator with the password “SOSNEAKY”. Furthermore, the first comparison against user input that happens is the comparison against the backdoor, so if we step until we get more than one successor state, one of those states will contain conditions constraining the user input to be the backdoor password. The following snippet implements this:

```python
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> state = proj.factory.entry_state(stdin=angr.SimFile)  # ignore that argument for now - we're disabling a more complicated default setup for the sake of education
>>> while True:
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]

>>> state1, state2 = succ.successors
>>> state1
<SimState @ 0x400629>
>>> state2
<SimState @ 0x400699
```

Don’t look at the constraints on these states directly - the branch we just went through involves the result of `strcmp`, which is a tricky function to emulate symbolically, and the resulting constraints are *very* complicated.

The program we emulated took data from standard input, which angr treats as an infinite stream of symbolic data by default. To perform a constraint solve and get a possible value that input could have taken in order to satisfy the constraints, we’ll need to get a reference to the actual contents of stdin. We’ll go over how our file and input subsystems work later on this very page, but for now, just use `state.posix.stdin.load(0, state.posix.stdin.size)` to retrieve a bitvector representing all the content read from stdin so far.

```python
>>> input_data = state1.posix.stdin.load(0, state1.posix.stdin.size)

>>> state1.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'

>>> state2.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'
```

As you can see, in order to go down the `state1` path, you must have given as a password the backdoor string “SOSNEAKY”. In order to go down the `state2` path, you must have given something *besides* “SOSNEAKY”. z3 has helpfully provided one of the billions of strings fitting this criteria.

Fauxware was the first program angr’s symbolic execution ever successfully worked on, back in 2013. By finding its backdoor using angr you are participating in a grand tradition of having a bare-bones understanding of how to use symbolic execution to extract meaning from binaries!

<a id="s77--state-presets"></a>

### State Presets

So far, whenever we’ve been working with a state, we’ve created it with `project.factory.entry_state()`. This is just one of several *state constructors* available on the project factory:

- `.blank_state()` constructs a “blank slate” blank state, with most of its data left uninitialized. When accessing uninitialized data, an unconstrained symbolic value will be returned.

- `.entry_state()` constructs a state ready to execute at the main binary’s entry point.

- `.full_init_state()` constructs a state that is ready to execute through any initializers that need to be run before the main binary’s entry point, for example, shared library constructors or preinitializers. When it is finished with these it will jump to the entry point.

- `.call_state()` constructs a state ready to execute a given function.

You can customize the state through several arguments to these constructors:

- All of these constructors can take an `addr` argument to specify the exact address to start.

- If you’re executing in an environment that can take command line arguments or an environment, you can pass a list of arguments through `args` and a dictionary of environment variables through `env` into `entry_state` and `full_init_state`. The values in these structures can be strings or bitvectors, and will be serialized into the state as the arguments and environment to the simulated execution. The default `args` is an empty list, so if the program you’re analyzing expects to find at least an `argv[0]`, you should always provide that!

- If you’d like to have `argc` be symbolic, you can pass a symbolic bitvector as `argc` to the `entry_state` and `full_init_state` constructors. Be careful, though: if you do this, you should also add a constraint to the resulting state that your value for argc cannot be larger than the number of args you passed into `args`.

- To use the call state, you should call it with `.call_state(addr, arg1, arg2, ...)`, where `addr` is the address of the function you want to call and `argN` is the Nth argument to that function, either as a Python integer, string, or array, or a bitvector. If you want to have memory allocated and actually pass in a pointer to an object, you should wrap it in an PointerWrapper, i.e. `angr.PointerWrapper("point to me!")`. The results of this API can be a little unpredictable, but we’re working on it.

- To specify the calling convention used for a function with `call_state`, you can pass a [`SimCC`](https://docs.angr.io/en/latest/api/angr.calling_conventions.html#angr.calling_conventions.SimCC) instance as the `cc` argument. We try to pick a sane default, but for special cases you will need to help angr out.

There are several more options that can be used in any of these constructors! See the docs on the `project.factory` object (an [`angr.factory.AngrObjectFactory`](https://docs.angr.io/en/latest/api/angr.factory.html#angr.factory.AngrObjectFactory)) for more details.

<a id="s77--low-level-interface-for-memory"></a>

### Low level interface for memory

The `state.mem` interface is convenient for loading typed data from memory, but when you want to do raw loads and stores to and from ranges of memory, it’s very cumbersome. It turns out that `state.mem` is actually just a bunch of logic to correctly access the underlying memory storage, which is just a flat address space filled with bitvector data: `state.memory`. You can use `state.memory` directly with the `.load(addr, size)` and `.store(addr, val)` methods:

```python
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, claripy.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>
```

As you can see, the data is loaded and stored in a “big-endian” fashion, since the primary purpose of `state.memory` is to load an store swaths of data with no attached semantics. However, if you want to perform a byteswap on the loaded or stored data, you can pass a keyword argument `endness` - if you specify little-endian, byteswap will happen. The endness should be one of the members of the `Endness` enum in the `archinfo` package used to hold declarative data about CPU architectures for angr. Additionally, the endness of the program being analyzed can be found as `arch.memory_endness` - for instance `state.arch.memory_endness`.

```python
>>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67452301>
```

There is also a low-level interface for register access, `state.registers`, that uses the exact same API as `state.memory`, but explaining its behavior involves a [dive](#s53--intermediate-representation) into the abstractions that angr uses to seamlessly work with multiple architectures. The short version is that it is simply a register file, with the mapping between registers and offsets defined in [archinfo](https://github.com/angr/archinfo).

<a id="s77--state-options"></a>

### State Options

There are a lot of little tweaks that can be made to the internals of angr that will optimize behavior in some situations and be a detriment in others. These tweaks are controlled through state options.

On each SimState object, there is a set (`state.options`) of all its enabled options. Each option (really just a string) controls the behavior of angr’s execution engine in some minute way. A listing of the full domain of options, along with the defaults for different state types, can be found in [the appendix](#s70--list-of-state-options). You can access an individual option for adding to a state through `angr.options`. The individual options are named with CAPITAL_LETTERS, but there are also common groupings of objects that you might want to use bundled together, named with lowercase_letters.

When creating a SimState through any constructor, you may pass the keyword arguments `add_options` and `remove_options`, which should be sets of options that modify the initial options set from the default.

```python
# Example: enable lazy solves, an option that causes state satisfiability to be checked as infrequently as possible.
# This change to the settings will be propagated to all successor states created from this state after this line.
>>> s.options.add(angr.options.LAZY_SOLVES)

# Create a new state with lazy solves enabled
>>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})

# Create a new state without simplification options enabled
>>> s = proj.factory.entry_state(remove_options=angr.options.simplification)
```

<a id="s77--state-plugins"></a>

### State Plugins

With the exception of the set of options just discussed, everything stored in a SimState is actually stored in a *plugin* attached to the state. Almost every property on the state we’ve discussed so far is a plugin - `memory`, `registers`, `mem`, `regs`, `solver`, etc. This design allows for code modularity as well as the ability to easily [implement new kinds of data storage](#s84--state-plugins) for other aspects of an emulated state, or the ability to provide alternate implementations of plugins.

For example, the normal `memory` plugin simulates a flat memory space, but analyses can choose to enable the “abstract memory” plugin, which uses alternate data types for addresses to simulate free-floating memory mappings independent of address, to provide `state.memory`. Conversely, plugins can reduce code complexity: `state.memory` and `state.registers` are actually two different instances of the same plugin, since the registers are emulated with an address space as well.

<a id="s77--the-globals-plugin"></a>

#### The globals plugin

`state.globals` is an extremely simple plugin: it implements the interface of a standard Python dict, allowing you to store arbitrary data on a state.

<a id="s77--the-history-plugin"></a>

#### The history plugin

`state.history` is a very important plugin storing historical data about the path a state has taken during execution. It is actually a linked list of several history nodes, each one representing a single round of execution—you can traverse this list with `state.history.parent.parent` etc.

To make it more convenient to work with this structure, the history also provides several efficient iterators over the history of certain values. In general, these values are stored as `history.recent_NAME` and the iterator over them is just `history.NAME`. For example, `for addr in state.history.bbl_addrs: print hex(addr)` will print out a basic block address trace for the binary, while `state.history.recent_bbl_addrs` is the list of basic blocks executed in the most recent step, `state.history.parent.recent_bbl_addrs` is the list of basic blocks executed in the previous step, etc. If you ever need to quickly obtain a flat list of these values, you can access `.hardcopy`, e.g. `state.history.bbl_addrs.hardcopy`. Keep in mind though, index-based accessing is implemented on the iterators.

Here is a brief listing of some of the values stored in the history:

- `history.descriptions` is a listing of string descriptions of each of the rounds of execution performed on the state.

- `history.bbl_addrs` is a listing of the basic block addresses executed by the state. There may be more than one per round of execution, and not all addresses may correspond to binary code - some may be addresses at which SimProcedures are hooked.

- `history.jumpkinds` is a listing of the disposition of each of the control flow transitions in the state’s history, as VEX enum strings.

- `history.jump_guards` is a listing of the conditions guarding each of the branches that the state has encountered.

- `history.events` is a semantic listing of “interesting events” which happened during execution, such as the presence of a symbolic jump condition, the program popping up a message box, or execution terminating with an exit code.

- `history.actions` is usually empty, but if you add the `angr.options.refs` options to the state, it will be populated with a log of all the memory, register, and temporary value accesses performed by the program.

<a id="s77--the-callstack-plugin"></a>

#### The callstack plugin

angr will track the call stack for the emulated program. On every call instruction, a frame will be added to the top of the tracked callstack, and whenever the stack pointer drops below the point where the topmost frame was called, a frame is popped. This allows angr to robustly store data local to the current emulated function.

Similar to the history, the callstack is also a linked list of nodes, but there are no provided iterators over the contents of the nodes - instead you can directly iterate over `state.callstack` to get the callstack frames for each of the active frames, in order from most recent to oldest. If you just want the topmost frame, this is `state.callstack`.

- `callstack.func_addr` is the address of the function currently being executed

- `callstack.call_site_addr` is the address of the basic block which called the current function

- `callstack.stack_ptr` is the value of the stack pointer from the beginning of the current function

- `callstack.ret_addr` is the location that the current function will return to if it returns

<a id="s77--more-about-i-o-files-file-systems-and-network-sockets"></a>

### More about I/O: Files, file systems, and network sockets

Please refer to [Working with File System, Sockets, and Pipes](#s51--working-with-file-system-sockets-and-pipes) for a more complete and detailed documentation of how I/O is modeled in angr.

<a id="s77--copying-and-merging"></a>

### Copying and Merging

A state supports very fast copies, so that you can explore different possibilities:

```python
>>> proj = angr.Project('/bin/true')
>>> s = proj.factory.blank_state()
>>> s1 = s.copy()
>>> s2 = s.copy()

>>> s1.mem[0x1000].uint32_t = 0x41414141
>>> s2.mem[0x1000].uint32_t = 0x42424242
```

States can also be merged together.

```python
# merge will return a tuple. the first element is the merged state
# the second element is a symbolic variable describing a state flag
# the third element is a boolean describing whether any merging was done
>>> (s_merged, m, anything_merged) = s1.merge(s2)

# this is now an expression that can resolve to "AAAA" *or* "BBBB"
>>> aaaa_or_bbbb = s_merged.mem[0x1000].uint32_t
```

<a id="s77--id1"></a>

Todo

describe limitations of merging


---

<a id="s78"></a>

<a id="s78--symbolic-execution"></a>

## [S78] Symbolic Execution

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


Symbolic execution is a program analysis technique used to explore multiple execution paths of a program simultaneously. Unlike normal execution, which runs the program with specific inputs, symbolic execution treats inputs as symbolic variables rather than concrete values. This means the execution can represent a wide range of inputs with symbolic expressions. Symbolic execution allows, at a time in emulation, to determine for a branch all conditions necessary to take a branch or not. Every variable is represented as a symbolic value, and each branch as a constraint. Thus, symbolic execution allows us to see which conditions allow the program to go from point A to point B by resolving these constraints. The execution paths are then analyzed by solving constraints generated by these symbolic expressions, allowing the discovery of bugs and vulnerabilities that might be missed in standard testing.

<a id="s78--example"></a>

### Example:

Consider the following simple program :

```c
const char* check_value(int x) {
    if (x > 10) {
        return "Greater";
    } else {
        return "Lesser or Equal";
    }
}
```

In normal execution, if `x` is set to 5, the program will follow the path where `x <= 10` and return “Lesser or Equal”. In symbolic execution, `x` is treated as a symbolic variable, `X`. The execution engine explores both paths:

> - Path 1: `X > 10` leading to the result “Greater”
>
> - Path 2: `X <= 10` leading to the result “Lesser or Equal”

Constraints for both paths are generated and solved to understand all possible behaviors of the program.

In software verification, it helps ensure that the code behaves as expected across all possible inputs and states. For security analysis, symbolic execution can uncover vulnerabilities such as input validation errors, which could be exploited by attackers. Additionally, in automated testing, it aids in generating comprehensive test cases that cover edge cases and rare execution paths, enhancing the robustness and security of software systems. Overall, symbolic execution provides a powerful means to rigorously analyze and improve software and firmware reliability.

<a id="s78--basic-execution"></a>

### Basic Execution

Now let’s see an example use case of symbolic execution with angr. Consider the following example code,

```c
void helloWorld() {
    printf("Hello, World!\n");
}


void firstCall(uint32_t num) {
    if (num > 50 && num <100)
        HelloWorld();
}
```

The `firstCall` function will accept a 32-bit number as an input and will call `helloWorld` function if the number is between 50 and 100.

You can perform a symbolic execution to find a correct and valid input to reach the final `helloWorld` function call with angr using the following sample code.

```python
import angr, claripy
# Load the binary
project = angr.Project('./3func', auto_load_libs=False)

# Define the address of the firstCall function
firstCall_addr = project.loader.main_object.get_symbol("firstCall")

# Define the address of the helloWorld function
helloWorld_addr = project.loader.main_object.get_symbol("helloWorld")
# Create a symbolic variable for the firstCall arg
input_arg = claripy.BVS('input_arg', 32)

# Create a blank state at the address of the firstCall function
init_state = project.factory.blank_state(addr=firstCall_addr.rebased_addr)

# Assuming the calling convention passes the argument in a register
# (e.g., x86 uses edi for the argument)
init_state.regs.edi = input_arg

# Create a simulation manager
simgr = project.factory.simulation_manager(init_state)

# Explore the binary, looking for the address of helloWorld
simgr.explore(find=helloWorld_addr.rebased_addr)

# Check if we found a state that reached the target
if simgr.found:
    input_value = simgr.found[0].solver.eval(input_arg)
    print(f"Value of input_arg that reaches HelloWorld: {input_value}")
    # Get the constraints for reaching the helloWorld function
    constraints = simgr.found[0].solver.constraints
    # Create a solver with the constraints
    solver = claripy.Solver()
    solver.add(constraints)
    min_val = solver.min(input_arg)
    max_val = solver.max(input_arg)
    print(f"Function arg: min = {min_val}, max = {max_val}")
else:
    print("Did not find a state that reaches HelloWorld.")
```

It will produce the output like the below with a valid example function arg that can reach the function `helloWorld` that you can use as a test case.

```shell
Value of input_arg that reaches HelloWorld: 71
Function arg: min = 51, max = 99
```


---

<a id="s79"></a>

<a id="s79--core-concepts"></a>

## [S79] Core Concepts

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


To get started with angr, you’ll need to have a basic overview of some fundamental angr concepts and how to construct some basic angr objects. We’ll go over this by examining what’s directly available to you after you’ve loaded a binary!

Your first action with angr will always be to load a binary into a *project*. We’ll use `/bin/true` for these examples.

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
```

A project is your control base in angr. With it, you will be able to dispatch analyses and simulations on the executable you just loaded. Almost every single object you work with in angr will depend on the existence of a project in some form.

Tip

Using and exploring angr in IPython (or other Python command line interpreters) is a main use case that we design angr for. When you are not sure what interfaces are available, tab completion is your friend!

Sometimes tab completion in IPython can be slow. We find the following workaround helpful without degrading the validity of completion results:

```python
# Drop this file in IPython profile's startup directory to avoid running it every time.
import IPython
py = IPython.get_ipython()
py.Completer.use_jedi = False
```

<a id="s79--basic-properties"></a>

### Basic properties

First, we have some basic properties about the project: its CPU architecture, its filename, and the address of its entry point.

```python
>>> import monkeyhex # this will format numerical results in hexadecimal
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'
```

- *arch* is an instance of an `archinfo.Arch` object for whichever architecture the program is compiled, in this case little-endian amd64. It contains a ton of clerical data about the CPU it runs on, which you can peruse [at your leisure](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py). The common ones you care about are `arch.bits`, `arch.bytes` (that one is a `@property` declaration on the [main Arch class](https://github.com/angr/archinfo/blob/master/archinfo/arch.py)), `arch.name`, and `arch.memory_endness`.

- *entry* is the entry point of the binary!

- *filename* is the absolute filename of the binary. Riveting stuff!

<a id="s79--loading"></a>

### Loading

Getting from a binary file to its representation in a virtual address space is pretty complicated! We have a module called CLE to handle that. CLE’s result, called the loader, is available in the `.loader` property. We’ll get into detail on how to use this [soon](#s73--loading-a-binary), but for now just know that you can use it to see the shared libraries that angr loaded alongside your program and perform basic queries about the loaded address space.

```python
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>

>>> proj.loader.shared_objects # may look a little different for you!
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000

>>> proj.loader.main_object  # we've loaded several binaries into this project. Here's the main one!
<ELF Object true, maps [0x400000:0x60721f]>

>>> proj.loader.main_object.execstack  # sample query: does this binary have an executable stack?
False
>>> proj.loader.main_object.pic  # sample query: is this binary position-independent?
True
```

<a id="s79--the-factory"></a>

### The factory

There are a lot of classes in angr, and most of them require a project to be instantiated. Instead of making you pass around the project everywhere, we provide `project.factory`, which has several convenient constructors for common objects you’ll want to use frequently.

This section will also serve as an introduction to several basic angr concepts. Strap in!

<a id="s79--blocks"></a>

#### Blocks

First, we have `project.factory.block()`, which is used to extract a [basic block](https://en.wikipedia.org/wiki/Basic_block) of code from a given address. This is an important fact - *angr analyzes code in units of basic blocks.* You will get back a Block object, which can tell you lots of fun things about the block of code:

```python
>>> block = proj.factory.block(proj.entry) # lift a block of code from the program's entry point
<Block for 0x401670, 42 bytes>

>>> block.pp()                          # pretty-print a disassembly to stdout
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]

>>> block.instructions                  # how many instructions are there?
0xb
>>> block.instruction_addrs             # what are the addresses of the instructions?
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```

Additionally, you can use a Block object to get other representations of the block of code:

```python
>>> block.capstone                       # capstone disassembly
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB (that's a Python internal address, not a program address)
<pyvex.block.IRSB at 0x7706330>
```

<a id="s79--states"></a>

#### States

Here’s another fact about angr - the `Project` object only represents an “initialization image” for the program. When you’re performing execution with angr, you are working with a specific object representing a *simulated program state* - a `SimState`. Let’s grab one right now!

```python
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```

A SimState contains a program’s memory, registers, filesystem data… any “live data” that can be changed by execution has a home in the state. We’ll cover how to interact with states in depth later, but for now, let’s use `state.regs` and `state.mem` to access the registers and memory of this state:

```python
>>> state.regs.rip        # get the current instruction pointer
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved  # interpret the memory at the entry point as a C int
<BV32 0x8949ed31>
```

Those aren’t Python ints! Those are *bitvectors*. Python integers don’t have the same semantics as words on a CPU, e.g. wrapping on overflow, so we work with bitvectors, which you can think of as an integer as represented by a series of bits, to represent CPU data in angr. Note that each bitvector has a `.length` property describing how wide it is in bits.

We’ll learn all about how to work with them soon, but for now, here’s how to convert from Python ints to bitvectors and back again:

```python
>>> bv = claripy.BVV(0x1234, 32)       # create a 32-bit-wide bitvector with value 0x1234
<BV32 0x1234>                               # BVV stands for bitvector value
>>> state.solver.eval(bv)                # convert to Python int
0x1234
```

You can store these bitvectors back to registers and memory, or you can directly store a Python integer and it’ll be converted to a bitvector of the appropriate size:

```python
>>> state.regs.rsi = claripy.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

The `mem` interface is a little confusing at first, since it’s using some pretty hefty Python magic. The short version of how to use it is:

- Use array\[index\] notation to specify an address

- Use `.<type>` to specify that the memory should be interpreted as `type` (common values: char, short, int, long, size_t, uint8_t, uint16_t…)

- From there, you can either:

  - Store a value to it, either a bitvector or a Python int

  - Use `.resolved` to get the value as a bitvector

  - Use `.concrete` to get the value as a Python int

There are more advanced usages that will be covered later!

Finally, if you try reading some more registers you may encounter a very strange looking value:

```python
>>> state.regs.rdi
<BV64 reg_48_11_64{UNINITIALIZED}>
```

This is still a 64-bit bitvector, but it doesn’t contain a numerical value. Instead, it has a name! This is called a *symbolic variable* and it is the underpinning of symbolic execution. Don’t panic! We will discuss all of this in detail exactly two chapters from now.

<a id="s79--simulation-managers"></a>

#### Simulation Managers

If a state lets us represent a program at a given point in time, there must be a way to get it to the *next* point in time. A simulation manager is the primary interface in angr for performing execution, simulation, whatever you want to call it, with states. As a brief introduction, let’s show how to tick that state we created earlier forward a few basic blocks.

First, we create the simulation manager we’re going to be using. The constructor can take a state or a list of states.

```python
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]
```

A simulation manager can contain several *stashes* of states. The default stash, `active`, is initialized with the state we passed in. We could look at `simgr.active[0]` to look at our state some more, if we haven’t had enough!

Now… get ready, we’re going to do some execution.

```python
>>> simgr.step()
```

We’ve just performed a basic block’s worth of symbolic execution! We can look at the active stash again, noticing that it’s been updated, and furthermore, that it has **not** modified our original state. SimState objects are treated as immutable by execution - you can safely use a single state as a “base” for multiple rounds of execution.

```python
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip                 # new and exciting!
<BV64 0x1020300>
>>> state.regs.rip                           # still the same!
<BV64 0x401670>
```

`/bin/true` isn’t a very good example for describing how to do interesting things with symbolic execution, so we’ll stop here for now.

<a id="s79--analyses"></a>

### Analyses

angr comes pre-packaged with several built-in analyses that you can use to extract some fun kinds of information from a program. Here they are:

```text
>>> proj.analyses.            # Press TAB here in ipython to get an autocomplete-listing of everything:
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG
 proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG
 proj.analyses.CFGFast              proj.analyses.Reassembler
```

A couple of these are documented later in this book, but in general, if you want to find how to use a given analysis, you should look in the api documentation for [`angr.analyses`](https://docs.angr.io/en/latest/api/angr.analyses.html#module-angr.analyses). As an extremely brief example: here’s how you construct and use a quick control-flow graph:

```python
# Originally, when we loaded this binary it also loaded all its dependencies into the same virtual address  space
# This is undesirable for most analysis.
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graph is a networkx DiGraph full of CFGNode instances
# You should go look up the networkx APIs to learn how to use this!
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# To get the CFGNode for a given address, use cfg.model.get_any_node
>>> entry_node = cfg.model.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```

<a id="s79--now-what"></a>

### Now what?

Having read this page, you should now be acquainted with several important angr concepts: basic blocks, states, bitvectors, simulation managers, and analyses. You can’t really do anything interesting besides just use angr as a glorified debugger, though! Keep reading, and you will unlock deeper powers…


---

<a id="s80"></a>

<a id="s80--angr-examples"></a>

## [S80] angr examples

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


To help you get started with [angr](https://github.com/angr/angr), we’ve created several examples. We’ve tried to organize them into major categories, and briefly summarize that each example will expose you to. Enjoy!

If you want a high-level cheatsheet of the “techniques” used in the examples, see [the angr strategies cheatsheet](https://github.com/bordig-f/angr-strategies/blob/master/angr_strategies.md) by [Florent Bordignon](https://github.com/bordig-f).

To jump to a specific category:

- [Introduction](#s80--introduction) - examples showing off the very basics of angr’s functionality

- [Reversing](#s80--reversing) - examples showing angr being used in reverse engineering tasks

- [Vulnerability Discovery](#s80--vulnerability-discovery) - examples of angr being used to search for vulnerabilities

- [Exploitation](#s80--exploitation) - examples of angr being used as an exploitation assistance tool

<a id="s80--introduction"></a>

### Introduction

These are some introductory examples to give an idea of how to use angr’s API.

<a id="s80--fauxware"></a>

#### Fauxware

This is a basic script that explains how to use angr to symbolically execute a program and produce concrete input satisfying certain conditions.

Binary, source, and script are found [here.](https://github.com/angr/angr-examples/tree/master/examples/fauxware)

<a id="s80--reversing"></a>

### Reversing

These are examples that use angr to solve reverse engineering challenges. There are a lot of these. We’ve chosen the most unique ones, and relegated the rest to the CTF Challenges section below.

<a id="s80--beginner-reversing-example-little-engine"></a>

#### Beginner reversing example: little_engine

```text
Script author: Michael Reeves (github: @mastermjr)
Script runtime: 3 min 26 seconds (206 seconds)
Concepts presented:
stdin constraining, concrete optimization with Unicorn
```

This challenge is similar to the csaw challenge below, however the reversing is much more simple. The original code, solution, and writeup for the challenge can be found at the b01lers github [here](https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_little_engine).

The angr solution script is [here](https://github.com/angr/angr-examples/tree/master/examples/b01lersctf2020_little_engine/solve.py) and the binary is [here](https://github.com/angr/angr-examples/tree/master/examples/b01lersctf2020_little_engine/engine).

<a id="s80--whitehat-ctf-2015-crypto-400"></a>

#### Whitehat CTF 2015 - Crypto 400

```text
Script author: Yan Shoshitaishvili (github: @Zardus)
Script runtime: 30 seconds
Concepts presented: statically linked binary (manually hooking with function summaries), commandline argument, partial solutions
```

We solved this crackme with angr’s help. The resulting script will help you understand how angr can be used for crackme *assistance*, not a full-out solve. Since angr cannot solve the actual crypto part of the challenge, we use it just to reduce the keyspace, and brute-force the rest.

You can find this script [here](https://github.com/angr/angr-examples/tree/master/examples/whitehat_crypto400/solve.py) and the binary [here](https://github.com/angr/angr-examples/tree/master/examples/whitehat_crypto400/whitehat_crypto400).

<a id="s80--csaw-ctf-2015-quals-reversing-500-wyvern"></a>

#### CSAW CTF 2015 Quals - Reversing 500, “wyvern”

```text
Script author: Audrey Dutcher (github: @rhelmot)
Script runtime: 15 mins
Concepts presented: stdin constraining, concrete optimization with Unicorn
```

angr can outright solve this challenge with very little assistance from the user. The script to do so is here \<https://github.com/angr/angr-examples/tree/master/examples/csaw_wyvern/solve.py\>\_ and the binary is [here](https://github.com/angr/angr-examples/tree/master/examples/csaw_wyvern/wyvern).

<a id="s80--tumctf-2016-zwiebel"></a>

#### TUMCTF 2016 - zwiebel

```text
Script author: Fish
Script runtime: 2 hours 31 minutes with pypy and Unicorn - expect much longer with CPython only
Concepts presented: self-modifying code support, concrete optimization with Unicorn
```

This example is of a self-unpacking reversing challenge. This example shows how to enable Unicorn support and self-modification support in angr. Unicorn support is essential to solve this challenge within a reasonable amount of time - simulating the unpacking code symbolically is *very* slow. Thus, we execute it concretely in unicorn/qemu and only switch into symbolic execution when needed.

You may refer to other writeup about the internals of this binary. I didn’t reverse too much since I was pretty confident that angr is able to solve it :-)

The long-term goal of optimizing angr is to execute this script within 10 minutes. Pretty ambitious :P

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/tumctf2016_zwiebel/zwiebel) and the [script](https://github.com/angr/angr-examples/tree/master/examples/tumctf2016_zwiebel/solve.py).

<a id="s80--flareon-2015-challenge-5"></a>

#### FlareOn 2015 - Challenge 5

```text
Script author: Adrian Tang (github: @tangabc)
Script runtime: 2 mins 10 secs
Concepts presented: Windows support
```

This is another [reversing challenge](https://github.com/angr/angr-examples/tree/master/examples/flareon2015_5/sender) from the FlareOn challenges.

“The challenge is designed to teach you about PCAP file parsing and traffic decryption by reverse engineering an executable used to generate it. This is a typical scenario in our malware analysis practice where we need to figure out precisely what the malware was doing on the network”

For this challenge, the author used angr to represent the desired encoded output as a series of constraints for the SAT solver to solve for the input.

For a detailed write-up please visit the author’s post [here](http://0x0atang.github.io/reversing/2015/09/18/flareon5-concolic.html) and you can also find the solution from the FireEye [here](https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/flareon/2015solution5.pdf)

<a id="s80--ctf-quals-2016-trace"></a>

#### 0ctf quals 2016 - trace

```text
Script author: WGH (wgh@bushwhackers.ru)
Script runtime: 1 min 50 secs (CPython 2.7.10), 1 min 12 secs (PyPy 4.0.1)
Concepts presented: guided symbolic tracing
```

In this challenge we’re given a text file with trace of a program execution. The file has two columns, address and instruction executed. So we know all the instructions being executed, and which branches were taken. But the initial data is not known.

Reversing reveals that a buffer on the stack is initialized with known constant string first, then an unknown string is appended to it (the flag), and finally it’s sorted with some variant of quicksort. And we need to find the flag somehow.

angr easily solves this problem. We only have to direct it to the right direction at every branch, and the solver finds the flag at a glance.

Files are [here](https://github.com/angr/angr-examples/tree/master/examples/0ctf_trace).

<a id="s80--asis-ctf-finals-2015-license"></a>

#### ASIS CTF Finals 2015 - license

```text
Script author: Fish Wang (github: @ltfish)
Script runtime: 3.6 sec
Concepts presented: using the filesystem, manual symbolic summary execution
```

This is a crackme challenge that reads a license file. Rather than hooking the read operations of the flag file, we actually pass in a filesystem with the correct file created.

Here is the [binary](https://github.com/angr/angr-examples/tree/master/examples/asisctffinals2015_license/license) and the [script](https://github.com/angr/angr-examples/tree/master/examples/asisctffinals2015_license/solve.py).

<a id="s80--defcon-quals-2017-crackme2000"></a>

#### DEFCON Quals 2017 - Crackme2000

```text
Script author: Shellphish
Script runtime: varies, but on the order of seconds
Concepts presented: automated reverse engineering
```

DEFCON Quals had a whole category for automatic reversing in 2017. Our scripts are [here](https:////github.com/angr/angr-examples/tree/master/examples/defcon2017quals_crackme2000).

<a id="s80--vulnerability-discovery"></a>

### Vulnerability Discovery

These are examples of angr being used to identify vulnerabilities in binaries.

<a id="s80--beginner-vulnerability-discovery-example-strcpy-find"></a>

#### Beginner vulnerability discovery example: strcpy_find

```text
Script author: Kyle Ossinger (github: @k0ss)
Concepts presented: exploration to vulnerability, programmatic find condition
```

This is the first in a series of “tutorial scripts” I’ll be making which use angr to find exploitable conditions in binaries. The first example is a very simple program. The script finds a path from the main entry point to `strcpy`, but **only** when we control the source buffer of the `strcpy` operation. To hit the right path, angr has to solve for a password argument, but angr solved this in less than 2 seconds on my machine using the standard Python interpreter. The script might look large, but that’s only because I’ve heavily commented it to be more helpful to beginners. The challenge binary is [here](https://github.com/angr/angr-examples/tree/master/examples/strcpy_find/strcpy_test) and the script is [here](https://github.com/angr/angr-examples/tree/master/examples/strcpy_find/solve.py).

<a id="s80--cgc-crash-identification"></a>

#### CGC crash identification

```text
Script author: Antonio Bianchi, Jacopo Corbetta
Concepts presented: exploration to vulnerability
```

This is a very easy binary containing a stack buffer overflow and an easter egg. CADET_00001 is one of the challenge released by DARPA for the Cyber Grand Challenge: [link](https://github.com/CyberGrandChallenge/samples/tree/master/examples/CADET_00001) The binary can run in the DECREE VM: [link](http://repo.cybergrandchallenge.com/boxes/) A copy of the original challenge and the angr solution is provided [here](https://github.com/angr/angr-examples/tree/master/examples/CADET_00001) CADET_00001.adapted (by Jacopo Corbetta) is the same program, modified to be runnable in an Intel x86 Linux machine.

<a id="s80--grub-back-to-28-bug"></a>

#### Grub “back to 28” bug

```text
Script author: Audrey Dutcher (github: @rhelmot)
Concepts presented: unusual target (custom function hooking required), use of exploration techniques to categorize and prune the program's state space
```

This is the demonstration presented at 32c3. The script uses angr to discover the input to crash grub’s password entry prompt.

[script](https://github.com/angr/angr-examples/tree/master/examples/grub/solve.py) - [vulnerable module](https://github.com/angr/angr-examples/tree/master/examples/grub/crypto.mod)

<a id="s80--exploitation"></a>

### Exploitation

These are examples of angr’s use as an exploitation assistance engine.

<a id="s80--insomnihack-simple-aeg"></a>

#### Insomnihack Simple AEG

```text
Script author: Nick Stephens (github: @NickStephens)
Concepts presented: automatic exploit generation, global symbolic data tracking
```

Demonstration for Insomni’hack 2016. The script is a very simple implementation of AEG.

[script](https://github.com/angr/angr-examples/tree/master/examples/insomnihack_aeg/solve.py)

<a id="s80--secuinside-2016-quals-mbrainfuzz-symbolic-exploration-for-exploitability-conditions"></a>

#### SecuInside 2016 Quals - mbrainfuzz - symbolic exploration for exploitability conditions

```text
Script author: nsr (nsr@tasteless.eu)
Script runtime: ~15 seconds per binary
Concepts presented: symbolic exploration guided by static analysis, using the CFG
```

Originally, a binary was given to the ctf-player by the challenge-service, and an exploit had to be crafted automatically. Four sample binaries, obtained during the ctf, are included in the example. All binaries follow the same format; the command-line argument is validated in a bunch of functions, and when every check succeeds, a memcpy() resulting into a stack-based buffer overflow is executed. angr is used to find the way through the binary to the memcpy() and to generate valid inputs to every checking function individually.

The sample binaries and the script are located [here](https://github.com/angr/angr-examples/tree/master/examples/secuinside2016mbrainfuzz) and additional information be found at the author’s [Write-Up](https://tasteless.eu/post/2016/07/secuinside-mbrainfuzz/).

<a id="s80--seccon-2016-quals-ropsynth"></a>

#### SECCON 2016 Quals - ropsynth

```text
Script author: Yan Shoshitaishvili (github @zardus) and Nilo Redini
Script runtime: 2 minutes
Concepts presented: automatic ROP chain generation, binary modification, reasoning over constraints, reasoning over action history
```

This challenge required the automatic generation of ropchains, with the twist that every ropchain was succeeded by an input check that, if not passed, would terminate the application. We used symbolic execution to recover those checks, removed the checks from the binary, used angrop to build the ropchains, and instrumented them with the inputs to pass the checks.

The various challenge files are located [here](https://github.com/angr/angr-examples/tree/master/examples/secconquals2016_ropsynth), with the actual solve script [here](https://github.com/angr/angr-examples/tree/master/examples/secconquals2016_ropsynth/solve.py).


---

<a id="s81"></a>

<a id="s81--writing-analyses"></a>

## [S81] Writing Analyses

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


An analysis can be created by subclassing the `angr.Analysis` class. In this section, we’ll create a mock analysis to show off the various features. Let’s start with something simple:

```python
>>> import angr

>>> class MockAnalysis(angr.Analysis):
...     def __init__(self, option):
...         self.option = option

>>> angr.AnalysesHub.register_default('MockAnalysis', MockAnalysis) # register the class with angr's global analysis list
```

This is a very simple analysis – it takes an option, and stores it. Of course, it’s not useful, but this is just a demonstration.

Let’s see how to run our new analysis:

```python
>>> proj = angr.Project("/bin/true")
>>> mock = proj.analyses.MockAnalysis('this is my option')
>>> assert mock.option == 'this is my option'
```

<a id="s81--working-with-projects"></a>

### Working with projects

Via some Python magic, your analysis will automatically have the project upon which you are running it under the `self.project` property. Use this to interact with your project and analyze it!

```python
>>> class ProjectSummary(angr.Analysis):
...     def __init__(self):
...         self.result = 'This project is a %s binary with an entry point at %#x.' % (self.project.arch.name, self.project.entry)

>>> angr.AnalysesHub.register_default('ProjectSummary', ProjectSummary)
>>> proj = angr.Project("/bin/true")

>>> summary = proj.analyses.ProjectSummary()
>>> print(summary.result)
This project is a AMD64 binary with an entry point at 0x401410.
```

<a id="s81--analysis-resilience"></a>

### Analysis Resilience

Sometimes, your (or our) code might suck and analyses might throw exceptions. We understand, and we also understand that oftentimes a partial result is better than nothing. This is specifically true when, for example, running an analysis on all of the functions in a program. Even if some of the functions fails, we still want to know the results of the functions that do not.

To facilitate this, the `Analysis` base class provides a resilience context manager under `self._resilience`. Here’s an example:

```python
>>> class ComplexFunctionAnalysis(angr.Analysis):
...     def __init__(self):
...         self._cfg = self.project.analyses.CFG()
...         self.results = { }
...         for addr, func in self._cfg.function_manager.functions.items():
...             with self._resilience():
...                 if addr % 2 == 0:
...                     raise ValueError("can't handle functions at even addresses")
...                 else:
...                     self.results[addr] = "GOOD"
```

The context manager catches any exceptions thrown and logs them (as a tuple of the exception type, message, and traceback) to `self.errors`. These are also saved and loaded when the analysis is saved and loaded (although the traceback is discarded, as it is not picklable).

You can tune the effects of the resilience with two optional keyword parameters to `self._resilience()`.

The first is `name`, which affects where the error is logged. By default, errors are placed in `self.errors`, but if `name` is provided, then instead the error is logged to `self.named_errors`, which is a dict mapping `name` to a list of all the errors that were caught under that name. This allows you to easily tell where thrown without examining its traceback.

The second argument is `exception`, which should be the type of the exception that `resilience` should catch. This defaults to `Exception`, which handles (and logs) almost anything that could go wrong. You can also pass a tuple of exception types to this option, in which case all of them will be caught.

Using `resilience` has a few advantages:

1.  Your exceptions are gracefully logged and easily accessible afterwards. This is really nice for writing testcases.

2.  When creating your analysis, the user can pass `fail_fast=True`, which transparently disable the resilience, which is really nice for manual testing.

3.  It’s prettier than having `try` `except` everywhere.

Have fun with analyses! Once you master the rest of angr, you can use analyses to understand anything computable!


---

<a id="s82"></a>

<a id="s82--extending-the-environment-model"></a>

## [S82] Extending the Environment Model

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


One of the biggest issues you may encounter while using angr to analyze programs is an incomplete model of the environment, or the APIs, surrounding your program. This usually takes the form of syscalls or dynamic library calls, or in rare cases, loader artifacts. angr provides a convenient interface to do most of these things!

Everything discussed here involves writing SimProcedures, so [make sure you know how to do that!](#s83--hooks-and-simprocedures).

Note that this page should be treated as a narrative document, not a reference document, so you should read it at least once start to end.

<a id="s82--setup"></a>

### Setup

You *probably* want to have a development install of angr, i.e. set up with the script in the [angr-dev repository](https://github.com/angr/angr-dev). It is remarkably easy to add new API models by just implementing them in certain folders of the angr repository. This is also desirable because any work you do in this field will almost always be useful to other people, and this makes it extremely easy to submit a pull request.

However, if you want to do your development out-of-tree, you want to work against a production version of angr, or you want to make customized versions of already-implemented API functions, there are ways to incorporate your extensions programmatically. Both these techniques, in-tree and out-of-tree, will be documented at each step.

<a id="s82--dynamic-library-functions-import-dependencies"></a>

### Dynamic library functions - import dependencies

This is the easiest case, and the case that SimProcedures were originally designed for.

First, you need to write a SimProcedure representing the function. Then you need to let angr know about it.

<a id="s82--case-1-in-tree-development-simlibraries-and-catalogues"></a>

#### Case 1, in-tree development: SimLibraries and catalogues

angr has a magical folder in its repository, [angr/procedures](https://github.com/angr/angr/tree/master/angr/procedures). Within it are all the SimProcedure implementations that come bundled with angr as well as information about what libraries implement what functions.

Each folder in the `procedures` directory corresponds to some sort of *standard*, or a body that specifies the interface part of an API and its semantics. We call each folder a *catalog* of procedures. For example, we have `libc` which contains the functions defined by the C standard library, and a separate folder `posix` which contains the functions defined by the posix standard. There is some magic which automatically scrapes these folders in the `procedures` directory and organizes them into the `angr.SIM_PROCEDURES` dict. For example, `angr/procedures/libc/printf.py` contains both `class printf` and `class __printf_chk`, so there exists both `angr.SIM_PROCEDURES['libc']['printf']` and `angr.SIM_PROCEDURES['libc']['__printf_chk']`.

The purpose of this categorization is to enable easy sharing of procedures among different libraries. For example. libc.so.6 contains all the C standard library functions, but so does msvcrt.dll! These relationships are represented with objects called `SimLibraries` which represent an actual shared library file, its functions, and their metadata. Take a look at the API reference for [`SimLibrary`](https://docs.angr.io/en/latest/api/angr.procedures.definitions.html#angr.procedures.definitions.SimLibrary) along with [the code for setting up glibc](https://github.com/angr/angr/blob/master/angr/procedures/definitions/glibc.py) to learn how to use it.

SimLibraries are defined in a special folder in the procedures directory, `procedures/definitions`. Files in here should contain an *instance*, not a subclass, of `SimLibrary`. The same magic that scrapes up SimProcedures will also scrape up SimLibraries and put them in `angr.SIM_LIBRARIES`, keyed on each of their common names. For example, `angr/procedures/definitions/linux_loader.py` contains `lib = SimLibrary(); lib.set_library_names('ld.so', 'ld-linux.so', 'ld.so.2', 'ld-linux.so.2', 'ld-linux-x86_64.so.2')`, so you can access it via `angr.SIM_LIBRARIES['ld.so'][0]` or `angr.SIM_LIBRARIES['ld-linux.so'][0]` or any of the other names.

At load time, all the dynamic library dependencies are looked up in `SIM_LIBRARIES` and their procedures (or stubs!) are hooked into the project’s address space to summarize any functions it can. The code for this process is found [here](https://github.com/angr/angr/blob/master/angr/project.py#L244).

**SO**, the bottom line is that you can just write your own SimProcedure and SimLibrary definitions, drop them into the directory structure, and they’ll automatically be applied. If you’re adding a procedure to an existing library, you can just drop it into the appropriate catalog and it’ll be picked up by all the libraries using that catalog, since most libraries construct their list of function implementation by batch-adding entire catalogs.

<a id="s82--case-2-out-of-tree-development-tight-integration"></a>

#### Case 2, out-of-tree development, tight integration

If you’d like to implement your procedures outside the angr repository, you can do that. You effectively do this by just manually adding your procedures to the appropriate SimLibrary. Just call `angr.SIM_LIBRARIES[libname][0].add(name, proc_cls)` to do the registration.

Note that this will only work if you do this before the project is loaded with `angr.Project`. Note also that adding the procedure to `angr.SIM_PROCEDURES`, i.e. adding it directly to a catalog, will *not* work, since these catalogs are used to construct the SimLibraries only at import and are used by value, not by reference.

<a id="s82--case-3-out-of-tree-development-loose-integration"></a>

#### Case 3, out-of-tree development, loose integration

Finally, if you don’t want to mess with SimLibraries at all, you can do things purely on the project level with [`hook_symbol()`](https://docs.angr.io/en/latest/api/angr.project.html#angr.project.Project.hook_symbol).

<a id="s82--syscalls"></a>

### Syscalls

Unlike dynamic library methods, syscall procedures aren’t incorporated into the project via hooks. Instead, whenever a syscall instruction is encountered, the basic block should end with a jumpkind of `Ijk_Sys`. This will cause the next step to be handled by the SimOS associated with the project, which will extract the syscall number from the state and query a specialized SimLibrary with that.

This deserves some explanation.

There is a subclass of SimLibrary called SimSyscallLibrary which is used for collecting all the functions that are part of an operating system’s syscall interface. SimSyscallLibrary uses the same system for managing implementations and metadata as SimLibrary, but adds on top of it a system for managing syscall numbers for multiple ABIs (application binary interfaces, like an API but lower level). The best example for an implementation of a SimSyscallLibrary is the [linux syscalls](https://github.com/angr/angr/blob/master/angr/procedures/definitions/linux_kernel.py). It keeps its procedures in a normal SimProcedure catalog called `linux_kernel` and adds them to the library, then adds several syscall number mappings, including separate mappings for `mips-o32`, `mips-n32`, and `mips-n64`.

In order for syscalls to be supported in the first place, the project’s SimOS must inherit from [`SimUserland`](https://docs.angr.io/en/latest/api/angr.simos.userland.html#angr.simos.userland.SimUserland), itself a SimOS subclass. This requires the class to call SimUserland’s constructor with a super() call that includes the `syscall_library` keyword argument, specifying the specific SimSyscallLibrary that contains the appropriate procedures and mappings for the operating system. Additionally, the class’s `configure_project` must perform a super() call including the `abi_list` keyword argument, which contains the list of ABIs that are valid for the current architecture. If the ABI for the syscall can’t be determined by just the syscall number, for example, that amd64 linux programs can use either `int 0x80` or `syscall` to invoke a syscall and these two ABIs use overlapping numbers, the SimOS cal override `syscall_abi()`, which takes a SimState and returns the name of the current syscall ABI. This is determined for int80/syscall by examining the most recent jumpkind, since libVEX will produce different syscall jumpkinds for the different instructions.

Calling conventions for syscalls are a little weird right now and they ought to be refactored. The current situation requires that `angr.SYSCALL_CC` be a map of maps `{arch_name: {os_name: cc_cls}}`, where `os_name` is the value of project.simos.name, and each of the calling convention classes must include an extra method called `syscall_number` which takes a state and return the current syscall number. Look at the bottom of [calling_conventions.py](https://github.com/angr/angr/blob/master/angr/calling_conventions.py) to learn more about it. Not very object-oriented at all…

As a side note, each syscall is given a unique address in a special object in CLE called the “kernel object”. Upon a syscall, the address for the specific syscall is set into the state’s instruction pointer, so it will show up in the logs. These addresses are not hooked, they are just used to identify syscalls during analysis given only an address trace. The test for determining if an address corresponds to a syscall is `project.simos.is_syscall_addr(addr)` and the syscall corresponding to the address can be retrieved with `project.simos.syscall_from_addr(addr)`.

<a id="s82--case-1-in-tree-development"></a>

#### Case 1, in-tree development

SimSyscallLibraries are stored in the same place as the normal SimLibraries, `angr/procedures/definitions`. These libraries don’t have to specify any common name, but they can if they’d like to show up in `SIM_LIBRARIES` for easy access.

The same thing about adding procedures to existing catalogs of dynamic library functions also applies to syscalls - implementing a linux syscall is as easy as writing the SimProcedure and dropping the implementation into `angr/procedures/linux_kernel`. As long as the class name matches one of the names in the number-to-name mapping of the SimLibrary (all the linux syscall numbers are included with recent releases of angr), it will be used.

To add a new operating system entirely, you need to implement the SimOS as well, as a subclass of SimUserland. To integrate it into the tree, you should add it to the `simos` directory, but this is not a magic directory like `procedures`. Instead, you should add a line to `angr/simos/__init__.py` calling `register_simos()` with the OS name as it appears in `project.loader.main_object.os` and the SimOS class. Your class should do everything described above.

<a id="s82--id1"></a>

#### Case 2, out-of-tree development, tight integration

You can add syscalls to a SimSyscallLibrary the same way you can add functions to a normal SimLibrary, by tweaking the entries in `angr.SIM_LIBRARIES`. If you’re this for linux you want `angr.SIM_LIBRARIES['linux'][0].add(name, proc_cls)`.

You can register a SimOS with angr from out-of-tree as well - the same `register_simos` method is just sitting there waiting for you as `angr.simos.register_simos(name, simos_cls)`.

<a id="s82--id2"></a>

#### Case 3, out-of-tree development, loose integration

The SimSyscallLibrary the SimOS uses is copied from the original during setup, so it is safe to mutate. You can directly fiddle with `project.simos.syscall_library` to manipulate an individual project’s syscalls.

You can provide a SimOS class (not an instance) directly to the `Project` constructor via the `simos` keyword argument, so you can specify the SimOS for a project explicitly if you like.

<a id="s82--simdata"></a>

### SimData

What about when there is an import dependency on a data object? This is easily resolved when the given library is actually loaded into memory - the relocation can just be resolved as normal. However, when the library is not loaded (for example, `auto_load_libs=False`, or perhaps some dependency is simply missing), things get tricky. It is not possible to guess in most cases what the value should be, or even what its size should be, so if the guest program ever dereferences a pointer to such a symbol, emulation will go off the rails.

CLE will warn you when this might happen:

```text
[22:26:58] [cle.backends.externs] |  WARNING: Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: _rtld_global
[22:26:58] [cle.backends.externs] |  WARNING: Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: __libc_enable_secure
[22:26:58] [cle.backends.externs] |  WARNING: Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: _rtld_global_ro
[22:26:58] [cle.backends.externs] |  WARNING: Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: _dl_argv
```

If you see this message and suspect it is causing issues (i.e. the program is actually introspecting the value of these symbols), you can resolve it by implementing and registering a SimData class, which is like a SimProcedure but for data. Simulated data. Very cool.

A SimData can effectively specify some data that must be used to provide an unresolved import symbol. It has a number of mechanisms to make this more useful, including the ability to specify relocations and subdependencies.

Look at the SimData `cle.backends.externs.simdata.SimData` class reference and the [existing SimData subclasses](https://github.com/angr/cle/tree/master/cle/backends/externs/simdata) for guidelines on how to do this.


---

<a id="s83"></a>

<a id="s83--hooks-and-simprocedures"></a>

## [S83] Hooks and SimProcedures

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


Hooks in angr are very powerful! You can use them to modify a program’s behavior in any way you could imagine. However, the exact way you might want to program a specific hook may be non-obvious. This chapter should serve as a guide when programming SimProcedures.

<a id="s83--quick-start"></a>

### Quick Start

Here’s an example that will remove all bugs from any program:

```python
>>> from angr import Project, SimProcedure
>>> project = Project('examples/fauxware/fauxware')

>>> class BugFree(SimProcedure):
...    def run(self, argc, argv):
...        print('Program running with argc=%s and argv=%s' % (argc, argv))
...        return 0

# this assumes we have symbols for the binary
>>> project.hook_symbol('main', BugFree())

# Run a quick execution!
>>> simgr = project.factory.simulation_manager()
>>> simgr.run()  # step until no more active states
Program running with argc=<SAO <BV64 0x0>> and argv=<SAO <BV64 0x7fffffffffeffa0>>
<SimulationManager with 1 deadended>
```

Now, whenever program execution reaches the main function, instead of executing the actual main function, it will execute this procedure! It just prints out a message, and returns.

Now, let’s talk about what happens on the edge of this function! When entering the function, where do the values that go into the arguments come from? You can define your `run()` function with however many arguments you like, and the SimProcedure runtime will automatically extract from the program state those arguments for you, via a [calling convention](#s58--working-with-calling-conventions), and call your run function with them. Similarly, when you return a value from the run function, it is placed into the state (again, according to the calling convention), and the actual control-flow action of returning from a function is performed, which depending on the architecture may involve jumping to the link register or jumping to the result of a stack pop.

It should be clear at this point that the SimProcedure we just wrote is meant to totally replace whatever function it is hooked over top of. In fact, the original use case for SimProcedures was replacing library functions. More on that later.

<a id="s83--implementation-context"></a>

### Implementation Context

On a `Project` class, the dict `project._sim_procedures` is a mapping from address to `SimProcedure` instances. When the [execution pipeline](#s56--understanding-the-execution-pipeline) reaches an address that is present in that dict, that is, an address that is hooked, it will execute `project._sim_procedures[address].execute(state)`. This will consult the calling convention to extract the arguments, make a copy of itself in order to preserve thread safety, and run the `run()` method. It is important to produce a new instance of the SimProcedure for each time it is run, since the process of running a SimProcedure necessarily involves mutating state on the SimProcedure instance, so we need separate ones for each step, lest we run into race conditions in multithreaded environments.

<a id="s83--kwargs"></a>

#### kwargs

This hierarchy implies that you might want to reuse a single SimProcedure in multiple hooks. What if you want to hook the same SimProcedure in several places, but tweaked slightly each time? angr’s support for this is that any additional keyword arguments you pass to the constructor of your SimProcedure will end up getting passed as keyword args to your SimProcedure’s `run()` method. Pretty cool!

<a id="s83--data-types"></a>

### Data Types

If you were paying attention to the example earlier, you noticed that when we printed out the arguments to the `run()` function, they came out as a weird `<SAO <BV64 0xSTUFF>>` class. This is a `SimActionObject`. Basically, you don’t need to worry about it too much, it’s just a thin wrapper over a normal bitvector. It does a bit of tracking of what exactly you do with it inside the SimProcedure—this is helpful for static analysis.

You may also have noticed that we directly returned the Python int `0` from the procedure. This will automatically be promoted to a word-sized bitvector! You can return a native number, a bitvector, or a SimActionObject.

When you want to write a procedure that deals with floating point numbers, you will need to specify the calling convention manually. It’s not too hard, just provide a cc to the hook: `` `cc = project.factory.cc_from_arg_kinds((True, True), ret_fp=True) `` and `project.hook(address, ProcedureClass(cc=mycc))` This method for passing in a calling convention works for all calling conventions, so if angr’s autodetected one isn’t right, you can fix that.

<a id="s83--control-flow"></a>

### Control Flow

How can you exit a SimProcedure? We’ve already gone over the simplest way to do this, returning a value from `run()`. This is actually shorthand for calling `self.ret(value)`. `self.ret()` is the function which knows how to perform the specific action of returning from a function.

SimProcedures can use lots of different functions like this!

- `ret(expr)`: Return from a function

- `jump(addr)`: Jump to an address in the binary

- `exit(code)`: Terminate the program

- `call(addr, args, continue_at)`: Call a function in the binary

- `inline_call(procedure, *args)`: Call another SimProcedure in-line and return the results

That second-last one deserves some looking-at. We’ll get there after a quick detour…

<a id="s83--conditional-exits"></a>

#### Conditional Exits

What if we want to add a conditional branch out of a SimProcedure? In order to do that, you’ll need to work directly with the SimSuccessors object for the current execution step.

The interface for this is `` `self.successors.add_successor(state, addr, guard, jumpkind) ``. All of these parameters should have an obvious meaning if you’ve followed along so far. Keep in mind that the state you pass in will NOT be copied and WILL be mutated, so be sure to make a copy beforehand if there will be more work to do!

<a id="s83--simprocedure-continuations"></a>

#### SimProcedure Continuations

How can we call a function in the binary and have execution resume within our SimProcedure? There is a whole bunch of infrastructure called the “SimProcedure Continuation” that will let you do this. When you use `self.call(addr, args, continue_at)`, `addr` is expected to be the address you’d like to call, `args` is the tuple of arguments you’d like to call it with, and `continue_at` is the name of another method in your SimProcedure class that you’d like execution to continue at when it returns. This method must have the same signature as the `run()` method. Furthermore, you can pass the keyword argument `cc` as the calling convention that ought to be used to communicate with the callee.

When you do this, you finish your current step, and execution will start again at the next step at the function you’ve specified. When that function returns, it has to return to some concrete address! That address is specified by the SimProcedure runtime: an address is allocated in angr’s externs segment to be used as the return site for returning to the given method call. It is then hooked with a copy of the procedure instance tweaked to run the specified `continue_at` function instead of `run()`, with the same args and kwargs as the first time.

There are two pieces of metadata you need to attach to your SimProcedure class in order to use the continuation subsystem correctly:

- Set the class variable `IS_FUNCTION = True`

- Set the class variable `local_vars` to a tuple of strings, where each string is the name of an instance variable on your SimProcedure whose value you would like to persist to when you return. Local variables can be any type so long as you don’t mutate their instances.

You may have guessed by now that there exists some sort of auxiliary storage in order to hold on to all this data. You would be right! The state plugin `state.callstack` has an entry called `.procedure_data` which is used by the SimProcedure runtime to store information local to the current call frame. angr tracks the stack pointer in order to make the current top of the `state.callstack` a meaningful local data store. It’s stuff that ought to be stored in memory in a stack frame, but the data can’t be serialized and/or memory allocation is hard.

As an example, let’s look at the SimProcedure that angr uses internally to run all the shared library initializers for a `full_init_state` for a linux program:

```python
class LinuxLoader(angr.SimProcedure):
    NO_RET = True
    IS_FUNCTION = True
    local_vars = ('initializers',)

    def run(self):
        self.initializers = self.project.loader.initializers
        self.run_initializer()

    def run_initializer(self):
        if len(self.initializers) == 0:
            self.project._simos.set_entry_register_values(self.state)
            self.jump(self.project.entry)
        else:
            addr = self.initializers[0]
            self.initializers = self.initializers[1:]
            self.call(addr, (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')
```

This is a particularly clever usage of the SimProcedure continuations. First, notice that the current project is available for use on the procedure instance. This is some powerful stuff you can get yourself into; for safety you generally only want to use the project as a read-only or append-only data structure. Here we’re just getting the list of dynamic initializers from the loader. Then, for as long as the list isn’t empty, we pop a single function pointer out of the list, being careful not to mutate the list, since the list object is shared across states, and then call it, returning to the `run_initializer` function again. When we run out of initializers, we set up the entry state and jump to the program entry point.

Very cool!

<a id="s83--global-variables"></a>

### Global Variables

As a brief aside, you can store global variables in `state.globals`. This is a dictionary that just gets shallow-copied from state to successor state. Because it’s only a shallow copy, its members are the same instances, so the same rules as local variables in SimProcedure continuations apply. You need to be careful not to mutate any item that is used as a global variable unless you know exactly what you’re doing.

<a id="s83--helping-out-static-analysis"></a>

### Helping out static analysis

We’ve already looked at the class variable `IS_FUNCTION`, which allows you to use the SimProcedure continuation. There are a few more class variables you can set, though these ones have no direct benefit to you - they merely mark attributes of your function so that static analysis knows what it’s doing.

- `NO_RET`: Set this to true if control flow will never return from this function

- `ADDS_EXITS`: Set this to true if you do any control flow other than returning

- `IS_SYSCALL`: Self-explanatory

Furthermore, if you set `ADDS_EXITS = True`, you’ll need to define the method `static_exits()`. This function takes a single parameter, a list of IRSBs that would be executed in the run-up to your function, and asks you to return a list of all the exits that you know would be produced by your function in that case. The return value is expected to be a list of tuples of (address (int), jumpkind (str)). This is meant to be a quick, best-effort analysis, and you shouldn’t try to do anything crazy or intensive to get your answer.

<a id="s83--user-hooks"></a>

### User Hooks

The process of writing and using a SimProcedure makes a lot of assumptions that you want to hook over a whole function. What if you don’t? There’s an alternate interface for hooking, a *user hook*, that lets you streamline the process of hooking sections of code.

```python
>>> @project.hook(0x1234, length=5)
... def set_rax(state):
...     state.regs.rax = 1
```

This is a lot simpler! The idea is to use a single function instead of an entire SimProcedure subclass. No extraction of arguments is performed, no complex control flow happens.

Control flow is controlled by the length argument. After the function finishes executing in this example, the next step will start at 5 bytes after the hooked address. If the length argument is omitted or set to zero, execution will resume executing the binary code at exactly the hooked address, without re-triggering the hook. The `Ijk_NoHook` jumpkind allows this to happen.

If you want more control over control flow coming out of a user hook, you can return a list of successor states. Each successor will be expected to have `state.regs.ip`, `state.scratch.guard`, and `state.scratch.jumpkind` set. The IP is the target instruction pointer, the guard is a symbolic boolean representing a constraint to add to the state related to it being taken as opposed to the others, and the jumpkind is a VEX enum string, like `Ijk_Boring`, representing the nature of the branch.

The general rule is, if you want your SimProcedure to either be able to extract function arguments or cause a program return, write a full SimProcedure class. Otherwise, use a user hook.

<a id="s83--hooking-symbols"></a>

### Hooking Symbols

As you should recall from the [section on loading a binary](#s73--loading-a-binary), dynamically linked programs have a list of symbols that they must import from the libraries they have listed as dependencies, and angr will make sure, rain or shine, that every import symbol gets resolved by *some* address, whether it’s a real implementation of the function or just a dummy address hooked with a do-nothing stub. As a result, you can just use the `Project.hook_symbol` API to hook the address referred to by a symbol!

This means that you can replace library functions with your own code. For instance, to replace `rand()` with a function that always returns a consistent sequence of values:

```python
>>> class NotVeryRand(SimProcedure):
...     def run(self, return_values=None):
...         rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
...         out = return_values[rand_idx]
...         self.state.globals['rand_idx'] = rand_idx + 1
...         return out

>>> project.hook_symbol('rand', NotVeryRand(return_values=[413, 612, 1025, 1111]))
```

Now, whenever the program tries to call `rand()`, it’ll return the integers from the `return_values` array in a loop.


---

<a id="s84"></a>

<a id="s84--state-plugins"></a>

## [S84] State Plugins

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


If you want to store some data on a state and have that information propagated from successor to successor, the easiest way to do this is with `state.globals`. However, this can become obnoxious with large amounts of interesting data, doesn’t work at all for merging states, and isn’t very object-oriented.

The solution to these problems is to write a *State Plugin* - an appendix to the state that holds data and implements an interface for dealing with the lifecycle of a state.

<a id="s84--my-first-plugin"></a>

### My First Plugin

Let’s get started! All state plugins are implemented as subclasses of `SimStatePlugin`. Once you’ve read this document, you can use the API reference for this class [`angr.state_plugins.plugin.SimStatePlugin`](https://docs.angr.io/en/latest/api/angr.state_plugins.plugin.html#angr.state_plugins.plugin.SimStatePlugin) to quickly review the semantics of all the interfaces you should implement.

The most important method you need to implement is `copy`: it should be annotated with the `memo` staticmethod and take a dict called the “memo”—these’ll be important later—and returns a copy of the plugin. Short of that, you can do whatever you want. Just make sure to call the superclass initializer!

```python
>>> import angr
>>> class MyFirstPlugin(angr.SimStatePlugin):
...     def __init__(self, foo):
...         super(MyFirstPlugin, self).__init__()
...         self.foo = foo
...
...     @angr.SimStatePlugin.memo
...     def copy(self, memo):
...         return MyFirstPlugin(self.foo)

>>> project = angr.load_shellcode(b'\x90', 'AMD64')
>>> state = angr.SimState(project=project)
>>> state.register_plugin('my_plugin', MyFirstPlugin('bar'))
>>> assert state.my_plugin.foo == 'bar'

>>> state2 = state.copy()
>>> state.my_plugin.foo = 'baz'
>>> state3 = state.copy()
>>> assert state2.my_plugin.foo == 'bar'
>>> assert state3.my_plugin.foo == 'baz'
```

It works! Note that plugins automatically become available as attributes on the state. `state.get_plugin(name)` is also available as a more programmatic interface.

<a id="s84--where-s-the-state"></a>

### Where’s the state?

State plugins have access to the state, right? So why isn’t it part of the initializer? It turns out, there are a plethora of issues related to initialization order and dependency issues, so to simplify things as much as possible, the state is not part of the initializer but is rather set onto the state in a separate phase, by using the `set_state` method. You can override this state if you need to do things like propagate the state to subcomponents or extract architectural information.

```python
>>> def set_state(self, state):
...     super(SimStatePlugin, self).set_state(state)
...     self.symbolic_word = claripy.BVS('my_variable', self.state.arch.bits)
```

Note the `self.state`! That’s what the super `set_state` sets up.

However, there’s no guarantee on what order the states will be set onto the plugins in, so if you need to interact with *other plugins* for initialization, you need to override the `init_state` method.

Once again, there’s no guarantee on what order these will be called in, so the rule is to make sure you set yourself up good enough during `set_state` so that if someone else tries to interact with you, no type errors will happen. Here’s an example of a good use of `init_state`, to map a memory region in the state. The use of an instance variable (presumably copied as part of `copy()`) ensures this only happens the first time the plugin is added to a state.

```python
>>> def init_state(self):
...     if self.region is None:
...        self.region = self.state.memory.map_region(SOMEWHERE, 0x1000, 7)
```

<a id="s84--note-weak-references"></a>

#### Note: weak references

`self.state` is not the state itself, but rather a [weak proxy](https://docs.python.org/2/library/weakref.html) to the state. You can still use this object as a normal state, but attempts to store it persistently will not work.

<a id="s84--merging"></a>

### Merging

The other element besides copying in the state lifecycle is merging. As input you get the plugins to merge and a list of “merge conditions” - symbolic booleans that are the “guard conditions” describing when the values from each state should actually apply.

The important properties of the merge conditions are:

- They are mutually exclusive and span an entire domain - exactly one may be satisfied at once, and there will be additional constraints to ensure that at least one must be satisfied.

- `len(merge_conditions)` == len(others) + 1, since `self` counts too.

- `zip(merge_conditions, [self] + others)` will correctly pair merge conditions with plugins.

During the merge function, you should *mutate* `self` to become the merged version of itself and all the others, with respect to the merge conditions. This involves using the if-then-else structure that claripy provides. Here is an example of constructing this merged structure by merging a bitvector instance variable called `myvar`, producing a binary tree of if-then-else expressions searching for the correct condition:

```python
for other_plugin, condition in zip(others, merge_conditions[1:]): # chop off self's condition
    self.myvar = claripy.If(condition, other_plugin.myvar, self.myvar)
```

This is such a common construction that we provide a utility to perform it automatically: `claripy.ite_cases`. The following code snippet is identical to the previous one:

```python
self.myvar = claripy.ite_cases(zip(merge_conditions[1:], [o.myvar for o in others]), self.myvar)
```

Keep in mind that like the rest of the top-level claripy functions, `ite_cases` and `If` are also available from `state.solver`, and these versions will perform SimActionObject unwrapping if applicable.

<a id="s84--common-ancestor"></a>

#### Common Ancestor

The full prototype of the `merge` interface is `def merge(self, others, merge_conditions, common_ancestor=None)`. `others` and `merge_conditions` have been discussed in depth already.

The common ancestor is the instance of the plugin from the most recent common ancestor of the states being merged. It may not be available for all merges, in which case it will be None. There are no rules for how exactly you should use this to improve the quality of your merges, but you may find it useful in more complex setups.

<a id="s84--serialization"></a>

### Serialization

In order to support serialization of states which contain your plugin, you should implement the `__getstate__`/`__setstate__` magic method pair. Keep in mind the following guidelines:

- Your serialization result should *not* include the state.

- After deserialization, `set_state()` will be called again.

This means that plugins are “detached” from the state and serialized in an isolated environment, and then reattached to the state on deserialization.

<a id="s84--plugins-all-the-way-down"></a>

### Plugins all the way down

You may have components within your state plugins which are large and complicated and start breaking object-orientation in order to make copy/merge work well with the state lifecycle. You’re in luck! Things can be state plugins even if they aren’t directly attached to a state. A great example of this is `SimFile`, which is a state plugin but is stored in the filesystem plugin, and is never used with `SimState.register_plugin`. When you’re doing this, there are a handful of rules to remember which will keep your plugins safe and happy:

- Annotate your copy function with `@SimStatePlugin.memo`.

- In order to prevent *divergence* while copying multiple references to the same plugin, make sure you’re passing the memo (the argument to copy) to the `.copy` of any subplugins. This with the previous point will preserve object identity.

- In order to prevent *duplicate merging* while merging multiple references to the same plugin, there should be a concept of the “owner” of each instance, and only the owner should run the merge routine.

- While passing arguments down into sub-plugins `merge()` routines, make sure you unwrap `others` and `common_ancestor` into the appropriate types. For example, if `PluginA` contains a `PluginB`, the former should do the following:

```python
>>> def merge(self, others, merge_conditions, common_ancestor=None):
...     # ... merge self
...     self.plugin_b.merge([o.plugin_b for o in others], merge_conditions,
...         common_ancestor=None if common_ancestor is None else common_ancestor.plugin_b)
```

<a id="s84--setting-defaults"></a>

### Setting Defaults

To make it so that a plugin will automatically become available on a state when requested, without having to register it with the state first, you can register it as a *default*. The following code example will make it so that whenever you access `state.my_plugin`, a new instance of `MyPlugin` will be instantiated and registered with the state.

```python
MyPlugin.register_default('my_plugin')
```


---

<a id="s85"></a>

<a id="s85--frequently-asked-questions"></a>

## [S85] Frequently Asked Questions

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


This is a collection of commonly-asked “how do I do X?” questions and other general questions about angr, for those too lazy to read this whole document.

If your question is of the form “how do I fix X issue after installing”, see also the Troubleshooting section of the [install instructions](#s88--installing-angr).

<a id="s85--why-is-it-named-angr"></a>

### Why is it named angr?

The core of angr’s analysis is on VEX IR, and when something is vexing, it makes you angry.

<a id="s85--how-should-angr-be-stylized"></a>

### How should “angr” be stylized?

All lowercase, even at the beginning of sentences. It’s an anti-proper noun.

<a id="s85--why-isn-t-symbolic-execution-doing-the-thing-i-want"></a>

### Why isn’t symbolic execution doing the thing I want?

The universal debugging technique for symbolic execution is as follows:

- Check your simulation manager for errored states. `print(simgr)` is a good place to start, and if you see anything to do with “errored”, go for `print(simgr.errored)`.

- If you have any errored states and it’s not immediately obvious what you did wrong, you can get a [pdb](https://docs.python.org/3/library/pdb.html) shell at the crash site by going `simgr.errored[n].debug()`.

- If no state has reached an address you care about, you should check the path each state has gone down: `import pprint; pprint.pprint(state.history.descriptions.hardcopy)`. This will show you a high-level summary of what the symbolic execution engine did at each step along the state’s history. You will be able to see from this a basic block trace and also a list of executed simprocedures. If you’re using unicorn engine, you can check `state.history.bbl_addrs.hardcopy` to see what blocks were executed in each invocation of unicorn.

- If a state is going down the wrong path, you can check what constraints caused it to go that way: `print(state.solver.constraints)`. If a state has just gone past a branch, you can check the most recent branch condition with `state.history.events[-1]`.

<a id="s85--how-can-i-get-diagnostic-information-about-what-angr-is-doing"></a>

### How can I get diagnostic information about what angr is doing?

angr uses the standard `logging` module for logging, with every package and submodule creating a new logger.

The simplest way to get debug output is the following:

```python
import logging
logging.getLogger('angr').setLevel('DEBUG')
```

You may want to use `INFO` or whatever else instead. By default, angr will enable logging at the `WARNING` level.

Each angr module has its own logger string, usually all the Python modules above it in the hierarchy, plus itself, joined with dots. For example, `angr.analyses.cfg`. Because of the way the Python logging module works, you can set the verbosity for all submodules in a module by setting a verbosity level for the parent module. For example, `logging.getLogger('angr.analyses').setLevel('INFO')` will make the CFG, as well as all other analyses, log at the INFO level.

<a id="s85--why-is-angr-so-slow"></a>

### Why is angr so slow?

It’s complicated! [Optimization considerations](#s57--optimization-considerations)

<a id="s85--how-do-i-find-bugs-using-angr"></a>

### How do I find bugs using angr?

It’s complicated! The easiest way to do this is to define a “bug condition”, for example, “the instruction pointer has become a symbolic variable”, and run symbolic exploration until you find a state matching that condition, then dump the input as a testcase. However, you will quickly run into the state explosion problem. How you address this is up to you. Your solution may be as simple as adding an `avoid` condition or as complicated as implementing CMU’s MAYHEM system as an Exploration Technique.

<a id="s85--why-did-you-choose-vex-instead-of-another-ir-such-as-llvm-reil-bap-etc"></a>

### Why did you choose VEX instead of another IR (such as LLVM, REIL, BAP, etc)?

We had two design goals in angr that influenced this choice:

1.  angr needed to be able to analyze binaries from multiple architectures. This mandated the use of an IR to preserve our sanity, and required the IR to support many architectures.

2.  We wanted to implement a binary analysis engine, not a binary lifter. Many projects start and end with the implementation of a lifter, which is a time consuming process. We needed to take something that existed and already supported the lifting of multiple architectures.

Searching around the internet, the major choices were:

- LLVM is an obvious first candidate, but lifting binary code to LLVM cleanly is a pain. The two solutions are either lifting to LLVM through QEMU, which is hackish (and the only implementation of it seems very tightly integrated into S2E), or McSema, which only supported x86 at the time but has since gone through a rewrite and gotten support for x86-64 and aarch64.

- TCG is QEMU’s IR, but extracting it seems very daunting as well and documentation is very scarce.

- REIL seems promising, but there is no standard reference implementation that supports all the architectures that we wanted. It seems like a nice academic work, but to use it, we would have to implement our own lifters, which we wanted to avoid.

- BAP was another possibility. When we started work on angr, BAP only supported lifting x86 code, and up-to-date versions of BAP were only available to academic collaborators of the BAP authors. These were two deal-breakers. BAP has since become open, but it still only supports x86_64, x86, and ARM.

- VEX was the only choice that offered an open library and support for many architectures. As a bonus, it is very well documented and designed specifically for program analysis, making it very easy to use in angr.

While angr uses VEX now, there’s no fundamental reason that multiple IRs cannot be used. There are two parts of angr, outside of the `angr.engines.vex` package, that are VEX-specific:

- the jump labels (i.e., the `Ijk_Ret` for returns, `Ijk_Call` for calls, and so forth) are VEX enums.

- VEX treats registers as a memory space, and so does angr. While we provide accesses to `state.regs.rax` and friends, on the backend, this does `state.registers.load(8, 8)`, where the first `8` is a VEX-defined offset for `rax` to the register file.

To support multiple IRs, we’ll either want to abstract these things or translate their labels to VEX analogues.

<a id="s85--why-are-some-arm-addresses-off-by-one"></a>

### Why are some ARM addresses off-by-one?

In order to encode THUMB-ness of an ARM code address, we set the lowest bit to one. This convention comes from LibVEX, and is not entirely our choice! If you see an odd ARM address, that just means the code at `address - 1` is in THUMB mode.

<a id="s85--how-do-i-serialize-angr-objects"></a>

### How do I serialize angr objects?

[Pickle](https://docs.python.org/2/library/pickle.html) will work. However, Python will default to using an extremely old pickle protocol that does not support more complex Python data structures, so you must specify a [more advanced data stream format](https://docs.python.org/2/library/pickle.html#data-stream-format). The easiest way to do this is `pickle.dumps(obj, -1)`.

<a id="s85--what-does-unsupportediroperror-floating-point-support-disabled-mean"></a>

### What does `UnsupportedIROpError("floating point support disabled")` mean?

This might crop up if you’re using a CGC analysis such as driller or rex. Floating point support in angr has been disabled in the CGC analyses for a tight-knit nebula of reasons:

- Libvex’s representation of floating point numbers is imprecise - it converts the 80-bit extended precision format used by the x87 for computation to 64-bit doubles, making it impossible to get precise results

- There is very limited implementation support in angr for the actual primitive operations themselves as reported by libvex, so you will often get a less friendly “unsupported operation” error if you go too much further

- For what operations are implemented, the basic optimizations that allow tractability during symbolic computation (AST deduplication, operation collapsing) are not implemented for floating point ops, leading to gigantic ASTs

- There are memory corruption bugs in z3 that get triggered frighteningly easily when you’re using huge workloads of mixed floating point and bitvector ops. We haven’t been able to get a testcase that doesn’t involve “just run angr” for the z3 guys to investigate.

Instead of trying to cope with all of these, we have simply disabled floating point support in the symbolic execution engine. To allow for execution in the presence of floating point ops, we have enabled an exploration technique called the https://github.com/angr/angr/blob/master/angr/exploration_techniques/oppologist.py \<oppologist\> that is supposed to catch these issues, concretize their inputs, and run the problematic instructions through qemu via unicorn engine, allowing execution to continue. The intuition is that the specific values of floating point operations don’t typically affect the exploitation process.

If you’re seeing this error and it’s terminating the analysis, it’s probably because you don’t have unicorn installed or configured correctly. If you’re seeing this issue just in a log somewhere, it’s just the oppologist kicking in and you have nothing to worry about.

<a id="s85--why-is-angr-s-cfg-different-from-ida-s"></a>

### Why is angr’s CFG different from IDA’s?

Two main reasons:

- IDA does not split basic blocks at function calls. angr will, because they are a form of control flow and basic blocks end at control flow instructions. You generally do not need the supergraph for performing automated analyses.

- IDA will split basic blocks if another block jumps into the middle of it. This is called basic block normalization, and angr does not do it by default since it is unnecessary for most static analyses. You may enable it by passing `normalize=True` to the CFG analysis.

<a id="s85--why-do-i-get-incorrect-register-values-when-reading-from-a-state-during-a-siminspect-breakpoint"></a>

### Why do I get incorrect register values when reading from a state during a SimInspect breakpoint?

libVEX will eliminate duplicate register writes within a single basic block when optimizations are enabled. Turn off IR optimization to make everything look right at all times.

In the case of the instruction pointer, libVEX will frequently omit mid-block writes even when optimizations are disabled. In this case, you should use `state.scratch.ins_addr` to get the current instruction pointer.


---

<a id="s86"></a>

<a id="s86--reporting-bugs"></a>

## [S86] Reporting Bugs

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


If you’ve found something that angr isn’t able to solve and appears to be a bug, please let us know!

1.  Create a fork off of angr/binaries and angr/angr

2.  Give us a pull request with angr/binaries, with the binaries in question

3.  Give us a pull request for angr/angr, with testcases that trigger the binaries in `angr/tests/broken_x.py`, `angr/tests/broken_y.py`, etc

Please try to follow the testcase format that we have (so the code is in a test_blah function), that way we can very easily merge that and make the scripts run.

An example is:

```python
def test_some_broken_feature():
    p = angr.Project("some_binary")
    result = p.analyses.SomethingThatDoesNotWork()
    assert result == "what it should *actually* be if it worked"

if __name__ == '__main__':
    test_some_broken_feature()
```

This will *greatly* help us recreate your bug and fix it faster.

The ideal situation is that, when the bug is fixed, your testcases passes (i.e., the assert at the end does not raise an AssertionError).

Then, we can just fix the bug and rename `broken_x.py` to `test_x.py` and the testcase will run in our internal CI at every push, ensuring that we do not break this feature again.

<a id="s86--developing-angr"></a>

## [S86] Developing angr

These are some guidelines so that we can keep the codebase in good shape!

<a id="s86--pre-commit"></a>

### pre-commit

Many angr repos contain pre-commit hooks provided by [pre-commit](https://pre-commit.com/). Installing this is as easy as `pip install pre-commit`. After `git` cloning an angr repository, if the repo contains a `.pre-commit-config.yaml`, run `pre-commit install`. Future `git` commits will now invoke these hooks automatically.

<a id="s86--coding-style"></a>

### Coding style

We format our code with [black](https://github.com/psf/black) and otherwise try to get as close as the [PEP8 code convention](http://legacy.python.org/dev/peps/pep-0008/) as is reasonable without being dumb. If you use Vim, the [python-mode](https://github.com/klen/python-mode) plugin does all you need. You can also [manually configure](https://wiki.python.org/moin/Vim) vim to adopt this behavior.

Most importantly, please consider the following when writing code as part of angr:

- Try to use attribute access (see the `@property` decorator) instead of getters and setters wherever you can. This isn’t Java, and attributes enable tab completion in iPython. That being said, be reasonable: attributes should be fast. A rule of thumb is that if something could require a constraint solve, it should not be an attribute.

- Use [our pylintrc from the angr-dev repo](https://github.com/angr/angr-dev/blob/master/pylintrc). It’s fairly permissive, but our CI server will fail your builds if pylint complains under those settings.

- DO NOT, under ANY circumstances, `raise Exception` or `assert False`. **Use the right exception type**. If there isn’t a correct exception type, subclass the core exception of the module that you’re working in (i.e., `AngrError` in angr, `SimError` in SimuVEX, etc) and raise that. We catch, and properly handle, the right types of errors in the right places, but `AssertionError` and `Exception` are not handled anywhere and force-terminate analyses.

- Avoid tabs; use space indentation instead. Even though it’s wrong, the de facto standard is 4 spaces. It is a good idea to adopt this from the beginning, as merging code that mixes both tab and space indentation is awful.

- Avoid super long lines. It’s okay to have longer lines, but keep in mind that long lines are harder to read and should be avoided. Let’s try to stick to **120 characters**.

- Avoid extremely long functions, it is often better to break them up into smaller functions.

- Always use `_` instead of `__` for private members (so that we can access them when debugging). *You* might not think that anyone has a need to call a given function, but trust us, you’re wrong.

- Format your code with `black`; config is already defined within `pyproject.toml`.

<a id="s86--documentation"></a>

### Documentation

Document your code. Every *class definition* and *public function definition* should have some description of:

- What it does.

- What are the type and the meaning of the parameters.

- What it returns.

Class docstrings will be enforced by our linter. Do *not* under any circumstances write a docstring which doesn’t provide more information than the name of the class. What you should try to write is a description of the environment that the class should be used in. If the class should not be instantiated by end-users, write a description of where it will be generated and how instances can be acquired. If the class should be instantiated by end-users, explain what kind of object it represents at its core, what behavior is expected of its parameters, and how to safely manage objects of its type.

We use [Sphinx](http://www.sphinx-doc.org/en/stable/) to generate the API documentation. Sphinx supports docstrings written in [ReStructured Text](http://openalea.gforge.inria.fr/doc/openalea/doc/_build/html/source/sphinx/rest_syntax.html#auto-document-your-python-code) with special [keywords](http://www.sphinx-doc.org/en/stable/domains.html#info-field-lists) to document function and class parameters, return values, return types, members, etc.

Here is an example of function documentation. Ideally the parameter descriptions should be aligned vertically to make the docstrings as readable as possible.

```python
def prune(self, filter_func=None, from_stash=None, to_stash=None):
    """
    Prune unsatisfiable paths from a stash.

    :param filter_func: Only prune paths that match this filter.
    :param from_stash:  Prune paths from this stash. (default: 'active')
    :param to_stash:    Put pruned paths in this stash. (default: 'pruned')
    :returns:           The resulting PathGroup.
    :rtype:             PathGroup
    """
```

This format has the advantage that the function parameters are clearly identified in the generated documentation. However, it can make the documentation repetitive, in some cases a textual description can be more readable. Pick the format you feel is more appropriate for the functions or classes you are documenting.

```python
def read_bytes(self, addr, n):
   """
   Read `n` bytes at address `addr` in memory and return an array of bytes.
   """
```

<a id="s86--unit-tests"></a>

### Unit tests

If you’re pushing a new feature and it is not accompanied by a test case it **will be broken** in very short order. Please write test cases for your stuff.

We have an internal CI server to run tests to check functionality and regression on each commit. In order to have our server run your tests, write your tests in a format acceptable to [nosetests](https://nose.readthedocs.org/en/latest/) in a file matching `test_*.py` in the `tests` folder of the appropriate repository. A test file can contain any number of functions of the form `def test_*():` or classes of the form `class Test*(unittest.TestCase):`. Each of them will be run as a test, and if they raise any exceptions or assertions, the test fails. Do not use the `nose.tools.assert_*` functions, as we are presently trying to migrate to `nose2`. Use `assert` statements with descriptive messages or the `unittest.TestCase` assert methods.

Look at the existing tests for examples. Many of them use an alternate format where the `test_*` function is actually a generator that yields tuples of functions to call and their arguments, for easy parametrization of tests.

Finally, do not add docstrings to your test functions.


---

<a id="s87"></a>

<a id="s87--help-wanted"></a>

## [S87] Help Wanted

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


<a id="s87--id1"></a>

Todo

This page is woefully out of date. We need to update it.

angr is a huge project, and it’s hard to keep up. Here, we list some big TODO items that we would love community contributions for in the hope that it can direct community involvement. They (will) have a wide range of complexity, and there should be something for all skill levels!

We tag issues on our github repositories that would be good for community involvement as “Help wanted”. To see the exhaustive list of these, use [this github search!](https://github.com/search?utf8=%E2%9C%93&q=user%3Aangr+label%3A%22help+wanted%22+state%3Aopen&type=Issues&ref=advsearch&l=&l=)

<a id="s87--documentation"></a>

### Documentation

There are many parts of angr that suffer from little or no documentation. We desperately need community help in this area.

<a id="s87--api"></a>

#### API

We are always behind on documentation. We’ve created several tracking issues on github to understand what’s still missing:

1.  [angr](https://github.com/angr/angr/issues/145)

2.  [claripy](https://github.com/angr/claripy/issues/17)

3.  [cle](https://github.com/angr/cle/issues/29)

4.  [pyvex](https://github.com/angr/pyvex/issues/34)

<a id="s87--gitbook"></a>

#### GitBook

This book is missing some core areas. Specifically, the following could be improved:

1.  Finish some of the TODOs floating around the book.

2.  Organize the Examples page in some way that makes sense. Right now, most of the examples are very redundant. It might be cool to have a simple table of most of them so that the page is not so overwhelming.

<a id="s87--angr-course"></a>

#### angr course

Developing a “course” of sorts to get people started with angr would be really beneficial. Steps have already been made in this direction [here](https://github.com/angr/angr-doc/pull/74), but more expansion would be beneficial.

Ideally, the course would have a hands-on component, of increasing difficulty, that would require people to use more and more of angr’s capabilities.

<a id="s87--research-re-implementation"></a>

### Research re-implementation

Unfortunately, not everyone bases their research on angr ;-). Until that’s remedied, we’ll need to periodically implement related work, on top of angr, to make it reusable within the scope of the framework. This section lists some of this related work that’s ripe for reimplementation in angr.

<a id="s87--redundant-state-detection-for-dynamic-symbolic-execution"></a>

#### Redundant State Detection for Dynamic Symbolic Execution

Bugrara, et al. describe a method to identify and trim redundant states, increasing the speed of symbolic execution by up to 50 times and coverage by 4%. This would be great to have in angr, as an ExplorationTechnique. The paper is here: <http://nsl.cs.columbia.edu/projects/minestrone/papers/atc13-bugrara.pdf>

<a id="s87--in-vivo-multi-path-analysis-of-software-systems"></a>

#### In-Vivo Multi-Path Analysis of Software Systems

Rather than developing symbolic summaries for every system call, we can use a technique proposed by [S2E](http://dslab.epfl.ch/pubs/s2e.pdf) for concretizing necessary data and dispatching them to the OS itself. This would make angr applicable to a *much* larger set of binaries than it can currently analyze.

While this would be most useful for system calls, once it is implemented, it could be trivially applied to any location of code (i.e., library functions). By carefully choosing which library functions are handled like this, we can greatly increase angr’s scalability.

<a id="s87--development"></a>

### Development

We have several projects in mind that primarily require development effort.

<a id="s87--angr-management"></a>

#### angr-management

The angr GUI, [angr-management](https://github.com/angr/angr-management), could use your improvements! Exposing more of angr’s capabilities in a usable way, graphically, would be really useful!

<a id="s87--ida-plugins"></a>

#### IDA Plugins

Much of angr’s functionality could be exposed via IDA. For example, angr’s data dependence graph could be exposed in IDA through annotations, or obfuscated values can be resolved using symbolic execution.

<a id="s87--additional-architectures"></a>

#### Additional architectures

More architecture support would make angr all the more useful. Supporting a new architecture with angr would involve:

1.  Adding the architecture information to [archinfo](https://github.com/angr/archinfo)

2.  Adding an IR translation. This may be either an extension to PyVEX, producing IRSBs, or another IR entirely.

3.  If your IR is not VEX, add a `SimEngine` to support it.

4.  Adding a calling convention (`angr.SimCC`) to support SimProcedures (including system calls)

5.  Adding or modifying an `angr.SimOS` to support initialization activities.

6.  Creating a CLE backend to load binaries, or extending the CLE ELF backend to know about the new architecture if the binary format is ELF.

**ideas for new architectures:**

- PIC, AVR, other embedded architectures

- SPARC (there is some preliminary libVEX support for SPARC [here](https://bitbucket.org/iraisr/valgrind-solaris))

**ideas for new IRs:**

- LLVM IR (with this, we can extend angr from just a Binary Analysis Framework to a Program Analysis Framework and expand its capabilities in other ways!)

- SOOT (there is no reason that angr can’t analyze Java code, although doing so would require some extensions to our memory model)

<a id="s87--environment-support"></a>

#### Environment support

We use the concept of “function summaries” in angr to model the environment of operating systems (i.e., the effects of their system calls) and library functions. Extending this would be greatly helpful in increasing angr’s utility. These function summaries can be found [here](https://github.com/angr/angr/tree/master/angr/procedures).

A specific subset of this is system calls. Even more than library function SimProcedures (without which angr can always execute the actual function), we have very few workarounds for missing system calls. Every implemented system call extends the set of binaries that angr can handle.

<a id="s87--design-problems"></a>

### Design Problems

There are some outstanding design challenges regarding the integration of additional functionalities into angr.

<a id="s87--type-annotation-and-type-information-usage"></a>

#### Type annotation and type information usage

angr has fledgling support for types, in the sense that it can parse them out of header files. However, those types are not well exposed to do anything useful with. Improving this support would make it possible to, for example, annotate certain memory regions with certain type information and interact with them intelligently. Consider, for example, interacting with a linked list like this: `print state.mem[state.regs.rax].llist.next.next.value`.

(editor’s note: you can actually already do this)

<a id="s87--research-challenges"></a>

### Research Challenges

Historically, angr has progressed in the course of research into novel areas of program analysis. Here, we list several self-contained research projects that can be tackled.

<a id="s87--semantic-function-identification-diffing"></a>

#### Semantic function identification/diffing

Current function diffing techniques (TODO: some examples) have drawbacks. For the CGC, we created a semantic-based binary identification engine ( <https://github.com/angr/identifier>) that can identify functions based on testcases. There are two areas of improvement, each of which is its own research project:

1.  Currently, the testcases used by this component are human-generated. However, symbolic execution can be used to automatically generate testcases that can be used to recognize instances of a given function in other binaries.

2.  By creating testcases that achieve a “high-enough” code coverage of a given function, we can detect changes in functionality by applying the set of testcases to another implementation of the same function and analyzing changes in code coverage. This can then be used as a semantic function diff.

<a id="s87--applying-afl-s-path-selection-criteria-to-symbolic-execution"></a>

#### Applying AFL’s path selection criteria to symbolic execution

AFL does an excellent job in identifying “unique” paths during fuzzing by tracking the control flow transitions taken by every path. This same metric can be applied to symbolic exploration, and would probably do a depressingly good job, considering how simple it is.

<a id="s87--overarching-research-directions"></a>

### Overarching Research Directions

There are areas of program analysis that are not well explored. We list general directions of research here, but readers should keep in mind that these directions likely describe potential undertakings of entire PhD dissertations.

<a id="s87--process-interactions"></a>

#### Process interactions

Almost all work in the field of binary analysis deals with single binaries, but this is often unrealistic in the real world. For example, the type of input that can be passed to a CGI program depend on pre-processing by a web server. Currently, there is no way to support the analysis of multiple concurrent processes in angr, and many open questions in the field (i.e., how to model concurrent actions).

<a id="s87--intra-process-concurrency"></a>

#### Intra-process concurrency

Similar to the modeling of interactions between processes, little work has been done in understanding the interaction of concurrent threads in the same process. Currently, angr has no way to reason about this, and it is unclear from the theoretical perspective how to approach this.

A subset of this problem is the analysis of signal handlers (or hardware interrupts). Each signal handler can be modeled as a thread that can be executed at any time that a signal can be triggered. Understanding when it is meaningful to analyze these handlers is an open problem. One system that does reason about the effect of interrupts is [FIE](http://pages.cs.wisc.edu/~davidson/fie/).

<a id="s87--path-explosion"></a>

#### Path explosion

Many approaches (such as [Veritesting](https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinosetal._2014_EnhancingSymbolicExecutionwithVeritesting.pdf)) attempt to mitigate the path explosion problem in symbolic execution. However, despite these efforts, path explosion is still *the* main problem preventing symbolic execution from being mainstream.

angr provides an excellent base to implement new techniques to control path explosion. Most approaches can be easily implemented as `ExplorationTechnique` s and quickly evaluated (for example, on the [CGC dataset](https://github.com/CyberGrandChallenge/samples)).


---

<a id="s88"></a>

<a id="s88--installing-angr"></a>

## [S88] Installing angr

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr is a library for Python 3.10+, and must be installed into a Python environment before it can be used.

<a id="s88--installing-from-pypi"></a>

### Installing from PyPI

angr is published on [PyPI](https://pypi.org/), and using this is the easiest and recommended way to install angr. It can be installed angr with pip:

```bash
pip install angr
```

Tip

It is recommended to use an isolated python environment rather than installing angr globally. Doing so reduces dependency conflicts and aids in reproducibility while debugging. Some popular tools that accomplish this include:

- [venv](https://docs.python.org/3/library/venv.html)

- [pipenv](https://pipenv.pypa.io/en/latest/)

- [virtualenv](https://virtualenv.pypa.io/en/latest/)

- [virtualenvwrapper](https://virtualenvwrapper.readthedocs.io/en/latest/)

- [conda](https://docs.conda.io/en/latest/)

Note

The PyPI distribution includes binary packages for most popular system configurations. If you are using a system that is not supported by the binary packages, you will need to build the C dependencies from source. See the [Installing from Source](#s88--installing-from-source) section for more information.

<a id="s88--installing-from-source"></a>

### Installing from Source

angr is a collection of Python packages, each of which is published on GitHub. The easiest way to install angr from source is to use [angr-dev](https://github.com/angr/angr-dev).

To set up a development environment manually, first ensure that build dependencies are installed. These consist of python development headers, `make`, a C++ compiler, and a Rust compiler. On Ubuntu, these can be installed with:

```bash
sudo apt-get install python3-dev build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then, checkout and install the following packages, in order:

- [archinfo](https://github.com/angr/archinfo)

- [pyvex](https://github.com/angr/pyvex) (clone with `--recursive`)

- [cle](https://github.com/angr/cle)

- [claripy](https://github.com/angr/claripy)

- [angr](https://github.com/angr/angr) (`pip install` with `--no-build-isolation`)

<a id="s88--installing-with-docker"></a>

### Installing with Docker

The angr team maintains a container image on Docker Hub that includes angr and its dependencies. This image can be pulled with:

```bash
docker pull angr/angr
```

The image can be run with:

```bash
docker run -it angr/angr
```

This will start a shell in the container, with angr installed and ready to use.

<a id="s88--troubleshooting"></a>

### Troubleshooting

<a id="s88--angr-has-no-attribute-project-or-similar"></a>

#### angr has no attribute Project, or similar

If angr can be imported but the `Project` class is missing, it is likely one of two problems:

1.  There is a script named `angr.py` in the working directory. Rename it to something else.

2.  There is a folder called `angr` in your working directory, possibly the cloned repository. Change the working directory to somewhere else.

<a id="s88--attributeerror-module-object-has-no-attribute-ks-arch-x86"></a>

#### AttributeError: ‘module’ object has no attribute ‘KS_ARCH_X86’

The `keystone` package is installed, which conflicts with the `keystone-engine` package, an optional dependency of angr. Uninstall `keystone` and install `keystone-engine`.


---

<a id="s89"></a>

<a id="s89--introduction"></a>

## [S89] Introduction

> **Official release appendix — preserved upstream material.** Examples may be historical or require external binaries. Where this conflicts with the main reference, prefer the version-checked main guidance. In particular, old Identifier, inspection, solver, and calling-convention examples need source/version checks.


angr is a multi-architecture binary analysis toolkit, with the capability to perform dynamic symbolic execution (like Mayhem, KLEE, etc.) and various static analyses on binaries. If you’d like to learn how to use it, you’re in the right place!

We’ve tried to make using angr as pain-free as possible - our goal is to create a user-friendly binary analysis suite, allowing a user to simply start up iPython and easily perform intensive binary analyses with a couple of commands. That being said, binary analysis is complex, which makes angr complex. This documentation is an attempt to help out with that, providing narrative explanation and exploration of angr and its design.

Several challenges must be overcome to programmatically analyze a binary. They are, roughly:

- Loading a binary into the analysis program.

- Translating a binary into an intermediate representation (IR).

- Performing the actual analysis. This could be:

  - A partial or full-program static analysis (i.e., dependency analysis, program slicing).

  - A symbolic exploration of the program’s state space (i.e., “Can we execute it until we find an overflow?”).

  - Some combination of the above (i.e., “Let’s execute only program slices that lead to a memory write, to find an overflow.”)

angr has components that meet all of these challenges. This documentation will explain how each component works, and how they can all be used to accomplish your goals.

<a id="s89--getting-support"></a>

### Getting Support

To get help with angr, you can:

- Chat with us on the [angr Discord server](http://discord.angr.io)

- Open an issue on the appropriate GitHub repository

<a id="s89--citing-angr"></a>

### Citing angr

If you use angr in an academic work, please cite the papers for which it was developed:

```bibtex
@article{shoshitaishvili2016state,
  title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Audrey and Grosen, Jessie and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2016}
}

@article{stephens2016driller,
  title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
  author={Stephens, Nick and Grosen, Jessie and Salls, Christopher and Dutcher, Audrey and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2016}
}

@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2015}
}
```

<a id="s89--going-further"></a>

### Going further

You can read this [paper](https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf), explaining some of the internals, algorithms, and used techniques to get a better understanding on what’s going on under the hood.

If you enjoy playing CTFs and would like to learn angr in a similar fashion, [angr_ctf](https://github.com/jakespringer/angr_ctf) will be a fun way for you to get familiar with much of the symbolic execution capability of angr. [The angr_ctf repo](https://github.com/jakespringer/angr_ctf) is maintained by [@jakespringer](https://github.com/jakespringer).

<a id="recreate-examples"></a>

## Recreate the complete example file set

Create an empty working directory and save each following block under its stated
relative filename. These are the complete files, not snippets. The examples
are original small targets and analysis programs supplied with this reference.
Native examples require Linux x86-64, a C compiler, Python 3.12, and angr 9.3.4.

```console
python3.12 -m venv .venv
.venv/bin/python -m pip install angr==9.3.4 pytest==9.1.1
.venv/bin/python tools/build_examples.py
.venv/bin/python examples/solve_stdin.py
.venv/bin/python -m pytest -q tests/test_labs.py
```

The compile script creates `build/targets` and `build/targets-pie`. Run examples
as files (for example `python examples/solve_argv.py`) so Python can import the
shared `examples/common.py`. In earlier chapters, `make examples` means running
the build script above, and `make test` means building targets then invoking
pytest. Documentation-only commands are unnecessary for these analysis examples.

### File: `examples/targets.c`

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Original teaching target; no third-party challenge binary is required. */
__attribute__((noinline)) int check(const unsigned char *p) {
    if (p[0] != 'C') return 0;
    if (p[1] != 'A') return 0;
    if (p[2] != 'T') return 0;
    if (p[3] != '!') return 0;
    return 1;
}
__attribute__((noinline)) uint32_t transform(uint32_t x) {
    return (x * 3u) ^ 0x55u;
}
__attribute__((noinline)) int score(unsigned int n) {
    unsigned int sum = 0;
    for (unsigned int i = 0; i < n; ++i) sum += i;
    return sum == 6;
}
__attribute__((noinline)) void win(void) { puts("ACCEPT"); }
__attribute__((noinline)) void lose(void) { puts("REJECT"); }

int main(int argc, char **argv) {
    unsigned char p[4] = {0};
    if (argc == 3 && strcmp(argv[1], "number") == 0) {
        printf("%u\n", transform((uint32_t)strtoul(argv[2], NULL, 10)));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "file") == 0) {
        FILE *f = fopen(argv[2], "rb");
        if (!f) return 2;
        size_t n = fread(p, 1, 4, f);
        fclose(f);
        if (n != 4) return 2;
    } else if (argc == 2) {
        if (strlen(argv[1]) != 4) return 2;
        memcpy(p, argv[1], 4);
    } else {
        if (read(0, p, 4) != 4) return 2;
    }
    if (check(p)) { win(); return 0; }
    lose();
    return 1;
}
```

### File: `examples/common.py`

```python
"""Small shared utilities; each tutorial explains the relevant calls."""
from pathlib import Path
import angr

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build/targets"

def project(binary=BINARY):
    if not Path(binary).is_file():
        raise FileNotFoundError("Build targets first: make examples")
    return angr.Project(str(binary), auto_load_libs=False)

def address(p, name):
    symbol = p.loader.main_object.get_symbol(name)
    if symbol is None:
        raise ValueError(f"Missing symbol {name!r}; use the unstripped lab binary")
    return symbol.rebased_addr

def search(p, state, steps=250):
    manager = p.factory.simulation_manager(state, save_unconstrained=True)
    manager.explore(find=address(p, "win"), avoid=address(p, "lose"), n=steps)
    if not manager.found:
        errors = [str(record.error) for record in manager.errored]
        counts = {name: len(states) for name, states in manager.stashes.items()}
        raise RuntimeError(f"No witness within {steps} steps: {counts}; errors={errors}")
    return manager.found[0]
```

### File: `tools/build_examples.py`

```python
"""Build only the original, local lab targets."""
from pathlib import Path
import os
import platform
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
    raise SystemExit("The native labs require Linux x86-64; build the docs with make html elsewhere.")
(ROOT / "build").mkdir(exist_ok=True)
for name, flags in (("targets", ["-fno-pie", "-no-pie"]), ("targets-pie", ["-fPIE", "-pie"])):
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
        "-O0", "-g", "-fno-inline", "-fno-stack-protector", *flags,
        str(ROOT / "examples/targets.c"), "-o", str(ROOT / "build" / name),
    ], check=True)
print("Built build/targets and build/targets-pie")
```

### File: `examples/analyze_cfg.py`

```python
"""Recover the local target's functions and decompile check."""
from common import address, project

def analyze():
    p = project()
    cfg = p.analyses.CFGFast(normalize=True, data_references=True)
    function = cfg.kb.functions[address(p, "check")]
    node = cfg.model.get_any_node(function.addr)
    assert node is not None
    decompiled = p.analyses.Decompiler(function, cfg=cfg.model)
    if decompiled.codegen is None:
        raise RuntimeError("Decompiler did not produce text")
    return {"functions": len(cfg.kb.functions), "blocks": len(function.block_addrs_set),
            "code": decompiled.codegen.text}

if __name__ == "__main__":
    result = analyze()
    print("Recovered functions:", result["functions"])
    print("Blocks in check:", result["blocks"])
    print(result["code"])
```

### File: `examples/analyze_dataflow.py`

```python
"""Observe reaching definitions at each node of one small function."""
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from common import address, project

def analyze():
    p = project()
    cfg = p.analyses.CFGFast(normalize=True)
    function = cfg.kb.functions[address(p, "transform")]
    points = [("node", block_addr, OP_AFTER) for block_addr in function.block_addrs_set]
    result = p.analyses.ReachingDefinitions(subject=function, observation_points=points, dep_graph=True)
    assert result.observed_results
    assert result.dep_graph is not None
    return {"observations": len(result.observed_results),
            "definitions": result.dep_graph.graph.number_of_nodes(),
            "dependencies": result.dep_graph.graph.number_of_edges()}

if __name__ == "__main__":
    print(analyze())
```

### File: `examples/bounded_search.py`

```python
"""Apply a loop bound to a function with an explicitly bounded argument."""
import angr
import claripy
from common import address, project

def solve():
    p = project()
    n = claripy.BVS("n", 32)
    stop = 0x70000000
    state = p.factory.call_state(address(p, "score"), n,
        prototype="int score(unsigned int)", ret_addr=stop)
    state.solver.add(n <= 6)
    cfg = p.analyses.CFGFast(normalize=True)
    manager = p.factory.simulation_manager(state)
    manager.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=8))
    manager.explore(find=stop, num_find=10, n=150)
    answers = set()
    for returned in manager.found:
        returned.solver.add(returned.regs.eax == 1)
        if returned.solver.satisfiable():
            answers.update(returned.solver.eval_upto(n, 7))
    assert not manager.active and not manager.errored
    assert not manager.stashes.get("spinning", [])
    return sorted(answers)

if __name__ == "__main__":
    print(solve())
```

### File: `examples/custom_analysis.py`

```python
"""A registered analysis returning useful, deterministic function sizes."""
import angr
from angr.analyses import AnalysesHub
from common import address, project

class FunctionSizes(angr.Analysis):
    def __init__(self):
        cfg = self.project.analyses.CFGFast(normalize=True)
        self.result = {function.addr: sum(block.size for block in function.blocks)
                       for function in cfg.kb.functions.values()
                       if self.project.loader.main_object.contains_addr(function.addr)}

AnalysesHub.register_default("HandbookFunctionSizes", FunctionSizes)

def analyze():
    p = project()
    result = p.analyses.HandbookFunctionSizes()
    return result.result[address(p, "check")]

if __name__ == "__main__":
    print("Recovered bytes in check:", analyze())
```

### File: `examples/inspect_writes.py`

```python
"""Observe state memory writes without recursively triggering inspection."""
import angr
from common import BINARY, project, search

def observe():
    p = project()
    state = p.factory.full_init_state(args=[str(BINARY)], stdin=b"CAT!")
    state.globals["write_count"] = 0
    def count_write(current):
        # Integers are immutable, so each state's shallow globals copy is safe.
        current.globals["write_count"] += 1
        assert current.inspect.attrs.mem_write_address is not None
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=count_write)
    winner = search(p, state)
    return winner.globals["write_count"]

if __name__ == "__main__":
    print("Observed writes:", observe())
```

### File: `examples/solve_argv.py`

```python
"""Symbolic argv; the factory creates the trailing string terminator."""
import subprocess
import claripy
from common import BINARY, project, search

def solve():
    p = project()
    token = claripy.BVS("argument", 32)
    state = p.factory.full_init_state(args=[str(BINARY), token])
    for byte in token.chop(8):
        state.solver.add(byte >= 0x21, byte <= 0x7e)
    winner = search(p, state)
    candidate = winner.solver.eval(token, cast_to=bytes)
    replay = subprocess.run([str(BINARY), candidate.decode("ascii")], capture_output=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout == b"ACCEPT\n"
    return candidate

if __name__ == "__main__":
    print(repr(solve()))
```

### File: `examples/solve_file.py`

```python
"""Solve a virtual file, then replay with an equivalent temporary real file."""
from pathlib import Path
import subprocess
import tempfile
import angr
import claripy
from common import BINARY, project, search

def solve():
    p = project()
    content = claripy.BVS("file_content", 32)
    state = p.factory.full_init_state(args=[str(BINARY), "file", "/input.bin"])
    state.fs.insert("/input.bin", angr.SimFile("/input.bin", content=content, size=4, has_end=True))
    winner = search(p, state)
    candidate = winner.solver.eval(content, cast_to=bytes)
    with tempfile.TemporaryDirectory() as directory:
        filename = Path(directory) / "input.bin"
        filename.write_bytes(candidate)
        replay = subprocess.run([str(BINARY), "file", str(filename)], capture_output=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout == b"ACCEPT\n"
    return candidate

if __name__ == "__main__":
    print(repr(solve()))
```

### File: `examples/solve_function.py`

```python
"""Call one function under an explicit ABI contract; validate through main."""
import subprocess
import claripy
from common import BINARY, address, project

def solve():
    p = project()
    x = claripy.BVS("x", 32)
    # This sentinel is only a stopping address, never executed.
    stop = 0x70000000
    assert p.loader.find_object_containing(stop) is None
    state = p.factory.call_state(address(p, "transform"), x,
        prototype="unsigned int transform(unsigned int)", ret_addr=stop)
    manager = p.factory.simulation_manager(state)
    manager.explore(find=stop, n=40)
    assert manager.found and not manager.errored
    returned = manager.found[0]
    returned.solver.add(returned.regs.eax == 0x7f)
    candidate = returned.solver.eval_one(x)
    replay = subprocess.run([str(BINARY), "number", str(candidate)],
                            capture_output=True, text=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout.strip() == "127"
    return candidate

if __name__ == "__main__":
    print(solve())
```

### File: `examples/solve_hook.py`

```python
"""Replace a pure function with its exact fixed-width expression."""
import angr
import claripy
from common import BINARY, project, search

class CheckSummary(angr.SimProcedure):
    def run(self, pointer):
        data = self.state.memory.load(pointer, 4)
        return claripy.If(data == claripy.BVV(b"CAT!"), claripy.BVV(1, 32), claripy.BVV(0, 32))

def solve():
    p = project()
    p.hook_symbol("check", CheckSummary(prototype="int check(unsigned char *)"))
    data = claripy.BVS("token", 32)
    state = p.factory.full_init_state(args=[str(BINARY)],
        stdin=angr.SimFileStream(name="stdin", content=data, has_end=True))
    winner = search(p, state)
    return winner.solver.eval(data, cast_to=bytes)

if __name__ == "__main__":
    print(repr(solve()))
```

### File: `examples/solve_memory.py`

```python
"""Allocate a real buffer in the state before passing a pointer."""
import claripy
from common import address, project

def solve():
    p = project()
    base = p.factory.blank_state()
    pointer = base.heap.allocate(4)
    data = claripy.BVS("buffer", 32)
    base.memory.store(pointer, data)
    stop = 0x70000000
    state = p.factory.call_state(address(p, "check"), pointer,
        prototype="int check(unsigned char *)", base_state=base, ret_addr=stop)
    manager = p.factory.simulation_manager(state)
    manager.explore(find=stop, num_find=8, n=80)
    for returned in manager.found:
        if returned.solver.satisfiable(extra_constraints=(returned.regs.eax == 1,)):
            returned.solver.add(returned.regs.eax == 1)
            return returned.solver.eval(data, cast_to=bytes)
    raise RuntimeError("No accepting return found")

if __name__ == "__main__":
    print(repr(solve()))
```

### File: `examples/solve_stdin.py`

```python
"""Find a four-byte stdin witness and replay it on the original target."""
import subprocess
import angr
import claripy
from common import BINARY, project, search

def solve(binary=BINARY):
    p = project(binary)
    token = claripy.BVS("token", 4 * 8)
    stream = angr.SimFileStream(name="stdin", content=token, has_end=True)
    initial = p.factory.full_init_state(args=[str(binary)], stdin=stream)
    winner = search(p, initial)
    candidate = winner.solver.eval(token, cast_to=bytes)
    replay = subprocess.run([str(binary)], input=candidate, capture_output=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout == b"ACCEPT\n", replay
    return candidate

if __name__ == "__main__":
    print(repr(solve()))
```

### File: `examples/solver_basics.py`

```python
"""Bit widths, signedness, uniqueness, and consistent tuple evaluation."""
import claripy

def solve():
    x, y = claripy.BVS("x", 8), claripy.BVS("y", 8)
    solver = claripy.Solver()
    solver.add([x >= 1, x <= 9, y >= 1, y <= 9, x + y == 10])
    pairs = solver.batch_eval([x, y], 20)
    assert len(pairs) == 9 and all(a + b == 10 for a, b in pairs)
    assert claripy.is_true(claripy.BVV(255, 8) + 1 == 0)
    assert claripy.is_true(claripy.BVV(255, 8).SLT(0))
    assert not claripy.is_true(claripy.BVV(255, 8) < 0)
    return sorted(pairs)

if __name__ == "__main__":
    print(solve())
```

### File: `examples/state_plugin.py`

```python
"""A plugin that preserves a symbolic counter through copies and merges."""
import angr
import claripy

class Counter(angr.SimStatePlugin):
    def __init__(self, value=None):
        super().__init__()
        self.value = claripy.BVV(0, 32) if value is None else value

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return Counter(self.value)

    def merge(self, others, merge_conditions, common_ancestor=None):
        self.value = claripy.ite_cases(
            [(condition, other.value) for condition, other in zip(merge_conditions[1:], others)],
            self.value)
        return True

def demonstrate():
    project = angr.load_shellcode(b"\x90", arch="AMD64")
    state = project.factory.blank_state()
    state.register_plugin("counter", Counter())
    left, right = state.copy(), state.copy()
    left.counter.value += 1
    right.counter.value += 2
    merged, conditions, changed = left.merge(right)
    assert state.solver.eval_one(state.counter.value) == 0
    assert changed and len(conditions) == 2
    return sorted(merged.solver.eval_upto(merged.counter.value, 3))

if __name__ == "__main__":
    print(demonstrate())
```

### File: `tests/test_labs.py`

```python
"""Behavioral validation: solve constraints, execute targets, inspect results."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
import pytest
import solve_stdin, solve_argv, solve_function, solve_memory, solve_file, solve_hook
import solver_basics, state_plugin, inspect_writes, analyze_cfg, bounded_search

@pytest.mark.parametrize("name", ["targets", "targets-pie"])
def test_stdin_replays_on_native_binary(name):
    assert solve_stdin.solve(ROOT / "build" / name) == b"CAT!"

@pytest.mark.parametrize("module", [solve_argv, solve_memory, solve_file, solve_hook])
def test_input_models_replay(module):
    candidate = module.solve()
    assert candidate == b"CAT!"
    replay = subprocess.run([str(ROOT / "build/targets")], input=candidate,
                            capture_output=True, timeout=5)
    assert replay.returncode == 0 and replay.stdout == b"ACCEPT\n"

def test_function_return_contract():
    assert solve_function.solve() == 14

def test_solver_pairs():
    assert solver_basics.solve() == [(x, 10-x) for x in range(1, 10)]

def test_copy_and_merge():
    assert state_plugin.demonstrate() == [1, 2]

def test_inspection_callback_fires():
    assert inspect_writes.observe() > 0

def test_cfg_and_decompiler():
    result = analyze_cfg.analyze()
    assert result["functions"] > 3 and result["blocks"] > 1
    assert "check" in result["code"] and "return" in result["code"]

def test_bounded_loop():
    assert bounded_search.solve() == [4]

def test_rejection_is_real():
    result = subprocess.run([str(ROOT / "build/targets")], input=b"DOG!", capture_output=True, timeout=5)
    assert result.returncode == 1 and result.stdout == b"REJECT\n"

def test_reaching_definitions_observations():
    import analyze_dataflow
    result = analyze_dataflow.analyze()
    assert result["observations"] >= 1
    assert result["definitions"] > 0 and result["dependencies"] > 0

def test_custom_analysis_counts_code():
    import custom_analysis
    assert custom_analysis.analyze() > 0

def test_ir_and_disassembly():
    from common import address, project
    p = project()
    block = p.factory.block(address(p, "transform"))
    assert block.size > 0 and block.capstone.insns
    assert block.vex.statements and block.vex.jumpkind
```

## License and attribution

Original guide prose, C target, and example scripts are covered by the project's
BSD-2-Clause license reproduced below. The official appendix retains the angr
Project contributors' authorship and BSD license, also reproduced below. The
upstream narrative snapshot is angr v9.3.4 commit
`a2ac48c21de430358a0a5e02ac3867148b27e620`.

### Original material license

```text
BSD 2-Clause License

Copyright (c) 2026, angr, explained contributors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### Official angr documentation license

```text
Copyright (c) 2017, The Arizona Board of Regents
Copyright (c) 2022, Emotion Labs, LLC
Copyright (c) 2023, Microsoft Corporation
Copyright (c) 2015, The Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
