# Z3 documentation for AI-assisted analysis

## Summary — read this first

**Z3** is an SMT (satisfiability modulo theories) solver. The Python distribution
is **`z3-solver`**, imported as **`z3`**; its Python interface is called **Z3Py**.
Use it to construct typed symbolic expressions, assert constraints, ask whether
those constraints can hold together, and extract a witness or prove that no
witness exists. Z3 does not load binaries, execute instructions, or infer the
semantics of a Python function. You must encode those semantics or use a frontend
such as angr. See also [the angr reference](angr-doc.md#s06).

This reference targets ReversEnv's **`z3-solver==5.1.0.0`** dependency. Examples
were tested with **CPython 3.12.14, Z3 5.1.0, Linux x86-64** in a clean environment.
See [validation and reproduction](#s22) for the exact scope and environment caveat.
Use the task table to retrieve a small section; do not load the whole reference
when a single API contract or recipe answers the question.

**Normal workflow:** choose sorts → declare inputs → encode operations and input
domain → `Solver().add(...)` → `check()` → handle `sat` / `unsat` / `unknown` →
evaluate all related outputs in one model → replay or independently verify.

**Essential rules:**

1. `Int` and `Real` are mathematical values. Use `BitVec(name, bits)` for
   fixed-width machine arithmetic and `FP` for IEEE floating point.
2. Z3 bitvectors have no stored signedness. `<`, `<=`, `>`, `>=`, `/`, `%`, and
   `>>` select signed operations; use explicit unsigned operators as needed.
   **Claripy comparisons default to unsigned; Z3Py comparisons do not.**
3. Symbolic expressions are not Python values. Build `And`, `Or`, `Not`, and
   `If`; do not use Python `and`, `or`, `not`, chained comparisons, or `if expr`.
4. Declare one symbol per logical input and reuse it. Same name + sort + context
   denotes the same Z3 constant; declarations are not automatically fresh.
5. `sat` means a witness exists for the encoded formula. `unsat` means none
   exists for that formula. `unknown`, timeouts, and bounded search exhaustion
   are not proofs of impossibility in the actual program.
6. Call `model()` only after a successful `sat` check for the current query.
   A model is one assignment, not a uniqueness guarantee. Model completion fills
   missing values arbitrarily; it does not discover additional facts.
7. Prove `P` under assumptions `A` by checking `A ∧ Not(P)` for `unsat`.
   Check that `A` is itself satisfiable to detect a vacuous proof.
8. State widths, signedness, overflow, endianness, valid memory, division guards,
   environment assumptions, and solver budgets. Z3 does not supply CPU traps,
   language undefined behavior, or memory safety automatically.
9. Enumerate correlated inputs from one model and block the whole tuple.
   Enumerate only a finite projection or impose a limit and report incompleteness.
10. Record package version, assertions, parameters, result, and replay outcome.
    Diagnose a wrong encoding before tuning the solver.

## Task index — retrieve only what you need

| Task or question | Start here | Related section |
| --- | --- | --- |
| Install, check version, fix `import z3` | [S01 Installation](#s01) | [S21 Troubleshooting](#s21) |
| Solve a first constraint | [S02 Quick start](#s02) | [S07 Solver API](#s07) |
| Choose a type; understand ASTs and symbols | [S03 Object model](#s03) | [S04 Boolean expressions](#s04) |
| Integers, rationals, division | [S05 Arithmetic](#s05) | [S19 Performance](#s19) |
| Registers, overflow, shifts, casts | [S06 Bitvectors](#s06) | [S17 Reverse-engineering example](#s17) |
| Understand `sat`, `unsat`, `unknown`, timeout | [S07 Solver API](#s07) | [S21 Troubleshooting](#s21) |
| Evaluate a model; extract bytes; prove uniqueness | [S08 Models](#s08) | [S17 Reverse-engineering example](#s17) |
| Branch temporarily, explain a contradiction | [S09 Scopes and cores](#s09) | [S07 Solver API](#s07) |
| Prove an identity or enumerate inputs | [S10 Proof and enumeration](#s10) | [S18 Bounded execution](#s18) |
| Memory, byte order, symbolic addresses | [S11 Arrays and memory](#s11) | [S06 Bitvectors](#s06) |
| Unknown functions, enums, records, lists | [S12 Functions and datatypes](#s12) | [S13 Quantifiers](#s13) |
| `ForAll`, `Exists`, triggers, F* proof queries | [S13 Quantifiers](#s13) | [S19 Internals](#s19) |
| Text, sequences, regex; IEEE floats | [S14 Strings and floating point](#s14) | [S03 Sorts](#s03) |
| Minimize, maximize, soft constraints | [S15 Optimization](#s15) | [S07 Check results](#s07) |
| Simplify, inspect ASTs, tactics, SMT-LIB | [S16 Inspection and interchange](#s16) | [S20 Contexts](#s20) |
| Threads, contexts, proof objects, Horn clauses | [S20 Specialist APIs](#s20) | [S19 Internals](#s19) |
| Reproduce tests, find sources and coverage limits | [S22 Validation](#s22) | [S23 Sources and glossary](#s23) |

### Readiness labels and result record

- **Runnable example:** a complete `python` fence; run independently with
  `z3-solver` installed. Assertions check behavior; silent completion is success.
- **Fragment/recipe:** requires the named surrounding objects or real target;
  it is guidance rather than a standalone tested script.
- **Console recipe:** installation or diagnostic commands; paths may need adapting.

Before analysis, record input domains, target semantics, success predicate,
assumptions, and bounds. After analysis, record the three-way solver result,
`reason_unknown()` if applicable, witness or contradiction, and replay outcome.
Native replay is required before claiming a generated input works on a real
binary. The examples here use small independent Python checks, not a supplied
native executable.

<a id="s01"></a>

## [S01] Installation and version checks

Use the distribution named `z3-solver`, not an unrelated package named `z3`.
For documentation experiments, an isolated environment avoids changing angr's
solver dependency. ReversEnv's pin is in `requirements.txt`; do not upgrade only
its solver package without checking the rest of the analysis stack.

**Console recipe** (run from ReversEnv; use a new environment path):

```console
python3.12 -m venv /tmp/reversenv-z3-guide
/tmp/reversenv-z3-guide/bin/python -m pip install z3-solver==5.1.0.0
/tmp/reversenv-z3-guide/bin/python -c "import z3; from importlib.metadata import version; print(version('z3-solver')); print(z3.get_version_string()); print(z3.__file__)"
```

Expected versions for this edition: distribution `5.1.0.0`, library `5.1.0`.
`get_version()` returns a tuple; `get_full_version()` gives a build/version string.
Use the same interpreter for installing and running. Avoid a local `z3.py` or
`z3/` directory that shadows the package. If metadata exists but `z3.Solver` does
not, inspect `z3.__file__` and verify a clean installation before trusting it.

Source: [official Z3 repository and installation instructions](https://github.com/Z3Prover/z3).

<a id="s02"></a>

## [S02] Quick start: solve and verify a byte

**Runnable example:** recover an eight-bit input whose wrapped addition is 42.

```python
import z3

x = z3.BitVec("input_byte", 8)
s = z3.Solver()
s.set(timeout=5000)  # milliseconds per solver check
s.add(z3.UGE(x, 0x20), z3.ULE(x, 0x7e), x + 1 == 42)
result = s.check()
if result == z3.sat:
    value = s.model().eval(x).as_long()
    assert value == 41
    assert (value + 1) & 0xff == 42
elif result == z3.unsat:
    raise AssertionError("No byte meets the encoded constraints")
else:
    raise RuntimeError(s.reason_unknown())
```

`x + 1 == 42` builds a formula; `add` asserts it; `check` performs search.
`as_long()` converts a concrete numeral, not an arbitrary symbolic expression.
The asserted result is deterministic here because the constraints fix `x`.

<a id="s03"></a>

## [S03] Object model, sorts, and symbol identity

| Object/API | Meaning and principal contract |
| --- | --- |
| `Context()` | Owns Z3 objects; expressions from different contexts cannot be mixed directly. Default constructors use a shared main context. |
| `BoolSort()`, `IntSort()`, `BitVecSort(n)` | Sort descriptors; bitvector `n` is a positive width in bits. |
| `Const(name, sort)` | Creates a symbolic constant of that sort, not an initialized mutable cell. |
| `Bool(name)`, `Int(name)`, `Real(name)`, `BitVec(name, n)` | Convenience constant constructors; optional `ctx` selects a context. |
| `BoolVal(v)`, `IntVal(v)`, `RealVal(v)`, `BitVecVal(v, n)` | Concrete symbolic literals. Use strings for exact decimal/rational input. Bitvector numerals reduce modulo `2**n`. |
| `ExprRef`, `BoolRef`, `ArithRef`, `BitVecRef` | Python wrappers around immutable expression ASTs. Operators construct further ASTs. |
| `Solver()` / `ModelRef` | Mutable assertion/search state / interpretation returned after a satisfiable query. |
| `FreshConst(sort, prefix="c")` | Creates a new symbol even when the prefix is reused. |

Choose `Bool` for conditions; `Int` for counts without wraparound; `Real` for
exact mathematics; `BitVec` for words/bytes; `Array` for indexed maps; `String`
for text; `FP` for IEEE values; a datatype for a structured value. Z3 sort
checking is not the source language's type checker.

Within one context, two `Int("x")` calls denote the same constant. A Python
assignment such as `x = x + 1` rebinds the Python name; it does not mutate the
previous AST or assert a state transition. Use `x0`, `x1`, and `x1 == x0 + 1`
when separate states are needed. Do not use the same textual name across sorts
in generated scripts; even when representable, it complicates interchange.

**Runnable example:** distinguish AST identity from logical equivalence.

```python
import z3

x = z3.Int("x")
assert z3.eq(x, z3.Int("x"))
assert not z3.eq(x + 0, x)  # structural comparison, not a theorem check
assert z3.eq(z3.simplify(x + 0), x)
assert (x + 1).sort() == z3.IntSort()
```

`eq(a, b)` returns a Python Boolean for structural equality. `a == b` normally
builds a symbolic equality. `is_true(e)` recognizes the literal true AST; it
does not ask whether current solver assertions imply `e`.

<a id="s04"></a>

## [S04] Boolean formulas and Python boundaries

| Intent | Z3Py expression | Contract / mistake to avoid |
| --- | --- | --- |
| All / any constraints | `And(*terms)` / `Or(*terms)` | Boolean terms; zero arguments mean true / false respectively. |
| Negate / imply | `Not(p)` / `Implies(p, q)` | Python `not p` attempts a host Boolean conversion. |
| Exclusive or / equivalence | `Xor(p, q)` / `p == q` | Boolean equality is equivalence. |
| Symbolic conditional | `If(p, a, b)` | Branches must have compatible sorts; both AST branches are constructed. |
| Interval | `And(x >= lo, x <= hi)` | `lo <= x <= hi` is a Python chained comparison and is wrong here. |
| All pairwise unequal | `Distinct(*xs)` | A Boolean constraint, not an instruction that generates unique variables. |
| At most / at least k true | `AtMost(*ps, k)` / `AtLeast(*ps, k)` | `ps` are Boolean expressions and `k` a concrete integer. |
| Weighted Boolean sum | `PbEq([(p, 2), (q, 1)], 2)` | Integer coefficients; `PbLe` and `PbGe` express bounds. |

Parenthesize each comparison when composing formulas. Never rely on symbolic
truth conversion: some equalities can convert using structural checks, producing
silent Python control-flow mistakes instead of an exception.

**Runnable example:** a symbolic absolute value and a branch-feasibility check.

```python
import z3

x = z3.Int("x")
absolute = z3.If(x >= 0, x, -x)
s = z3.Solver()
s.add(absolute == 7)
assert s.check(x < 0) == z3.sat  # temporary assumption
assert s.model().eval(x).as_long() == -7
assert s.check(x > 0) == z3.sat  # previous assumption is gone
assert s.model().eval(x).as_long() == 7
```

A Python loop over a known `range(n)` is fine: it builds finitely many formulas.
A Python loop controlled by a symbolic condition is not symbolic execution.

<a id="s05"></a>

## [S05] Integer and real arithmetic

`Int` is unbounded and `Real` is exact; neither overflows. `+`, `-`, `*`, `/`,
comparisons, `Sum(*xs)`, and `Abs(x)` construct terms. `ToReal(i)` embeds an
integer. `ToInt(r)` floors a real, including negative values; `IsInt(r)` asks
whether its value is integral. Mixed integer/real arithmetic can introduce
coercions; inspect `.sort()` when unsure.

For integer expressions, `/` is integer division and `%` is modulus. With a
nonzero divisor, Euclidean modulus is nonnegative and smaller than the divisor's
absolute value. These are not C's truncation/remainder rules for negative
operands. For reals, `/` is exact division. Arithmetic division by zero is total
but under-specified in the logic; add a nonzero guard or explicitly model the
program's error behavior. Do not infer a runtime exception from the SMT term.

Use `RealVal("0.1")` or `RealVal("1/10")` for exact constants. Python computes
`1 / 3` before Z3 sees it. The resulting host float is not the exact rational
one third. `RealVal(1) / 3` stays symbolic and exact.

**Runnable example:** check rational and signed-division semantics.

```python
import z3

third = z3.simplify(z3.RealVal(1) / 3)
assert third.numerator_as_long() == 1
assert third.denominator_as_long() == 3
assert z3.simplify(z3.IntVal(-5) / 2).as_long() == -3
assert z3.simplify(z3.IntVal(-5) % 2).as_long() == 1
assert z3.simplify(z3.ToInt(z3.RealVal("-1.2"))).as_long() == -2
```

`RatNumRef` supports numerator/denominator extraction. `as_decimal(precision)`
can print a trailing `?` for a truncated decimal; it is not an exact serialization.
Nonlinear real solutions can contain `AlgebraicNumRef` values such as square
roots, which are not rationals. Keep exact ASTs for comparisons. Nonlinear
integer arithmetic has no general terminating decision procedure; add budgets
and handle `unknown`.

<a id="s06"></a>

## [S06] Bitvectors: machine arithmetic, signedness, and casts

An `n`-bit value is a bit pattern. Addition, subtraction, multiplication, and
bitwise operations keep width `n` and wrap modulo `2**n`. Operands normally need
matching widths. Python integers are coerced to that width: `BitVecVal(256, 8)`
is zero. This is a frequent cause of accidentally impossible range constraints.

| Operation | Signed interpretation | Unsigned interpretation / notes |
| --- | --- | --- |
| Compare | `a < b`, `a <= b`, `a > b`, `a >= b` | `ULT`, `ULE`, `UGT`, `UGE` |
| Divide | `a / b` | `UDiv(a, b)` |
| Remainder | `SRem(a, b)` follows dividend's sign | `URem(a, b)` |
| Modulus | `a % b` uses signed modulus, tied to divisor's sign | Use `URem` for unsigned modulus |
| Right shift | `a >> count` fills with sign bit | `LShR(a, count)` fills with zero |
| Left shift | `a << count` | Low bits retained; high bits discarded |
| Bitwise | `a & b`, `a \| b`, `a ^ b`, `~a` | Same bit operation regardless of interpretation |
| Extend | `SignExt(extra_bits, a)` | `ZeroExt(extra_bits, a)`; argument is added width, not final width |
| Convert to Int | `BV2Int(a, is_signed=True)` | `BV2Int(a)` defaults to unsigned |
| Rotate | `RotateLeft(a, count)`, `RotateRight(a, count)` | Preserves width; rotation is different from shift |

`Extract(high, low, a)` selects inclusive bit indices, counting from least
significant bit zero, and returns width `high - low + 1`.
`Concat(a, b, ...)` places the first argument at the most significant end.
`Int2BV(integer_expr, width)` reduces modulo `2**width`; it is not a proof that
the integer was in range. Mixed Int/BitVec encodings may be more expensive than
staying in a single theory.

**Runnable example:** edge cases that distinguish these operations.

```python
import z3

ff = z3.BitVecVal(255, 8)
assert z3.simplify(ff + 1).as_long() == 0
assert z3.is_true(z3.simplify(ff < 0))
assert z3.is_false(z3.simplify(z3.ULT(ff, 0)))
assert z3.simplify(ff >> 1).as_long() == 255
assert z3.simplify(z3.LShR(ff, 1)).as_long() == 127
assert z3.simplify(z3.SignExt(8, ff)).as_long() == 65535
assert z3.simplify(z3.ZeroExt(8, ff)).as_long() == 255
assert z3.simplify(z3.BV2Int(ff, is_signed=True)).as_long() == -1
minus_five, two = z3.BitVecVal(-5, 8), z3.BitVecVal(2, 8)
assert z3.simplify(minus_five / two).as_signed_long() == -2
assert z3.simplify(z3.SRem(minus_five, two)).as_signed_long() == -1
assert z3.simplify(minus_five % two).as_signed_long() == 1
```

### Model the instruction or language, not just the bit width

SMT bitvector shifts do not automatically mask counts as some CPUs do. For
example, an x86 32-bit shift's masked count needs a corresponding mask in the
encoding. Account for instruction-specific flag and exceptional behavior.
Bitvector division has defined zero-divisor semantics, not a CPU divide fault;
signed minimum divided by minus one also needs explicit handling when the target
traps. Add guards or encode the exceptional branch.

C integer promotions can widen byte operands before arithmetic. Signed C
overflow can be undefined, while an executed machine add wraps. Decide whether
you are modeling source-language defined executions or actual instructions.
For an unsigned carry, widen operands by one bit before adding and inspect the
high bit. An `n`-bit sum alone has already lost the carry.

**Fragment/recipe:** for two equally wide bitvectors `a` and `b`, let
`wide = ZeroExt(1, a) + ZeroExt(1, b)` and
`carry = Extract(a.size(), a.size(), wide) == 1`. Supply the correct operands
and instruction semantics; this does not model every arithmetic flag.

<a id="s07"></a>

## [S07] Solver API and three-way results

These are common public call forms; optional internal constructor arguments are
omitted. `Solver()` is a good starting point. `SolverFor("QF_BV")` selects a
logic-specific configuration; choose it only when the formula fits that logic.
`QF` means quantifier-free; `BV`, `LIA`, `LRA`, and `NRA` denote bitvectors,
linear integer arithmetic, linear real arithmetic, and nonlinear real arithmetic.

| Call | Parameters, result, and state effects |
| --- | --- |
| `Solver(ctx=None)` | New solver with no assertions, in the chosen/default context. |
| `s.add(*constraints)` | Boolean expressions (also accepts a list); adds persistent assertions; returns `None`. Does not solve. |
| `s.check(*assumptions)` | Checks persistent assertions plus temporary Boolean assumptions; returns `CheckSatResult`: compare with `sat`, `unsat`, `unknown`. |
| `s.model()` | Returns `ModelRef` for the last successful query. Use only after `sat`; otherwise may raise `Z3Exception` or offer no justified witness. |
| `s.set(timeout=5000)` | Per-solver timeout in milliseconds; zero means no timeout. Settings are not asserted formulas. |
| `s.set(rlimit=...)` | Internal resource budget, not milliseconds; work units depend on version and solver behavior. |
| `s.reason_unknown()` | Diagnostic string after `unknown`; do not match exact wording as a stable interface. |
| `s.assertions()` | Current assertions as an `AstVector`; assumptions passed to `check` are not persistent assertions. |
| `s.push()` / `s.pop(n=1)` | Save an assertion scope / discard the last `n` scopes and their additions. Popping too far is an error. |
| `s.reset()` | Removes assertions and scopes; reapply intended settings explicitly when reusing it. |
| `s.statistics()` | Last-check statistics; keys depend on the engine/version. |
| `s.to_smt2()` / `s.sexpr()` | Text representations useful for recording/debugging; see [S16](#s16). |
| `s.help()` / `s.param_descrs()` | Available parameter descriptions; `help()` prints them. Unsupported settings can fail when set or when solving starts. |

After adding constraints or changing scopes, call `check()` again before using
results. A saved old model remains a model of its old query; it need not satisfy
the new one. Solver settings and assertion scopes are different things; do not
expect `pop()` to undo parameter changes.

| Result | Valid conclusion | Next action |
| --- | --- | --- |
| `sat` | At least one model satisfies this query. | Extract correlated values and validate the encoding/replay. |
| `unsat` | No model satisfies all assertions and current assumptions. | Inspect an unsat core or use the result as a proof under stated assumptions. |
| `unknown` | The solver did not establish either result. | Record `reason_unknown()`, budget and formula; simplify or revise strategy. |

Do not use `if s.check():`, compare with strings, or catch every exception and
label it `unsat`. A sort error is a modeling/programming error; a library-loading
failure is an environment error. For an overall wall-clock limit, also bound the
host process: the solver timeout does not budget all Python encoding, parsing,
model extraction, or a sequence of many checks.

<a id="s08"></a>

## [S08] Models, concrete values, and uniqueness

`m.eval(expr, model_completion=False)` (alias `evaluate`) evaluates an expression
in a `ModelRef` and returns a Z3 expression. With default completion disabled,
an unconstrained symbol can remain symbolic. With completion enabled, Z3 adds
interpretations as needed to this model; those choices are arbitrary and may
mutate its displayed contents.

| Value | Conversion after evaluation |
| --- | --- |
| Integer numeral | `.as_long()` → Python integer |
| Bitvector numeral | `.as_long()` → unsigned integer; `.as_signed_long()` → two's-complement signed integer |
| Boolean literal | `is_true(value)` / `is_false(value)`; reject a residual symbolic value |
| Rational numeral | `.numerator_as_long()` and `.denominator_as_long()` |
| String literal | `.as_string()` → Python string, not raw input bytes |
| Array / function | Evaluate selected applications; inspect the interpretation only when necessary |

`m[x]` retrieves a declared constant's interpretation and can be `None` if
unconstrained. Prefer `eval` for compound expressions. A displayed assignment
is neither a canonical result nor evidence of uniqueness. To prove a projected
value is unique, add `expr != value` temporarily and require `unsat`.

**Runnable example:** complete an unconstrained value and test uniqueness.

```python
import z3

x, unused = z3.Ints("x unused")
s = z3.Solver()
s.add(x == 12)
assert s.check() == z3.sat
m = s.model()
v = m.eval(x)
assert v.as_long() == 12
assert z3.is_int_value(m.eval(unused, model_completion=True))
s.push()
s.add(x != v)
assert s.check() == z3.unsat
s.pop()
assert s.check(unused != 0) == z3.sat  # completion did not constrain the solver
```

Extract every byte of a candidate from the same model. Calling separate solvers
for different bytes can produce mutually inconsistent choices. Preserve bytes
exactly, including zero and newline bytes; lossy decoding or stripping changes
the candidate. See [the complete byte example](#s17).

<a id="s09"></a>

## [S09] Incremental queries, assumptions, and unsat cores

Use `push`/`pop` for temporary assertions. Pair them with `try`/`finally` in
application code so exceptions do not leak scopes. Use `check(*assumptions)` for
short-lived conditions, often fresh Boolean activation literals. The returned
model or core is for that specific check, including its assumptions.

`assert_and_track(constraint, label)` asserts a formula and attaches a Boolean
constant (or string name) for core reporting. Use fresh, unique labels and keep
a label-to-source map. Tracking labels are not switches for disabling formulas;
use `Implies(label, formula)` plus explicit check assumptions for that purpose.

`unsat_core()` returns an `AstVector` of relevant labels/assumptions after
`unsat`. It explains inconsistency relative to all untracked background
assertions. It need not contain every cause, be minimal, or be a proof object.
An empty core can mean the background is already inconsistent.

**Runnable example:** obtain a core and independently recheck its formulas.

```python
import z3

x = z3.Int("x")
rules = {"positive": x > 0, "negative": x < 0, "ceiling": x < 100}
s = z3.Solver()
for label, formula in rules.items():
    s.assert_and_track(formula, label)
assert s.check() == z3.unsat
names = {str(label) for label in s.unsat_core()}
assert {"positive", "negative"} <= names
recheck = z3.Solver()
recheck.add(*[rules[name] for name in names])
assert recheck.check() == z3.unsat
```

**Runnable example:** optional constraints activated per query.

```python
import z3

x = z3.Int("x")
low, high = z3.Bools("enable_low enable_high")
s = z3.Solver()
s.add(z3.Implies(low, x < 2), z3.Implies(high, x > 5))
assert s.check(low, high) == z3.unsat
assert s.check(low, z3.Not(high)) == z3.sat
assert s.model().eval(x).as_long() < 2
```

Omitting an activation literal leaves it unconstrained; it does not force it
false. Supply `Not(label)` when disabling it is itself part of the query.

<a id="s10"></a>

## [S10] Proving properties and enumerating projected models

A satisfiability query asks for an assignment. A validity query asks whether a
property holds for every assignment satisfying the assumptions. Negate the
property and look for a counterexample. `unsat` proves the property only for
the model you encoded; inconsistent assumptions prove everything vacuously.

**Runnable example:** prove a wrapped arithmetic identity.

```python
import z3

x = z3.BitVec("x", 16)
s = z3.Solver()
assert s.check() == z3.sat  # assumptions are consistent
s.add(z3.Not((x + 1) - 1 == x))
assert s.check() == z3.unsat
```

`z3.prove(...)` and `z3.solve(...)` are useful interactive printing helpers.
Use an explicit `Solver` and result handling for agent automation.

To enumerate a projection `[x, y]`, extract both values from one model and add
`Or(x != vx, y != vy)`. This excludes that pair and preserves pairs differing
in either component. Adding both inequalities separately discards valid pairs.
Projection avoids enumerating irrelevant internal symbols and function models.

**Runnable example:** enumerate a finite domain with an explicit bound.

```python
import z3

x, y = z3.Ints("x y")
s = z3.Solver()
s.set(timeout=5000)
s.add(x >= 0, x <= 3, y >= 0, y <= 3, x + y == 3)
seen = set()
limit = 10
complete = False
for _ in range(limit):
    result = s.check()
    if result == z3.unsat:
        complete = True
        break
    if result == z3.unknown:
        raise RuntimeError(s.reason_unknown())
    m = s.model()
    vx, vy = m.eval(x), m.eval(y)
    seen.add((vx.as_long(), vy.as_long()))
    s.add(z3.Or(x != vx, y != vy))
assert complete  # only final UNSAT establishes exhaustion
assert seen == {(0, 3), (1, 2), (2, 1), (3, 0)}
```

If the loop hits its limit, report a partial enumeration even if the last model
happened to be the final one. Unbounded integers, reals, arrays, and functions
usually make full-model enumeration inappropriate.

<a id="s11"></a>

## [S11] Arrays, symbolic memory, and byte order

`Array(name, index_sort, value_sort)` creates a total mathematical map.
`Select(a, i)` (or `a[i]`) reads it. `Store(a, i, v)` returns a new array term
with that entry changed; it does not mutate `a`. `K(index_sort, value)` creates
a constant array. Array equality is extensional: all corresponding entries
must agree. An array has no implicit allocation size or invalid addresses.

For byte-addressed memory, use an address bitvector sort and eight-bit values.
Constrain valid addresses, initialized regions, aliasing, and faults yourself.
A fresh unconstrained array gives unconstrained contents; `K(..., 0)` instead
asserts that every entry starts at zero, a stronger modeling assumption.

**Runnable example:** store and load a little-endian 32-bit word.

```python
import z3

memory = z3.Array("memory", z3.BitVecSort(64), z3.BitVecSort(8))
address = z3.BitVecVal(0x1000, 64)
word = z3.BitVec("word", 32)
updated = memory
for offset in range(4):
    byte = z3.Extract(8 * offset + 7, 8 * offset, word)
    updated = z3.Store(updated, address + offset, byte)
loaded = z3.Concat(*[z3.Select(updated, address + i) for i in (3, 2, 1, 0)])
s = z3.Solver()
s.add(loaded != word)
assert s.check() == z3.unsat
s.reset()
s.add(word == 0x12345678)
assert s.check() == z3.sat
m = s.model()
raw = bytes(m.eval(z3.Select(updated, address + i)).as_long() for i in range(4))
assert raw == b"\x78\x56\x34\x12"
```

The addresses here are fixed, distinct, and do not wrap. A symbolic pointer near
the address-space boundary needs extra constraints. For a small fixed input
buffer, a Python list of byte variables is often simpler than an SMT array;
symbolic list indices require a different encoding (`If` selection or an array).

<a id="s12"></a>

## [S12] Uninterpreted functions and algebraic datatypes

`Function(name, domain_sort, ..., range_sort)` declares a total uninterpreted
function. Equal arguments imply equal results, but there is no other behavior
until constrained. It is not an arbitrary fresh return value per call and does
not execute Python. `DeclareSort(name)` declares an uninterpreted, nonempty sort;
it does not impose a finite cardinality.

For an unknown pure function, an uninterpreted function may be a useful
abstraction. For stateful behavior, include the relevant state in its arguments
or model state transitions explicitly. Omitting behavior can admit spurious
witnesses. Replay concrete candidates and refine the model as necessary.

**Runnable example:** congruence forces equal outputs for equal inputs.

```python
import z3

f = z3.Function("f", z3.IntSort(), z3.IntSort())
x, y = z3.Ints("x y")
s = z3.Solver()
s.add(x == y, f(x) != f(y))
assert s.check() == z3.unsat
```

`EnumSort(name, names)` returns a finite sort and its distinct constructors.
`Datatype(name)` starts a datatype declaration; `declare` adds constructors and
fields; `create()` finalizes it. Constructors are disjoint and injective;
recognizers test the constructor. Accessors applied to the wrong constructor
are under-specified, so guard their use. For mutually recursive datatypes use
`CreateDatatypes(...)` after declaring all types.

**Runnable example:** a tagged optional integer.

```python
import z3

Maybe = z3.Datatype("MaybeInt")
Maybe.declare("missing")
Maybe.declare("present", ("value", z3.IntSort()))
Maybe = Maybe.create()
v = z3.Const("v", Maybe)
s = z3.Solver()
s.add(Maybe.is_present(v), Maybe.value(v) == 9)
assert s.check() == z3.sat
assert z3.is_true(s.model().eval(v == Maybe.present(9)))
```

Recursive datatypes describe finite constructor trees. Recursive functions are
separate: `RecFunction(...)` declares one and `RecAddDefinition(f, args, body)`
supplies its equation. Recursion does not give automatic induction or guarantee
termination of all queries. Use bounded unfolding or a dedicated proof strategy.

<a id="s13"></a>

## [S13] Quantifiers, triggers, and verification conditions

`ForAll([x, ...], body)` and `Exists([x, ...], body)` bind the listed constants in
the body. Free constants in a satisfiability query are already existentially
chosen, so `Exists` is often unnecessary for ordinary input recovery. Quantifier
order matters: `ForAll(x, Exists(y, ...))` lets `y` depend on `x`; reversing the
order asks for one `y` that works for every `x`.

`ForAll(..., patterns=[f(x)])` supplies a trigger for instantiation; `qid="name"`
labels a quantifier for diagnostics. Patterns must cover bound variables (a
`MultiPattern` can cover them jointly) and use suitable applications. They do
not alter the intended formula, but they can drastically change whether search
finishes. Poor patterns can prevent useful instantiations or generate endless
new matching terms.

**Runnable example:** instantiate a simple quantified function axiom.

```python
import z3

x = z3.Int("x")
f = z3.Function("successor", z3.IntSort(), z3.IntSort())
s = z3.Solver()
s.set(timeout=5000)
s.add(z3.ForAll([x], f(x) == x + 1, patterns=[f(x)], qid="successor_rule"))
s.add(f(8) != 9)
assert s.check() == z3.unsat
```

For a small, known finite range, instantiate a Python loop over that range
instead of quantifying over all integers. This is equivalent only if the intended
domain really is that finite range. E-matching uses ground terms and equality
information to instantiate patterns; model-based quantifier instantiation seeks
instances that refute candidate models. Neither makes arbitrary quantified
problems reliably decidable. See [Z3 Internals, quantifiers](https://z3prover.github.io/papers/z3internals.html).

### Reading a verification frontend's query

A frontend such as F* translates source obligations into SMT assertions. The
SMT-LIB `assert` command assumes a formula; it does not check a source-language
assertion. To validate a source assertion, the frontend typically asserts the
assumptions and negated obligation, then expects `unsat`. Its encoding may add
uninterpreted symbols, axioms, triggers, and unfolding limits. Inspect the actual
query before treating a timeout or a model as a source-level failure. F*'s fuel
settings belong to its encoding and are not a generic Z3Py recursion option.
See [Understanding how F* uses Z3](https://fstar-lang.org/tutorial/book/under_the_hood/uth_smt.html#understanding-how-f-uses-z3).

<a id="s14"></a>

## [S14] Strings, sequences, regular expressions, and floating point

### Text versus bytes

`String(name)` is SMT text, not a byte buffer or a C string. `StringVal(text)`
constructs a literal. `Length`, `Concat`, `SubString(s, offset, length)`,
`Contains`, `PrefixOf(prefix, s)`, `SuffixOf(suffix, s)`, and
`IndexOf(s, needle, offset)` construct string constraints. `IndexOf` returns an
integer expression, with minus one for no occurrence. `SubString`'s third
argument is a length, not a Python slice endpoint.

`Re(text)` constructs a literal regular expression, not a Python regex parser.
Use `Range`, `Union`, `Concat`, `Star`, `Plus`, and `InRe` to build regex formulas.
`SeqSort(element_sort)`, `Unit(element)`, and `Empty(sequence_sort)` generalize
sequences beyond characters. Do not assume their layout models machine memory.

**Runnable example:** constrain a short text value.

```python
import z3

text = z3.String("text")
s = z3.Solver()
s.set(timeout=5000)
s.add(z3.Length(text) == 4, z3.PrefixOf("AB", text), z3.SuffixOf("12", text))
assert s.check() == z3.sat
assert s.model().eval(text).as_string() == "AB12"
```

Use eight-bit bitvectors for arbitrary binary input, explicit byte encodings,
embedded NULs, and bytewise arithmetic. Model UTF-8 encoding and C termination
separately if they affect the target.

### IEEE floating point

`FP(name, Float32())` and `FP(name, Float64())` create IEEE-format values.
`FPSort(exponent_bits, significand_bits)` includes the hidden significand bit.
Use `fpAdd(rm, a, b)`, `fpSub`, `fpMul`, and `fpDiv` with explicit rounding:
`RNE()` (nearest, ties to even), `RNA()`, `RTP()`, `RTN()`, or `RTZ()`.

`fpEQ(a, b)` models IEEE equality: NaN is unequal to itself and signed zeros
compare equal. Z3 term equality `a == b` instead expresses logical equality,
which is reflexive and distinguishes the signed zeros. Use `fpIsNaN`, `fpIsInf`,
`fpIsZero`, and `fpIsNegative` for classification.

`fpBVToFP(bits, sort)` reinterprets an IEEE bit pattern; `fpToIEEEBV(value)`
returns an encoding (NaN payloads are not preserved as distinct FP values).
Numeric conversion is different: `fpToFP(rm, signed_bv, sort)` or
`fpToFPUnsigned(rm, unsigned_bv, sort)`. Z3's FP theory does not automatically
model CPU exception flags, flush-to-zero modes, or every NaN payload rule.

**Runnable example:** compare signed zero and reinterpret the bits for 1.0.

```python
import z3

positive = z3.FPVal(0.0, z3.Float32())
negative = z3.fpMinusZero(z3.Float32())
assert z3.is_true(z3.simplify(z3.fpEQ(positive, negative)))
assert z3.is_false(z3.simplify(positive == negative))
one = z3.fpBVToFP(z3.BitVecVal(0x3f800000, 32), z3.Float32())
assert z3.is_true(z3.simplify(z3.fpEQ(one, z3.FPVal(1.0, z3.Float32()))))
```

<a id="s15"></a>

## [S15] Optimization and soft constraints

Use `Optimize()` when a feasible witness is not enough and an objective should
be minimized or maximized. Its `add`, `check`, `model`, `push`, and `pop` resemble
the solver interface, but objective handling and parameters are distinct.

| Call | Contract |
| --- | --- |
| `o.minimize(expr)` / `o.maximize(expr)` | Adds an arithmetic or supported bitvector objective; returns an objective handle. |
| `o.add_soft(condition, weight="1", id=None)` | Adds a preference that may be violated; weight is a positive numeric weight, represented exactly as a string when appropriate. IDs group soft constraints. |
| `o.check()` | Returns `sat`, `unsat`, or `unknown`; handle all three. |
| `handle.lower()` / `handle.upper()` | Objective bounds as Z3 values; can involve infinity or infinitesimal terms. |
| `o.set(priority="lex")` | Lexicographic objectives in insertion order (default). `pareto` and `box` have different semantics. |
| `o.set(timeout=5000)` | Timeout in milliseconds; an interrupted optimization is not a certificate of optimality. |

**Runnable example:** find the nearest integer satisfying a threshold.

```python
import z3

x = z3.Int("x")
o = z3.Optimize()
o.set(timeout=5000)
o.add(x >= 0, x <= 20, 3 * x >= 17)
objective = o.minimize(x)
assert o.check() == z3.sat
assert o.model().eval(x).as_long() == 6
assert objective.lower().as_long() == 6
assert objective.upper().as_long() == 6
```

For strict real bounds, an optimum may be unattained: minimizing `x` with `x > 0`
has infimum zero but no feasible minimizer. Inspect objective bounds rather than
claiming a model attains a limit. Unbounded objectives can yield infinite bounds.
For multiple objectives, `lex` prioritizes earlier objectives; `pareto` explores
tradeoffs through successive checks; `box` finds independent objective bounds
that need not be jointly attainable by one model.

When minimizing a machine value, express the intended signedness explicitly
with `BV2Int(value, is_signed=...)`. Soft constraints are preferences, never a
replacement for mandatory safety or input-domain constraints.

<a id="s16"></a>

## [S16] AST inspection, simplification, tactics, and SMT-LIB

For an expression `e`, `.sort()` reports its type, `.sexpr()` its SMT-LIB-like
syntax, and `.children()` its immediate expression children. For applications,
`.decl()` reports the declaration, `.decl().kind()` an operator identifier, and
`.num_args()` / `.arg(i)` access arguments. Test `is_app`, `is_quantifier`, and
`is_var` before applying node-specific methods; bound variables use indices.

`simplify(e, **options)` returns an expression; it does not use a solver's
assertions or establish arbitrary equivalence. `substitute(e, (old, new), ...)`
performs structural expression substitution. Avoid replacing variable names by
editing printed text. `help_simplify()` lists simplifier options.

**Runnable example:** inspect, substitute, and round-trip a solver query.

```python
import z3

x = z3.Int("x")
expression = x + 2
assert expression.num_args() == 2
assert z3.simplify(z3.substitute(expression, (x, z3.IntVal(5)))).as_long() == 7
s = z3.Solver()
s.add(x >= 4, x <= 4)
serialized = s.to_smt2()
restored = z3.Solver()
restored.from_string(serialized)
assert restored.check() == z3.sat
assert restored.model().eval(x).as_long() == 4
```

`parse_smt2_string(text, sorts={}, decls={})` returns an `AstVector` of assertions,
not a solver result. `parse_smt2_file(path)` reads a file. `s.from_string(text)`
and `s.from_file(path)` add parsed assertions. Pass declaration mappings when a
fragment refers to already created symbols. Do not assume parsing executes an
arbitrary interactive SMT-LIB command session. Save the last temporary
assumptions, solver parameters, objectives, and version separately: an assertion
export alone is not a full session replay. `e.sexpr()` alone may omit declarations.

### Tactics transform goals; solvers answer queries

`Goal()` holds formulas for transformation. `Tactic(name)(goal)` returns an
`ApplyResult` containing subgoals, not `sat` or a `ModelRef`. In general, the
original goal is satisfiable if at least one resulting subgoal is satisfiable.
Model conversion can be necessary after eliminating variables; independently
solving a transformed goal does not automatically recover the original model.

Compose tactics with `Then`, alternatives with `OrElse`, bounded tactic execution
with `TryFor(tactic, milliseconds)`, and tactic parameters with `With`.
`Then(...).solver()` builds a solver that handles the tactic pipeline and model
conversion. A tactic failure raises `Z3Exception`; it is not unsatisfiability.

**Runnable example:** solve a small bitvector formula through a tactic pipeline.

```python
import z3

x = z3.BitVec("x", 8)
s = z3.Then("simplify", "bit-blast", "sat").solver()
s.add(x + 1 == 0)
assert s.check() == z3.sat
assert s.model().eval(x).as_long() == 255
```

Discover available names with `tactics()` and parameters with `Tactic(name).help()`.
Do not apply a bitvector-specific pipeline to arbitrary arrays, quantifiers,
or arithmetic and assume the same coverage as the default solver.

<a id="s17"></a>

## [S17] Complete example: recover and replay a byte input

This toy validator packs two uppercase bytes in little-endian order, XORs a
constant, and compares the result. The third byte uses an eight-bit wrapped sum.
All operations, widths, and the input domain are explicit. This example uses
Z3 directly and has no dependency on angr or a target executable.

**Runnable example:** recover the correlated input and prove its uniqueness
within the stated input domain.

```python
import z3


def concrete_accepts(data):
    if len(data) != 3 or not all(0x41 <= byte <= 0x5a for byte in data):
        return False
    packed = int.from_bytes(data[:2], "little")
    return (packed ^ 0x1234) == 0x5075 and ((data[0] + data[1]) & 0xff) == data[2] + 64


b = [z3.BitVec(f"input_{i}", 8) for i in range(3)]
s = z3.Solver()
s.set(timeout=5000)
for byte in b:
    s.add(z3.UGE(byte, 0x41), z3.ULE(byte, 0x5a))
packed = z3.Concat(b[1], b[0])
s.add((packed ^ 0x1234) == 0x5075)
# Widen the right-hand arithmetic to reflect the concrete Python predicate.
# The left-hand sum wraps as an 8-bit operation before being widened.
s.add(z3.ZeroExt(8, b[0] + b[1]) == z3.ZeroExt(8, b[2]) + 64)
result = s.check()
if result == z3.unknown:
    raise RuntimeError(s.reason_unknown())
assert result == z3.sat
m = s.model()
candidate = bytes(m.eval(byte, model_completion=True).as_long() for byte in b)
assert candidate == b"ABC"
assert concrete_accepts(candidate)
s.add(z3.Or(*[byte != value for byte, value in zip(b, candidate)]))
assert s.check() == z3.unsat  # no second candidate in this domain
```

For a real target, replace the concrete predicate with execution of the exact
binary using its actual stdin/argv/file framing, and compare the observed success
condition. Record any translation of machine operations into constraints.
A recovered input establishes feasibility; only the second `unsat` query
establishes uniqueness within this particular model and domain.

### Moving between angr/Claripy and Z3Py

Claripy ASTs and Z3Py ASTs are different objects with different APIs. Use
Claripy through `state.solver` for normal angr tasks; do not insert Z3 ASTs into
a SimState. In particular, do not translate `claripy_bv < constant` to
`z3_bv < constant` without checking signedness. Z3's `model().eval(...)` is not
Claripy's `state.solver.eval(...)`, which returns a concrete value directly.

When exporting a formula, preserve widths, variable identities, and all path
constraints. An isolated expression omits the conditions that made the angr
state reachable. Backend conversion interfaces are version-sensitive and are
outside this guide's tested examples. See [angr solver architecture](angr-doc.md#s13).

<a id="s18"></a>

## [S18] Bounded transition systems and reachability

Z3 has no implicit execution loop. Introduce one symbolic state per step, assert
an initial condition and transitions, and ask whether a bad state occurs in the
chosen bound. This is bounded model checking. If only the final state is queried,
the question is reachability at that exact step, unless the encoding provides
stuttering or an explicit earlier-state disjunction.

**Runnable example:** an eight-bit counter reaches three within three steps.

```python
import z3

states = [z3.BitVec(f"counter_{i}", 8) for i in range(4)]
s = z3.Solver()
s.add(states[0] == 0)
for current, following in zip(states, states[1:]):
    s.add(following == current + 1)
s.push()
s.add(z3.Or(*[state == 3 for state in states[:3]]))
assert s.check() == z3.unsat  # only steps 0, 1, 2 were queried
s.pop()
s.add(z3.Or(*[state == 3 for state in states]))
assert s.check() == z3.sat
assert [s.model().eval(state).as_long() for state in states] == [0, 1, 2, 3]
```

A bounded `unsat` result is not an unbounded safety proof. To establish an
inductive invariant `I`, separately prove initialization implies `I`, each
transition preserves `I`, and `I` implies the safety property. Each proof uses
an unsatisfiable counterexample query. If the invariant is too weak, a failed
induction query need not be an actual reachable program counterexample.

<a id="s19"></a>

## [S19] Solver internals and practical performance

Z3 combines several engines. The standard SMT architecture combines Boolean
search and learning with theory reasoning (often called CDCL(T)). Equality
reasoning shares information among terms; theory solvers reason about arithmetic,
arrays, and other domains. Many finite bitvector problems are reduced to Boolean
constraints (bit-blasting). Preprocessing can remove or reshape formulas before
search. These are explanatory models, not a promise of a specific engine for
every query or release. See [Z3 Internals](https://z3prover.github.io/papers/z3internals.html).

Practical consequences for an analysis agent:

| Symptom / choice | Action and reason |
| --- | --- |
| An easy-looking query is slow | Inspect `.sexpr()` and sorts; accidental nonlinear terms or quantifiers can change the problem substantially. |
| Machine arithmetic | Keep fixed widths where they match semantics; avoid unnecessary `BV2Int` / `Int2BV` crossings. |
| Huge symbolic buffer or memory | Model only relevant regions and realistic input lengths; do not silently narrow the input domain merely to obtain a result. |
| Repeated nearby queries | Reuse assertions with scopes or assumptions; measure against fresh solvers for the actual workload. |
| Many equivalent expressions | Reuse constructed terms, simplify obvious redundancies, and profile encoding separately from solving. |
| Symbolic products/division/variable shifts | Isolate their contribution and supply justified bounds; replacing them with constants changes the problem. |
| Quantifier-heavy query | Inspect triggers and ground terms; use finite expansion only for an actually finite domain. |
| Performance experiment | Save the exact formula and settings, change one choice, record time and result, and revalidate witnesses. |

A random seed may help reproduce a particular run but does not make witnesses,
cores, statistics, or performance stable across releases and platforms. Do not
select parameters from an old article without checking the active object's
`help()` or `param_descrs()`. A longer timeout does not correct a wrong encoding.

<a id="s20"></a>

## [S20] Contexts, concurrency, proof objects, and Horn clauses

### Context isolation

Use separate `Context` instances for independent threads. Do not concurrently
operate on objects sharing a context; parallel solver internals are a different
feature. `expr.translate(destination_context)` and
`solver.translate(destination_context)` create translated objects. Construct
literals in the same context as their operands or let safe coercions do so.
For processes, serialize formulas and rebuild objects rather than sharing
Python wrappers or raw native pointers.

**Runnable example:** translate an existing solver to another context.

```python
import z3

first, second = z3.Context(), z3.Context()
x = z3.Int("x", ctx=first)
s = z3.Solver(ctx=first)
s.add(x == 7)
copy = s.translate(second)
assert copy.check() == z3.sat
assert copy.model().eval(x.translate(second)).as_long() == 7
```

This checks translation, not concurrent thread execution. For production
concurrency, isolate contexts for their full lifetime and test the exact API use.

### Proof objects

`Context(proof=True)` enables proof production for objects in that context;
`s.proof()` retrieves a proof after `unsat` for supported configurations. Enable
it before constructing the query. An unsat core is a subset of constraints; a
proof object is a derivation. Proof formats and supported tactics vary, and
retrieving an object is not the same as independently checking it. Proof
certificate production/checking is not validated in this reference.

### Fixedpoint and recursive reachability

`Fixedpoint()` is a separate interface for relations and Horn rules. Principal
calls are `register_relation(relation)`, `declare_var(*variables)`,
`rule(head, body)`, `fact(atom)`, `query(atom)`, and `get_answer()`.
`set(engine="spacer")` selects the property-directed Horn-clause engine.
Interpret results relative to the reachability query: `sat` means the queried
relation is reachable/derivable, `unsat` means it is not, and `unknown` is
inconclusive. `get_answer()` is engine-dependent, not an ordinary solver model.

**Runnable example:** derive a reachable counter value with Horn rules.

```python
import z3

reach = z3.Function("reach", z3.IntSort(), z3.BoolSort())
x = z3.Int("x")
fp = z3.Fixedpoint()
fp.set(engine="spacer", timeout=5000)
fp.register_relation(reach)
fp.declare_var(x)
fp.fact(reach(0))
fp.rule(reach(x + 1), z3.And(reach(x), x < 3))
assert fp.query(reach(3)) == z3.sat
assert fp.query(reach(4)) == z3.unsat
```

User propagators, solver callbacks, custom theories, and full invariant-synthesis
workflows are specialist interfaces outside this guide's validated coverage.
Consult the matching public API and build a small reproducer before integrating.

<a id="s21"></a>

## [S21] Troubleshooting and safe result interpretation

| Symptom / searchable error | Likely cause | Check or fix |
| --- | --- | --- |
| `ModuleNotFoundError: z3` | Wrong interpreter or missing distribution | Install `z3-solver` with that interpreter; inspect its environment. |
| `module 'z3' has no attribute 'Solver'` | Shadowing, unrelated package, or incomplete installation | Print `z3.__file__`; test a fresh pinned environment. Metadata alone does not validate imports. |
| `Z3Exception: sort mismatch` / incompatible bitvector sizes | Mixed widths, kinds, or malformed arguments | Print operand sorts; use deliberate extension/extraction/conversion. |
| `context mismatch` | Objects from different contexts | Construct consistently or explicitly `translate`. |
| `Symbolic expressions cannot be cast to concrete Boolean values` | Python condition, `and`, `or`, `not`, or chained comparison | Build Z3 Boolean expressions and issue an explicit query. |
| Wrong branch selected without an exception | Equality converted structurally to a Python Boolean | Audit all Python control flow using symbolic values. |
| `model is not available` | No successful current `sat` query | Handle `check()` first; recheck after mutations. |
| `.as_long()` missing or failing | Value is symbolic, nonintegral, or another sort | Evaluate first and inspect its kind; use the correct conversion. |
| Unexpected negative / huge integer | Signedness or bitvector interpretation | Compare `as_long()` with `as_signed_long()` and inspect operators. |
| Constraint on a byte is always false | E.g. `byte < 256` coerced 256 to zero | Use a valid bound such as `ULE(byte, 255)` or widen first. |
| Division/shift disagrees with the binary | SMT operation differs from instruction semantics | Model count masking, signed division, traps, promotions, and overflow. |
| Arbitrary zeros or absent model entries | Underconstrained or irrelevant inputs | Decide whether missing constraints are intended; completion is arbitrary. |
| Repeated or missing enumeration results | Blocking a wrong expression/tuple | Extract and block the entire selected tuple from one model. |
| `unknown`, timeout, resource exhaustion | Incomplete theory reasoning or budget | Record diagnostic and limits; never relabel as `unsat`. |
| `unsat` unexpectedly | Contradictory assumptions, width error, stale scope | Check smaller subsets or tracking cores; inspect asserted formulas. |
| Every property appears provable | Base assumptions already inconsistent | Check base satisfiability before negating the property. |
| A satisfiable witness fails replay | Incomplete/wrong encoding or input framing | Compare concrete and symbolic computations at their first divergence. |
| A tactic returns subgoals | Confusing transformation with solving | Use a solver built from the tactic or handle subgoal/model conversion properly. |
| Optimization gives a surprising model | Priority, unboundedness, strict bound, or timeout | Inspect objective bounds, result, and exact objective sorts. |

A useful bug report includes Python/distribution/library versions, platform,
minimal standalone code or SMT-LIB, settings, expected versus observed semantics,
last result and diagnostic, and whether the failure reproduces in a clean
environment. Do not remove constraints until a candidate appears and report it
as solving the original problem.

<a id="s22"></a>

## [S22] Validation, reproduction, and coverage limits

Reference date: **2026-09-25**. The guide targets the repository's
**z3-solver 5.1.0.0** pin. An initial check, completed before further runtime
validation was deferred, executed all **23 runnable examples** successfully
with **CPython 3.12.14**, native library **Z3 5.1.0**, on Linux x86-64 in an
isolated environment. This is a check of these examples, not a compatibility
claim for every API or target. No repository dependency was changed.

To reproduce an individual example, install the pinned package as described in
[S01](#s01), copy its complete Python fence into a file, and run it with that
interpreter and assertions enabled (without `-O`). Every Python fence is
independent and includes its own imports and inputs. Silent completion means
its assertions passed. The examples cover solving, signed arithmetic, model
completion, cores, enumeration, arrays, datatypes, quantifiers, strings,
floating point, optimization, SMT-LIB, tactics, byte recovery/replay, bounded
reachability, context translation, and Horn rules.

Not validated: native binary replay, multi-threaded execution, proof certificate
checking, all optimizer priorities, every theory combination, or every API
member. The guide is a working reference, not an exhaustive generated API dump.
A passing small quantified example does not establish completeness for general
quantified inputs. Timings, chosen witnesses, core membership beyond logical
necessity, and internal statistics can vary across versions.

<a id="s23"></a>

## [S23] Source trail and glossary

The examples and explanations are original. Public API contracts were checked
against the installed 5.1.0.0 Python binding (`z3/z3.py`) and executable examples.
The web references below were consulted on 2026-09-25; they are supplemental,
and their historical versions or rolling API content can differ from this pin.

| Source | What to consult it for |
| --- | --- |
| [Programming Z3](https://z3prover.github.io/papers/programmingz3.html) | Broad survey of theories, solver interaction, tactics, and optimization; its architecture discussion is historically versioned. |
| [Z3 Internals (draft)](https://z3prover.github.io/papers/z3internals.html) | Engines, equality reasoning, model construction, quantifiers, and preprocessing. |
| [Understanding how F* uses Z3](https://fstar-lang.org/tutorial/book/under_the_hood/uth_smt.html#understanding-how-f-uses-z3) | Verification conditions, SMT assertion meaning, frontend encodings and query inspection. |
| [Z3Py public API reference](https://z3prover.github.io/api/html/namespacez3py.html) | Searchable constructor/function/class reference; confirm details against the installed binding. |
| [Z3 source repository](https://github.com/Z3Prover/z3) | Installation, release history, source, and issue reporting. |

For local API details, use Python `help(z3.Solver)` or `help(z3.BV2Int)` and inspect
`z3.__file__` to locate the installed binding. For parameter availability, use
the specific solver/tactic object's help instead of relying on generic lists.

| Term | Meaning |
| --- | --- |
| AST | Abstract syntax tree; Z3 shares immutable subterms, so the implementation is a graph. |
| Sort | Logical type of an expression. |
| SMT | Satisfiability modulo theories: Boolean reasoning combined with domain semantics. |
| Theory | Meaning and rules for operations such as arithmetic, arrays, or bitvectors. |
| Assertion | Constraint assumed true in the current query. |
| Model / witness | Interpretation satisfying a query; not necessarily unique. |
| Validity | Truth for every assignment satisfying the assumptions. |
| Counterexample | A model satisfying the assumptions and negated property. |
| Projection | The selected expressions whose values matter when extracting/enumerating models. |
| Unsat core | An inconsistent subset of tracked assumptions relative to the background. |
| Trigger / pattern | Term shape guiding quantifier instantiation. |
| Bit-blasting | Reduction of bitvector operations to Boolean constraints. |
| VC | Verification condition encoding a proof obligation. |
| BMC | Bounded model checking over a finite number of transitions. |
| Horn clause | Rule relating predicates, used by fixedpoint engines for reachability/invariants. |
