# UNIFIED STATE TAXONOMY v1.0
## UEG Deterministic Execution System

**Authoritative Reference Document**

---

## CORE PHILOSOPHY

Traditional systems ask: *"Did it work or fail?"*

This system asks: *"What exists, and what's the next valid form it can take?"*

There is no failure—only **incomplete formation**. Every state is a waypoint toward execution.

---

## THE SEVEN EXISTENTIAL CLASSES

Every possible system state falls into exactly one of these classes. They are **mutually exclusive** and **collectively exhaustive**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         STATE EXISTENCE SPECTRUM                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  VOID → NASCENT → DECLARED → CANONICAL → GATED → SEALED → EXECUTED         │
│    ↓       ↓         ↓           ↓          ↓        ↓         ↓           │
│   [0]     [1]       [2]         [3]        [4]      [5]       [6]          │
│                                                                             │
│  Nothing  Something  Named      Meaning    Ready    Locked    Complete     │
│  exists   detected   exists     fixed      to run   down      & recorded   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## CLASS DEFINITIONS

### CLASS 0: VOID

**Definition:** No input has been received. The system is observing but has nothing to process.

| Property | Value |
|----------|-------|
| Exists | No |
| Identity | None |
| Meaning | None |
| Executable | No |
| Responsible Subsystem | UIX1 (awaiting human input) |

**Allowed Transitions:**
- `VOID → NASCENT` (input received)

**What happens here:** System idles. UIX1 presents ready state. No action needed—this is structural rest, not waiting.

---

### CLASS 1: NASCENT

**Definition:** Raw input exists but has not been classified or named. It is *something* but we don't yet know *what*.

| Property | Value |
|----------|-------|
| Exists | Yes (raw form) |
| Identity | Unassigned |
| Meaning | Ambiguous |
| Executable | No |
| Responsible Subsystem | Identity Declaration |

**Allowed Transitions:**
- `NASCENT → DECLARED` (identity assigned)
- `NASCENT → VOID` (input determined to be null/empty—structural dissolution)

**What happens here:** The Identity Declaration subsystem inspects the input and assigns a type signature. This is not validation—it's classification. The question isn't "is this valid?" but "what *is* this?"

---

### CLASS 2: DECLARED

**Definition:** Input has an assigned identity and type, but its meaning may still be ambiguous or underspecified.

| Property | Value |
|----------|-------|
| Exists | Yes |
| Identity | Assigned |
| Meaning | Partial/Ambiguous |
| Executable | No |
| Responsible Subsystem | FASTCOD≡ (Meaning Canonicalization) |

**Allowed Transitions:**
- `DECLARED → CANONICAL` (meaning fully resolved)
- `DECLARED → DECLARED` (refinement cycle—more specificity added)

**What happens here:** FASTCOD≡ takes the declared identity and resolves all ambiguity. This stage may loop (`DECLARED → DECLARED`) as UIX1 gathers more information. This is not "asking for clarification"—it's **completing the declaration**.

---

### CLASS 3: CANONICAL

**Definition:** The request has a single, unambiguous meaning. There is exactly one interpretation of what needs to happen.

| Property | Value |
|----------|-------|
| Exists | Yes |
| Identity | Fixed |
| Meaning | Singular & Complete |
| Executable | Not yet (environment unchecked) |
| Responsible Subsystem | UEG + Preflight + AutoFix |

**Allowed Transitions:**
- `CANONICAL → GATED` (all execution requirements confirmed present)
- `CANONICAL → CANONICAL` (completion cycle via AutoFix/Universal Installer)

**What happens here:** UEG checks if execution is structurally possible. Preflight inventories what's needed vs. what exists. If something is missing, AutoFix or Universal Installer **completes the environment**—they don't report problems, they resolve gaps.

---

### CLASS 4: GATED

**Definition:** All preconditions for execution are satisfied. The operation is ready to run but has not yet been locked for execution.

| Property | Value |
|----------|-------|
| Exists | Yes |
| Identity | Fixed |
| Meaning | Singular & Complete |
| Executable | Yes (pending seal) |
| Responsible Subsystem | Runtime Green (sealing) |

**Allowed Transitions:**
- `GATED → SEALED` (execution lock acquired)

**What happens here:** Runtime Green acquires exclusive execution rights. This is the "point of no return" preparation. The system confirms nothing will change during execution.

---

### CLASS 5: SEALED

**Definition:** Execution is in progress. The operation has exclusive control and is running in an immutable context.

| Property | Value |
|----------|-------|
| Exists | Yes (in motion) |
| Identity | Fixed |
| Meaning | Being actualized |
| Executable | Executing now |
| Responsible Subsystem | Runtime Green |

**Allowed Transitions:**
- `SEALED → EXECUTED` (operation complete)

**What happens here:** The operation runs to completion. Because all preconditions were met and the environment is locked, the outcome is deterministic.

**Critical Rule:** SEALED operations cannot be interrupted, only completed. Partial execution doesn't exist in this model.

---

### CLASS 6: EXECUTED

**Definition:** The operation has completed. Results exist and are recorded.

| Property | Value |
|----------|-------|
| Exists | Yes (completed) |
| Identity | Archived |
| Meaning | Actualized |
| Executable | N/A (already done) |
| Responsible Subsystem | UIX1 (presentation) + TMS (truth recording) |

**Allowed Transitions:**
- `EXECUTED → VOID` (cycle complete, ready for next input)
- `EXECUTED → NASCENT` (if output triggers new operation)

**What happens here:** Results are recorded in Truth Maintenance System (TMS). UIX1 presents outcomes to human. System returns to ready state.

---

## COMPLETE STATE DIAGRAM

```
                              ┌──────────────────┐
                              │                  │
                              ▼                  │
┌──────┐    input    ┌─────────┐    identity    ┌──────────┐
│ VOID │ ──────────► │ NASCENT │ ─────────────► │ DECLARED │
└──────┘             └─────────┘                └──────────┘
   ▲                      │                          │
   │                      │ null input               │ refinement
   │                      ▼                          │ (loop)
   │                 ┌─────────┐                     │
   │                 │  VOID   │◄────────────────────┤
   │                 └─────────┘                     │
   │                                                 │
   │                                                 ▼ meaning fixed
   │                                          ┌───────────┐
   │                                          │ CANONICAL │◄──┐
   │                                          └───────────┘   │
   │                                                 │        │ completion
   │                                                 │        │ (loop)
   │                                                 ▼        │
   │                                          ┌───────────┐   │
   │                                          │  GATED    │───┘
   │                                          └───────────┘
   │                                                 │
   │                                                 ▼ lock acquired
   │                                          ┌───────────┐
   │                                          │  SEALED   │
   │                                          └───────────┘
   │                                                 │
   │                                                 ▼ complete
   │                                          ┌───────────┐
   └──────────────────────────────────────────│ EXECUTED  │
                      cycle complete          └───────────┘
```

---

## SUBSYSTEM RESPONSIBILITY MATRIX

| State | Primary Subsystem | Action | Success Condition |
|-------|-------------------|--------|-------------------|
| VOID | UIX1 | Await input | Input received |
| NASCENT | Identity Declaration | Classify input | Type signature assigned |
| DECLARED | FASTCOD≡ | Resolve meaning | Zero ambiguity remains |
| CANONICAL | UEG + Preflight + AutoFix | Verify/complete environment | All requirements present |
| GATED | Runtime Green | Acquire execution lock | Exclusive access obtained |
| SEALED | Runtime Green | Execute operation | Operation completes |
| EXECUTED | UIX1 + TMS | Present & record | Results delivered |

---

## HOW THIS REPLACES ERROR HANDLING

### Traditional Approach (Eliminated)

```
try:
    result = do_thing()
except FileNotFoundError:
    print("File not found!")  # STUCK
except DependencyError:
    print("Missing package!")  # STUCK
except ValueError:
    print("Bad input!")  # STUCK
```

**Problems:**
1. Exceptions halt progress
2. Human must diagnose and intervene
3. System enters undefined "error state"
4. No structural guarantee of forward motion

### Deterministic Approach (Used)

```
State: DECLARED {target: "config.json", exists: false}

# Traditional: "FileNotFoundError" → HALT
# Deterministic: State is incomplete → Complete it

Action: AutoFix recognizes missing file pattern
Action: AutoFix generates default config.json
State: DECLARED {target: "config.json", exists: true}
Transition: DECLARED → CANONICAL

# No error. No halt. Just completion.
```

### The Key Insight

**Traditional systems classify outcomes as success/failure.**
**This system classifies states as complete/incomplete.**

An incomplete state isn't an error—it's just not done yet. The system's job is to complete it.

---

## SYSTEM INVARIANTS

These guarantees are structural and cannot be violated:

1. **Forward Progress Invariant:** Every non-VOID state has at least one outbound transition that advances toward EXECUTED.

2. **No Stuck Invariant:** No state exists without a responsible subsystem capable of transitioning it forward.

3. **Determinism Invariant:** Given identical inputs and identical system state, the same state sequence will always occur.

4. **Completion Invariant:** Any SEALED state will reach EXECUTED. Partial execution is structurally impossible.

5. **Dissolution Invariant:** Invalid or null inputs dissolve to VOID rather than creating error states.

---

## EXAMPLE TRANSITIONS

### Example 1: User Requests Code Fix

```
T0: VOID (system ready)
    Input: "fix the bug"
    
T1: NASCENT {raw: "fix the bug"}
    Identity Declaration: Intent=Repair, Target=Unknown
    
T2: DECLARED {type: repair, target: null}
    FASTCOD≡: Incomplete. UIX1 query needed.
    UIX1: "Which file has the bug?"
    Human: "api.py line 23"
    
T3: DECLARED {type: repair, target: "api.py:23", criteria: null}
    FASTCOD≡: Incomplete.
    UIX1: "What should the correct behavior be?"
    Human: "should return 200, not 500"
    
T4: DECLARED {type: repair, target: "api.py:23", criteria: "return_200"}
    FASTCOD≡: Complete.
    
T5: CANONICAL {operation: "modify api.py:23 to return 200"}
    Preflight: api.py exists ✓, write permission ✓
    
T6: GATED
    Runtime Green: Acquiring lock...
    
T7: SEALED
    Executing modification...
    
T8: EXECUTED
    Result: api.py modified
    TMS: Change recorded.
    
T9: VOID (ready for next)
```

### Example 2: Missing Dependency

```
T0: CANONICAL {operation: "run analysis.py"}
    Preflight: analysis.py ✓, Python ✓, pandas ✗
    
    # Traditional: "ModuleNotFoundError" → HALT
    # Deterministic: Environment incomplete → Complete it
    
T1: CANONICAL (held)
    AutoFix: Installing pandas...
    
T2: CANONICAL {operation: "run analysis.py"}
    Preflight recheck: pandas ✓
    
T3: GATED
    [continues normally]
```

### Example 3: Null Input Dissolution

```
T0: VOID
    Input: "     " (whitespace only)
    
T1: NASCENT {raw: "     "}
    Identity Declaration: No semantic content.
    
T2: VOID (dissolved)
    # No error. Input didn't constitute anything.
```

---

## IMPLEMENTATION REQUIREMENTS

For any system implementing this taxonomy:

- [ ] Every subsystem must implement `can_advance(state) → bool`
- [ ] Every subsystem must implement `advance(state) → new_state`
- [ ] State objects must be immutable (new state = new object)
- [ ] State transitions must be logged to TMS
- [ ] UI must never display "error"—only "completing..." or "ready"
- [ ] All loops must have provable termination
- [ ] SEALED states must have timeout-to-completion, not timeout-to-failure

---

## QUICK REFERENCE CARD

```
┌────────────┬──────────────┬─────────────────┬──────────────────┐
│ STATE      │ EXISTS?      │ MEANING?        │ EXECUTABLE?      │
├────────────┼──────────────┼─────────────────┼──────────────────┤
│ VOID       │ No           │ No              │ No               │
│ NASCENT    │ Raw          │ No              │ No               │
│ DECLARED   │ Yes          │ Partial         │ No               │
│ CANONICAL  │ Yes          │ Complete        │ Not yet verified │
│ GATED      │ Yes          │ Complete        │ Yes, ready       │
│ SEALED     │ Yes          │ Being realized  │ In progress      │
│ EXECUTED   │ Yes          │ Actualized      │ Done             │
└────────────┴──────────────┴─────────────────┴──────────────────┘
```

---

**Document Version:** 1.0  
**Last Updated:** 2025  
**Project:** UEG  
**Classification:** Foundational Architecture  

*The future executes deterministically.*
