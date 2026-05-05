# UEG State Model Alignment

The product carries two state views on purpose:

- the seven-class architectural taxonomy defines the philosophy and invariant model
- the nine-stage CLI model defines the exact operational checkpoints implemented in the hardened binary

They are aligned, but not one-to-one.

## Why there are more CLI stages

The architectural taxonomy is intentionally abstract. It answers "what kind of existence is this request currently in?"

The CLI inserts additional operational checkpoints so it can:

- distinguish between a request that is complete but missing prerequisites
- expose a safe refinement surface before execution
- separate "armed and ready" from "completed and recorded"

## Mapping table

| CLI stage | Architectural class | Purpose |
|-----------|---------------------|---------|
| `VOID` | `VOID` | No request yet |
| `NASCENT` | `NASCENT` | Raw input exists |
| `DECLARED` | `DECLARED` | Identity assigned, meaning still forming |
| `CANONICAL` | `CANONICAL` | Meaning singular and scoped |
| `GATED` | `GATED` | Requirements evaluated |
| `REFINABLE` | `CANONICAL` | Safe completion loop for missing prerequisites |
| `EXECUTABLE` | `GATED` to `SEALED` boundary | Command armed and about to run |
| `EXECUTED` | `EXECUTED` | Command finished |
| `STABILIZED` | `EXECUTED` | Receipt finalized and stable |

## The only intentional compression

The seven-class taxonomy includes `SEALED` as the exclusive in-progress execution state.

The current CLI does not keep a user-visible long-lived `SEALED` stage. Instead:

- it transitions into `EXECUTABLE`
- immediately runs the command or internal op
- records the result in `EXECUTED`
- finalizes the receipt in `STABILIZED`

That means the CLI preserves the architectural meaning of `SEALED`, but collapses its visible lifetime into the execution boundary.

## Product guidance

Use the seven-class taxonomy when positioning the product, teaching the model, or describing invariants.

Use the nine-stage CLI model when:

- testing the binary
- reasoning about receipts and replay
- writing integrations around machine-readable execution traces
