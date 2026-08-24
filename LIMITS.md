# Limits

What UEG does not do, stated plainly, because a safety tool that oversells
itself is worse than no safety tool.

## Classification reads the command line, not the program

The effect class is decided from argv before the process starts. That is the
only moment at which refusing is still possible, and at that moment the command
line is all there is.

So:

- `python script.py` cannot be classified. Nothing in that string says what the
  script does. It is `UNCLASSIFIED` and refused by default.
- A program named `ls` that deletes files is classified as a read.
- A command classified `REVERSIBLE` can still do arbitrary damage if the binary
  behind it is not what its name suggests.
- Rules match on argv shape. A destructive command written in a form no rule
  anticipated falls through to `UNCLASSIFIED` — refused by default, which is the
  intended failure direction, but not the same as being recognised.

`REVERSIBLE` means "this argv describes a read or a precisely undoable change,"
not "this process is harmless."

## Shell strings are not parsed

`bash -c "rm -rf /"`, `sh -c`, `zsh -c`, `cmd /c`, PowerShell command strings,
`eval`, and similar are `UNCLASSIFIED`. UEG does not implement a shell parser,
and a partial one would be worse than none: quoting, expansion, substitution
and chaining all provide ways to hide the real command from a naive matcher.

If you pass `--allow-unclassified`, you are running an unexamined string.

## UEG is not a sandbox

An admitted command runs as a normal child process with the invoking user's full
privileges: same filesystem, same network, same credentials. UEG decides whether
to start it. It does not confine it, intercept its syscalls, or stop it once it
is running.

For containment, use a sandbox. UEG is a decision and evidence layer, and can be
placed in front of one.

## Detection of some effects is impossible before the fact

An admitted process may spawn children, write anywhere it has permission, or
make network calls. None of that appears in UEG's evidence beyond the exit code
and captured output. The receipt records what UEG asked for and what came back,
not everything the process touched.

## The evidence proves observation, not honesty

The chain proves that a UEG process holding an authenticated operational key
recorded these facts in this order and that the resulting bundle is internally
consistent. It does not prove:

- that the machine was not compromised at the time;
- that the binary called `ueg` was the real one;
- that a person holding an operational private key did not manufacture a
  plausible history inside that key's authorization window;
- that a B+ Evidence Identity belongs to a particular person, organization,
  device, account, or legal authority;
- that evidence contents are true, legally admissible, or nonrepudiable.

For legacy evidence, `IDENTITY_TRUSTED` requires an independently obtained
complete `--expected-key-id`. B+ evidence requires an independently obtained
genesis `--expected-identity-id` and an independently supplied or retained
lifecycle checkpoint before it can be `VERIFIED` at that checkpoint. Copying a
pin or checkpoint from the bundle adds no external trust.

B+ operational keys live under `$UEG_HOME/identity/epochs/`. The active private
key is limited on Windows to the owning user and LocalSystem with inherited
access disabled; POSIX requires mode `0600` inside protected directories. UEG
verifies those conditions and fails closed when it cannot secure or load the
key. Anyone who can read an active operational key can sign within that epoch.
LocalSystem and processes running as the owning user remain inside that trust
boundary.

## Evidence Identity is pseudonymous continuity

The stable B+ identity id is a digest of an authenticated genesis manifest. It
is not a human or organizational identity. An advisory label has no
cryptographic authority. External systems must decide what real-world subject,
if any, they associate with a pinned identity id.

The encrypted recovery package contains the recovery-root private key. It is
written only to the explicit initialization destination and is never included
in a bundle or normal UEG state. Encryption does not compensate for a weak
passphrase or unsafe custody. Loss of the recovery root makes future lifecycle
control impossible; compromise ends trustworthy continuity for that identity.
UEG has no root rotation, threshold governance, cloud recovery, or HSM support.

## Offline status has a freshness ceiling

A lifecycle checkpoint proves the authentic state it contains. An offline
verifier cannot prove that no newer suspension or revocation exists. When
current status is required, `--require-current-status` returns
`TRUST_INDETERMINATE` and exits nonzero rather than inventing freshness.

An independently retained evidence anchor binds one exact ledger head and one
operational epoch. It can preserve trust for covered evidence after that epoch
is compromised. It does not cover another revoked epoch, establish trusted
time, or prove facts that were never anchored independently.

UEG cannot prevent an old copied home from using copied key material. It can
detect stale state only when a newer authenticated checkpoint is supplied or
already retained. Without that external freshness input it reports local-only
freshness rather than claiming the clone is current.

## Timestamps are wall clock

`timestamp_iso8601` is the host clock, marked `kernel_observed`. It is not
trusted time and can be wrong or manipulated. Ordering is proved by the chain
(sequence numbers and `prev_receipt_id`), not by the timestamps.

## Two runs of the same command produce different receipts

Receipt ids are content-addressed, and the content includes the timestamp and
the sequence number, so identical commands yield different ids. What is
reproducible is the comparison `ueg replay` performs: exit code and the SHA-256
of each output stream.

Commands that are inherently non-deterministic — anything printing a date, a
random value, a pid, or a duration — will replay as `DIVERGED`. That is
accurate, not a bug, but it means replay is a check on reproducible commands,
not a general-purpose test.

## Replay executes

`ueg replay` re-runs a complete recorded command for real and writes a new
signed admission/outcome pair for that replay. Current enforce policy is
applied even if the original used observe posture. `IRREVOCABLE` requires
`--approve`, `UNCLASSIFIED` requires `--allow-unclassified`, and `PROHIBITED`
is never replayed. A `REVERSIBLE` classification is still only as good as the
section at the top of this file.

If an admission is intact but has no outcome, replay returns
`INCOMPLETE_OR_TRUNCATED` and does not run it. Until later evidence has been
externally anchored, UEG cannot distinguish a process interruption from removal
of the terminal outcome. It also cannot know whether an interrupted child made
an external change before it stopped; the operator must inspect that system
before choosing a new command.

## Evidence-home concurrency and interrupted writes

UEG serializes its own operations per evidence home. A long-running command
therefore makes another UEG process wait rather than allowing duplicate sequence
numbers. Programs that edit UEG's evidence files directly are outside that
coordination boundary and are detected as invalid evidence.

Each receipt/request pair has a write-ahead recovery record. If the second file
write fails, export remains blocked until `ueg recover` completes the exact
signed pair and verifies the chain. This is application-level crash recovery,
not a guarantee against storage hardware that lies about durable writes.

## Output capture is bounded in the evidence

The SHA-256 covers the entire stream. The excerpt stored in the receipt is
capped at 64 KiB per stream and flagged `stdout_truncated` / `stderr_truncated`
when cut. Full output beyond that cap is not retained.

Arguments and retained excerpts are evidence, not sanitized logs. If a command
prints a credential or receives one as an argument, that value can be recorded
and carried into an export. UEG does not claim generic secret detection or
redaction. Keep secrets out of command arguments and output, and inspect bundles
before sharing them. The export format does not automatically include UEG's
private-key file, but processes running as the owning user remain inside the
same trust boundary as that key.

## Observe posture gates only PROHIBITED effects

`--posture observe` classifies and records, and admits non-prohibited effects,
including `IRREVOCABLE` and `UNCLASSIFIED`. It exists so the rule table can be
evaluated against real traffic before enforcement is turned on.

`PROHIBITED` is different: after a command is classified `PROHIBITED`, it is
always refused regardless of posture, `--approve`, or `--allow-unclassified`.
This does not mean UEG recognizes every destructive spelling. An opaque shell
string or an operation absent from the rule table remains `UNCLASSIFIED`, and
observe mode deliberately admits it.

The posture is part of the policy hash, so evidence cannot later be read as
enforcement that was not in force.

## Platform coverage

The Go source builds for Windows, Linux, and macOS. Direct Windows executable
aliases are normalized across case, path spelling, and `.exe`, `.com`, `.bat`,
and `.cmd` suffixes. Direct `format` and `diskpart` invocations are classified
`PROHIBITED`; drive-root operands normalize ordinary, dot-segment,
environment-expanded, and extended Windows forms.

UEG still does not parse `cmd` or PowerShell program text. For example, a
destructive operation hidden inside `cmd /c` or `powershell -Command` is
`UNCLASSIFIED`: default enforce posture refuses it, while observe mode or an
explicit unclassified approval admits it. Native runtime qualification is
platform-specific; a cross-compiled binary proves compilation, not execution
on an operating system that was not used for the test.

## Deliberate scope boundaries

- No approval workflow beyond a local flag. `--approve` is the operator saying
  yes at the moment of running; there is no queue, no second party, no remote
  confirmation.
- No hosted revocation/status service, transparency log, trusted timestamp,
  blockchain, PKI, user account, concurrent signer, recovery-root rotation,
  general multi-key governance, HSM integration, or GUI.
- B+ migration is explicit and one-way. It preserves historical legacy
  verification but does not create lifecycle protection retroactively.
- Recovery restores signing authority only. It does not recreate deleted
  evidence, reconstruct a lost ledger, or prove secure erasure of retired keys.
- The Go verifier enforces closed security-record structures and one strict JSON
  policy directly. The Python verifier applies the JSON Schemas as well. This
  is cross-implementation agreement, not formal proof that the implementations
  have no shared misunderstanding.
