# Product Hunt Submission

## Product name

UEG

## Final tagline

Run commands. Prove what happened.

## Short description

UEG is a deterministic CLI for command execution with receipts, replay, and tamper detection.

## Full launch description

UEG is a standalone command-line tool for teams that need more than "it ran on my machine."

It executes commands, saves receipts, replays prior runs, and detects when an execution record has been changed after the fact. That makes it useful anywhere command execution needs to be inspectable later, especially in DevOps, infrastructure, security-minded engineering, and AI-agent tooling.

UEG is not a cloud service and it is not a shell replacement. It is a local execution gateway that adds proof, replay, and deterministic validation around command runs.

If your workflow depends on showing what happened, not just whether something returned exit code 0, UEG is built for that gap.

## Maker comment

We built UEG because command execution usually vanishes into terminal history, stdout, and an exit code. That works until you need to prove what actually happened, replay the same path, or detect that a record was changed later. UEG is our attempt to make command execution more inspectable without turning it into a platform or service. If you build internal tooling, agent systems, or operational automation, I’d love to hear where receipts and replay would be useful.

## First comment

UEG is deliberately small in scope. It runs commands, records receipts, replays the path later, and flags tampering. It does not promise sandboxing, hosted workflows, or magic automation. The goal is a better execution record for technical teams that already live in the terminal.

## Suggested tags and categories

Suggested Product Hunt categories:

- Developer Tools
- Open Source
- Security

Suggested keyword tags for supporting copy and outreach:

- CLI
- DevOps
- Infrastructure
- Compliance
- AI agents
- Auditability

## FAQ

### Is UEG a shell replacement?

No. UEG is a standalone CLI that wraps command execution with receipts, replay, validation, and tamper detection.

### Does UEG sandbox commands?

No. It does not claim OS-level sandboxing or isolation. Commands still run on the local machine.

### Does UEG require a server or cloud account?

No. UEG is a local binary.

### Who is this for?

Teams running operational commands who need better evidence, replay, and auditability: DevOps, infra, security/compliance, and AI-agent builders.

### What platforms are available?

Windows AMD64, Linux AMD64, macOS Intel, and macOS Apple Silicon.

## Launch-day checklist

- Confirm the landing page URL is live and points to the current download page.
- Confirm the GitHub release is already published before the Product Hunt launch goes live.
- Make sure your Product Hunt posting account is a personal account.
- If the Product Hunt account is new, confirm it currently has posting access before launch day.
- Create a draft or scheduled launch ahead of time and review the preview carefully.
- Add up to 3 Product Hunt categories that match the product.
- Add the product URL as the main link.
- Add the GitHub release or download page as the download link.
- Upload the screenshots and demo GIF listed in `SCREENSHOT_PLAN.md`.
- Paste the maker comment and first comment from this file.
- Test every link again after publishing.

## Screenshot and video asset list

- `validate-proof.png` or GIF: `ueg --validate`
- `receipt-run.png` or GIF: command execution with `--receipt`
- `replay-match.png` or GIF: replay showing `MATCH`
- `tamper-detected.png` or GIF: replay showing `TAMPERED`
- `release-assets.png`: `dist/` plus `checksums.txt`
- `30-second-demo.gif`: quick flow from validate to tamper detection

## Product Hunt submission notes

Based on current Product Hunt help articles:

- products are posted from a personal account
- you can create a draft or schedule a launch
- first-time launch setup includes category selection
- live products do better than waitlist-only launches
