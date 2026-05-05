# Outreach Posts

## Hacker News - Show HN

**Suggested title:**

Show HN: UEG - a CLI that runs commands, saves receipts, replays runs, and detects tampering

**Post body:**

I built UEG, a standalone CLI for command execution with receipts, replay, and tamper detection.

The problem I wanted to solve is simple: a lot of command execution ends with stdout, stderr, and an exit code, but no good way to prove later what actually happened or whether the execution record was changed.

UEG runs a command, can save a receipt, replay the receipt later, and report whether the replay matches the original deterministic path. If a receipt is changed, replay reports that it was tampered with.

It is local, not a SaaS product, and it does not claim sandboxing. The focus is evidence and replay for people who already work in terminals: DevOps, infra, security-minded engineering, and AI-agent tooling.

I’d especially value feedback on where receipts and replay are actually useful in real operational workflows.

## Reddit - r/devops

I’m launching a small CLI called UEG.

It wraps command execution with:

- receipt creation
- replay
- deterministic match checks
- tamper detection

The audience is teams that need a better record of what happened than terminal history plus an exit code. It is not a hosted service and it does not claim sandboxing. The idea is more proof around execution, not more orchestration.

If you run operational commands that later need to be explained to another person, I’d love to know whether this is useful or just overkill.

## Reddit - r/selfhosted

I’m sharing a local-first CLI called UEG.

It is not a hosted product and it does not require an account. The focus is command execution with receipts, replay, and tamper detection so you can prove what happened later.

This felt relevant here because a lot of self-hosted workflows still rely on shell history and logs that are awkward to replay or verify. UEG is not a server and not a dashboard, just a standalone binary with a tighter execution record.

If there’s a better subreddit fit, happy to move it. I’m mainly looking for practical feedback from people who run their own systems.

## Reddit - r/cybersecurity

I built a CLI called UEG for command execution with receipts, replay, and tamper detection.

It is not a security silver bullet and it does not sandbox commands. The narrower goal is to improve the evidence around local command execution by creating receipts that can be replayed later and checked for tampering.

I’m interested in whether this is useful for incident review, administrative change tracking, or AI-agent execution controls, and also where the limits are.

If you have strong opinions on what "proof" should mean in this area, I’d love that feedback.

## LinkedIn

Launching UEG today.

UEG is a standalone CLI for teams that need better evidence around command execution. It can run commands, save receipts, replay prior runs, and detect when a receipt has been changed.

This is for the cases where stdout and an exit code are not enough, especially in DevOps, infrastructure, security/compliance, and AI-agent tooling.

UEG is intentionally small in scope: local binary, no SaaS requirement, no inflated claims about isolation or compliance. Just a cleaner execution record and a replay path.

If you work in systems, automation, or agent infrastructure, I’d love to hear where this would help and where it would not.

## X / Twitter

Launching UEG today.

UEG is a standalone CLI that:

- runs commands
- saves receipts
- replays prior runs
- detects tampered execution records

Built for DevOps, infra, security-minded teams, and AI-agent builders who need more than stdout + exit codes.

No SaaS. No sandboxing claims. Just better proof around command execution.
