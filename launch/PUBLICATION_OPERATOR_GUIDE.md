# Publication Operator Guide

This guide is for getting UEG public as fast as possible with the least moving parts.

Recommended fastest path:

1. Create a public GitHub repo named `UEG`
2. Push the contents of `C:\UEG`
3. Publish a GitHub release `v1.2.0`
4. Use the GitHub repo URL as the public home
5. Use the GitHub release page as the download location
6. Submit that GitHub URL to Product Hunt
7. Replace the GitHub URL with a dedicated landing page later if needed

## 1. GitHub setup

### Create the GitHub repo

In the browser:

1. Sign in to GitHub.
2. Click the `+` button in the top-right.
3. Click `New repository`.
4. Repository name: `UEG`
5. Visibility: `Public`
6. Do not add a README, `.gitignore`, or license from the GitHub UI.
7. Click `Create repository`.
8. Copy the repo URL GitHub shows you.

You need that URL for the `git remote add origin` command below.

### Run these exact PowerShell commands from `C:\UEG`

```powershell
Set-Location C:\UEG
git status
git add .
git commit -m "Initial public UEG release"
git branch -M main
git remote add origin <PASTE_GITHUB_REPO_URL_HERE>
git push -u origin main
```

If Git asks for sign-in, complete the GitHub authentication flow and then rerun the `git push -u origin main` command.

## 2. GitHub release

### Create release `v1.2.0`

In the browser:

1. Open your new `UEG` repo on GitHub.
2. Click `Releases`.
3. Click `Draft a new release`.
4. Tag: `v1.2.0`
5. Release title:

```text
UEG v1.2.0 - Run commands. Prove what happened.
```

6. Paste the release notes from the block below into the description field.
7. Upload these exact files from `C:\UEG\dist`:
   - `ueg-v1.2.0-windows-amd64.zip`
   - `ueg-v1.2.0-linux-amd64.zip`
   - `ueg-v1.2.0-darwin-amd64.zip`
   - `ueg-v1.2.0-darwin-arm64.zip`
   - `checksums.txt`
8. Click `Publish release`.

### Paste-ready release notes

```md
# UEG Public Release Notes

## v1.0 launch summary

This is the first public launch package for UEG: a standalone CLI for command execution with receipts, replay, validation, and tamper detection.

Important version note:

- the current build artifacts in this package report `v1.2.0`
- if you publish these exact binaries, the GitHub release tag should match `v1.2.0`
- if you want the public release tag to be `v1.0.0`, change the version in the core intentionally before rebuilding

## What is included

- `ueg-v1.2.0-windows-amd64.zip`
- `ueg-v1.2.0-linux-amd64.zip`
- `ueg-v1.2.0-darwin-amd64.zip`
- `ueg-v1.2.0-darwin-arm64.zip`
- `checksums.txt`

## What UEG does

- Executes commands through a deterministic gateway
- Saves receipts for runs
- Replays prior runs and checks for deterministic path matches
- Detects tampered receipts via checksum verification
- Exposes a `--validate` command for state-model proof output

## What UEG does not do

- It does not claim OS-level sandboxing
- It does not require or provide a cloud service
- It does not replace your shell
- It does not promise compliance certifications, hosted audit storage, or managed workflows

## Checksum verification

Verify release assets before use.

### PowerShell

```powershell
Get-FileHash .\ueg-v1.2.0-windows-amd64.zip -Algorithm SHA256
Get-Content .\checksums.txt
```

### Bash

```bash
sha256sum ./ueg-v1.2.0-linux-amd64.zip
cat ./checksums.txt
```

## Install instructions

### Windows AMD64

1. Download `ueg-v1.2.0-windows-amd64.zip`
2. Verify the SHA-256 hash against `checksums.txt`
3. Extract the archive
4. Run `ueg.exe` from the extracted folder or add it to `PATH`

### Linux AMD64

1. Download `ueg-v1.2.0-linux-amd64.zip`
2. Verify the SHA-256 hash
3. Extract the archive
4. `chmod +x ueg`
5. Move it into your preferred binary directory if desired

### macOS Intel

1. Download `ueg-v1.2.0-darwin-amd64.zip`
2. Verify the SHA-256 hash
3. Extract the archive
4. `chmod +x ueg`

### macOS Apple Silicon

1. Download `ueg-v1.2.0-darwin-arm64.zip`
2. Verify the SHA-256 hash
3. Extract the archive
4. `chmod +x ueg`

## Demo commands

### Windows PowerShell

```powershell
.\ueg.exe --receipt .\demo-receipt.json cmd /c echo hello-from-ueg
.\ueg.exe --replay .\demo-receipt.json
.\ueg.exe --validate
```

### Bash

```bash
./ueg --receipt ./demo-receipt.json /bin/echo hello-from-ueg
./ueg --replay ./demo-receipt.json
./ueg --validate
```
```

## 3. Product Hunt

Product Hunt needs a public URL.

Fastest path:

- use the public GitHub repo URL as the main product URL
- use the GitHub release page as the download URL

If you publish a landing page later, you can use that instead. For the first public launch, GitHub is the fastest valid home.

Important Product Hunt notes:

- use a personal Product Hunt account
- make sure the product is publicly accessible before the launch goes live
- create a draft or schedule the launch before launch day if possible

### Paste-ready Product Hunt fields

#### Product name

```text
UEG
```

#### Tagline

```text
Run commands. Prove what happened.
```

#### Description

```text
UEG is a deterministic CLI for command execution with receipts, replay, and tamper detection.
```

#### Full launch description

```text
UEG is a standalone command-line tool for teams that need more than "it ran on my machine."

It executes commands, saves receipts, replays prior runs, and detects when an execution record has been changed after the fact. That makes it useful anywhere command execution needs to be inspectable later, especially in DevOps, infrastructure, security-minded engineering, and AI-agent tooling.

UEG is not a cloud service and it is not a shell replacement. It is a local execution gateway that adds proof, replay, and deterministic validation around command runs.

If your workflow depends on showing what happened, not just whether something returned exit code 0, UEG is built for that gap.
```

#### Maker comment

```text
We built UEG because command execution usually vanishes into terminal history, stdout, and an exit code. That works until you need to prove what actually happened, replay the same path, or detect that a record was changed later. UEG is our attempt to make command execution more inspectable without turning it into a platform or service. If you build internal tooling, agent systems, or operational automation, I’d love to hear where receipts and replay would be useful.
```

#### First comment

```text
UEG is deliberately small in scope. It runs commands, records receipts, replays the path later, and flags tampering. It does not promise sandboxing, hosted workflows, or magic automation. The goal is a better execution record for technical teams that already live in the terminal.
```

#### Tags and categories

Use these Product Hunt categories:

- Developer Tools
- Open Source
- Security

Use these supporting tags in your own notes and outreach:

- CLI
- DevOps
- Infrastructure
- Compliance
- AI agents
- Auditability

#### Asset checklist

Upload these assets with the Product Hunt listing:

- screenshot or GIF of `ueg --validate`
- screenshot or GIF of command execution with `--receipt`
- screenshot or GIF of replay showing `MATCH`
- screenshot or GIF of replay showing `TAMPERED`
- screenshot of `dist/` plus `checksums.txt`
- optional 30-second GIF showing the full flow

## 4. Fastest launch path

Use this order:

1. GitHub repo as the first public home
2. GitHub Release as the download location
3. Product Hunt submission pointed at the GitHub repo URL
4. Landing page later if you want a more polished front door

Do not wait on a landing page to launch if the GitHub repo and release are ready.

## 5. Screenshot checklist

Capture these before submitting:

### Screenshot 1: `ueg --validate`

Capture terminal output from:

```powershell
go run ./cmd/ueg --validate
```

What it proves:

- UEG has a built-in proof surface
- the state model validates successfully

### Screenshot 2: command with receipt

Capture terminal output from:

```powershell
go run ./cmd/ueg --receipt .\demo-receipt.json cmd /c echo hello-from-ueg
```

Also show the generated `demo-receipt.json` file in the folder view.

What it proves:

- UEG executes a real command
- UEG creates a receipt artifact

### Screenshot 3: replay `MATCH`

Capture terminal output from:

```powershell
go run ./cmd/ueg --replay .\demo-receipt.json
```

What it proves:

- UEG can replay a receipt
- the replay can verify a deterministic path match

### Screenshot 4: tamper detected

Capture terminal output from replaying a tampered receipt:

```powershell
go run ./cmd/ueg --replay .\demo-receipt-tampered.json
```

What it proves:

- UEG can detect receipt tampering

### Screenshot 5: `dist/` plus `checksums.txt`

Capture a folder or terminal listing showing:

- `ueg-v1.2.0-windows-amd64.zip`
- `ueg-v1.2.0-linux-amd64.zip`
- `ueg-v1.2.0-darwin-amd64.zip`
- `ueg-v1.2.0-darwin-arm64.zip`
- `checksums.txt`

What it proves:

- UEG is packaged for public download
- checksums are included for verification

### Optional GIF

Capture this sequence:

1. `ueg --validate`
2. run command with `--receipt`
3. replay showing `MATCH`
4. tamper with receipt
5. replay showing `TAMPERED`

## 6. Final manual checklist

These are the only things you personally must do in the browser:

- create the public GitHub repo named `UEG`
- copy the repo URL and paste it into the `git remote add origin <PASTE_GITHUB_REPO_URL_HERE>` command
- create the GitHub release `v1.2.0`
- upload the `dist` files to the GitHub release
- create the Product Hunt listing
- upload the screenshots and optional GIF
- submit the Product Hunt launch
