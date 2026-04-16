# NS

Secure local file, folder, and drive-content encryption for Windows, designed to stay simple.

NS turns a file, a full folder, or the contents of a drive into a single `.ns` container, then restores it later with the correct password. It is built for people who want strong modern encryption in a normal Windows terminal without dealing with a heavy vault app or a complicated workflow.

Latest release:

- [v1.3.0](https://github.com/Nassim0x/.ns/releases/tag/v1.3.0)
- [NS.exe](https://github.com/Nassim0x/.ns/releases/download/v1.3.0/NS.exe)
- [NS-Installer.exe](https://github.com/Nassim0x/.ns/releases/download/v1.3.0/NS-Installer.exe)
- [SHA256SUMS.txt](https://github.com/Nassim0x/.ns/releases/download/v1.3.0/SHA256SUMS.txt)

## Overview

- encrypts files, folders, and drive contents into a single `.ns` container
- restores the original file or directory structure on decrypt
- supports optional compression before encryption with `--compress`
- uses `AES-256-GCM` authenticated encryption
- uses `Argon2id` for new `.ns` containers
- new stable containers include built-in recovery blocks for single-chunk self-repair
- keeps backward decrypt compatibility with older `.ns` containers
- shows a live progress bar during preparation, encryption, decryption, and restore
- ships as a portable single-file Windows executable: `dist/NS.exe`

## What NS Is For

NS is a practical file-at-rest protection tool.

It is a good fit for:

- personal archives
- local backups
- sensitive documents
- photo, video, and media folders
- removable drives and secondary data drives
- project exports you want to store or move securely

It is not meant to replace:

- endpoint security
- password managers
- full disk encryption
- secure collaboration platforms

## What It Can Encrypt

NS works with binary and text content alike.

Examples:

- images: `.png`, `.jpg`, `.webp`, `.psd`
- documents: `.pdf`, `.docx`, `.xlsx`, `.txt`
- archives: `.zip`, `.7z`
- executables and installers: `.exe`, `.msi`
- media: `.mp4`, `.mp3`, `.wav`
- full folders with nested files and empty directories
- drive roots such as `E:\`

If Windows can read the file or folder from disk, NS can package and encrypt it.

## Quick Start

Run the portable binary:

```powershell
.\dist\NS.exe
```

That opens the interactive terminal UI.

Direct command examples:

```powershell
.\dist\NS.exe encrypt "C:\Docs\contract.pdf"
.\dist\NS.exe encrypt "C:\Docs\contract.pdf" "C:\Vault\contract.ns" --compress
.\dist\NS.exe encrypt "C:\Photos\Trip-2026"
.\dist\NS.exe encrypt "C:\Photos\Trip-2026" "D:\Backups\trip.ns" --compress
.\dist\NS.exe encrypt "E:\" "D:\Backups\drive-e.ns"
.\dist\NS.exe encrypt "C:\Docs\contract.pdf" "C:\Vault\contract"
.\dist\NS.exe decrypt "C:\Docs\contract.pdf.ns"
.\dist\NS.exe decrypt "C:\Photos\Trip-2026.ns" "C:\Restored\Trip-2026" --force
.\dist\NS.exe verify "C:\Vault\archive.ns"
.\dist\NS.exe recover "C:\Vault\archive.ns"
.\dist\NS.exe repair "C:\Vault\archive.ns"
```

If the output path passed to `encrypt` does not end with `.ns`, NS appends it automatically.

## CLI

```text
NS encrypt <path> [output.ns] [--compress] [--force]
NS decrypt <file.ns> [output] [--force]
NS verify <file.ns>
NS recover <file.ns> [output] [--force]
NS repair <file.ns> [output.ns] [--force]
NS help
```

Behavior:

- `encrypt` accepts a file, a folder, or a drive root
- `decrypt` restores either a file or a folder, depending on what was originally stored
- `--compress` applies ZIP compression before encryption
- `--force` allows overwriting an existing output path
- `verify` inspects the health of a current-format `.ns` container
- `recover` exports what can still be recovered from a damaged current-format `.ns`
- `repair` rebuilds a fresh current-format `.ns` when damage is self-repairable
- running `NS.exe` without arguments starts the interactive mode

## Installation

### Portable Windows Binary

The easiest way to use NS is the published executable:

- `dist/NS.exe`
- `dist/NS-Installer.exe`
- [Latest GitHub release downloads](https://github.com/Nassim0x/.ns/releases/tag/v1.3.0)

No `dotnet run` step is required.

### Mini Installer

If you want a more app-like Windows setup flow, launch:

```powershell
.\dist\NS-Installer.exe
```

The mini installer:

- installs `NS.exe` into `%LocalAppData%\Programs\NS`
- creates Start Menu shortcuts
- can create a desktop shortcut
- can launch NS immediately after install
- registers an uninstall entry for the current user
- triggers the automatic `.ns` shell integration setup

### Windows Shell Integration

Starting `NS.exe` normally on Windows now installs the shell integration automatically for the current user.

That means the first regular launch can automatically enable:

- double-click support for `.ns`
- the NS file icon
- Explorer context menu entries for files, folders, drives, and `.ns` containers

That installs a per-user shell integration under `HKCU\Software\Classes` and copies the active `NS.exe` to:

```text
%LocalAppData%\Programs\NS\NS.exe
```

### Build From Source

```powershell
dotnet build NS.slnx -c Release
dotnet publish .\src\NS\NS.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o dist
dotnet publish .\src\NS.Setup\NS.Setup.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o dist
```

## Security Design

NS uses a layered container format for new `.ns` files.

| Component | Current design |
| --- | --- |
| Cipher | `AES-256-GCM` |
| Password KDF | `Argon2id` |
| Argon2id time cost | `3` |
| Argon2id memory cost | `64 MiB` |
| Argon2id parallelism | up to `4` lanes |
| Salt | `256-bit` random salt per container |
| Per-container key | `256-bit` random content key |
| Key wrapping | content key is encrypted by the password-derived key |
| Key separation | distinct derived keys for metadata and content |
| Metadata protection | encrypted, authenticated, and padded |
| Chunk protection | authenticated block encryption with unique nonces |
| Stability layer | recovery parity blocks per chunk group in the current stable format |
| Folder and drive handling | packed into an internal archive before encryption |

### What This Means In Practice

For newly created `.ns` files:

- the password is not used as the raw content key
- each container gets fresh random material
- tampering breaks authentication
- identical inputs do not produce identical outputs
- metadata leakage is reduced compared to a naive file wrapper
- a single damaged content chunk inside a recovery group can be rebuilt automatically

### What NS Protects Well

- stolen or copied encrypted containers
- offline inspection without the password
- silent modification of encrypted data
- normal local storage scenarios on disk, USB, and cloud-synced folders
- encrypted backups of removable or secondary drives

### What NS Does Not Protect Against

- a weak or reused password
- malware on the machine
- keyloggers
- memory scraping on a compromised host
- password loss
- a full system compromise

That matters: NS uses strong cryptographic building blocks, but no password-based tool is literally "impossible to crack" if the password is weak enough.

## Format and Compatibility

- new containers use the current `.ns` format
- older `.ns` containers remain decryptable
- the `.ns` extension is project-specific and has no standard meaning outside NS

## Folder Support

Folders are first packed into an internal archive, then encrypted into a single `.ns` file.

On restore, NS recreates:

- nested directories
- regular files
- empty directories

For safety, folders containing reparse points, junctions, or similar linked paths are rejected instead of being followed implicitly.

## Compression

Compression is optional and is enabled with `--compress`.

- for a regular file, NS creates a temporary single-file archive, then encrypts it
- for a folder or drive content, NS keeps the same single-container workflow but uses compressed archive entries instead of store-only entries
- if you skip `--compress`, NS still encrypts everything normally

This is mainly useful when:

- the source contains text, documents, or other compressible content
- you want a smaller `.ns` container
- you are packaging a folder and want to reduce archive size before encryption

It is less useful for already-compressed content such as many videos, archives, installers, and some image formats.

## Drive Support

NS can also encrypt the contents of a drive by pointing `encrypt` at the drive root, for example `E:\`.

This is useful for:

- external hard drives
- USB storage
- secondary internal data drives

Important:

- NS packages the contents of the drive into a `.ns` container
- NS does not replace true full-disk encryption products such as BitLocker
- decrypting a drive container restores it as a normal folder unless you explicitly choose another output path

## Operational Notes

- output is written to a temporary path first, then moved into place only on success
- overwrite protection is on by default
- password entry is masked in interactive mode
- file and folder names are restored from encrypted metadata when no explicit output path is given
- large payloads are processed in chunks instead of loading everything into memory at once
- a live progress bar is shown for archive preparation, encryption, decryption, and restore

## Stability and Recovery

Current stable `.ns` containers add a built-in recovery layer on top of chunked authenticated encryption.

- `verify` tells you whether a container is healthy, self-repairable, or only partially recoverable
- `decrypt` automatically rebuilds a single damaged chunk when the matching recovery block is intact
- `repair` creates a fresh healthy `.ns` container when the damaged container can still be rebuilt exactly
- `recover` exports the best possible result even when exact repair is no longer possible

Important:

- exact self-repair is designed for the current stable `.ns` format
- older v1/v2/v3 containers remain decryptable, but they do not have the same built-in repair layer
- when a container is too damaged for exact repair, `recover` may zero-fill unrecoverable chunks instead of pretending the file is intact

## Limits

NS is intentionally focused.

- it is a local encryption tool, not a vault platform
- it does not hide approximate payload size
- it has not been through a formal third-party security audit
- it is currently built around Windows usage and a Windows binary distribution

## Measured Local Security Audit

Latest measured audit completed on `2026-04-13` against newly created current-format `.ns` containers, with repeated local runs to smooth normal machine-to-machine and run-to-run variance.

Audit environment:

- CPU: `AMD Ryzen 5 8400F`
- Threads available: `12`
- RAM: `31.6 GiB`
- OS: `Windows 11 64-bit`
- Binary tested: `dist/NS.exe`
- Audit script: `scripts/SecurityAudit.ps1`

Reproduce locally:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\SecurityAudit.ps1
```

What was measured:

- round-trip integrity with hash comparison
- encryption and decryption throughput on random binary data
- wrong-password rejection timing
- container tamper rejection at multiple offsets
- output non-determinism across two encryptions of the same input
- basic metadata leak check for the original filename
- compression impact on highly compressible text data

### Results

| Check | Measured result |
| --- | --- |
| Random payload size | `32 MiB` |
| Encrypt time | median `319.47 ms` across 3 runs |
| Decrypt time | median `314.73 ms` across 3 runs |
| Encrypt throughput | median `100.19 MiB/s`, observed range `100.17` to `101.98 MiB/s` |
| Decrypt throughput | median `102.37 MiB/s`, observed range `101.67` to `107.53 MiB/s` |
| Container size overhead on 32 MiB random data | `8,601 bytes` (`0.0256%`) |
| Round-trip file hash | `match` |
| Same input encrypted twice | `different container hashes` |
| Original filename visible as plain UTF-8 in container | `not detected` |
| Wrong-password median reject time | `276.31 ms` |
| Wrong-password range across repeated audit runs | `261.77 ms` to `276.31 ms` |
| Approximate wrong-password rejects on this machine | about `3.62` to `3.82 per second` |
| Tamper tests rejected | `6 / 6` |

Tamper cases checked:

- modified magic byte: rejected
- modified wrapped key area: rejected
- modified encrypted metadata area: rejected
- modified ciphertext in the middle of the payload: rejected
- modified last byte of the container: rejected
- appended trailing byte after the container: rejected

Compression test on a highly compressible text file:

- source size: `8,388,611 bytes`
- encrypted container size with `--compress`: `52,854 bytes`
- measured ratio: `0.0063` (`0.63%` of the original size)

### Interpretation

These measured results support the following claims for current-format containers created by the current build:

- NS correctly detects wrong passwords and container tampering in the tested cases
- NS does not produce identical output twice for the same file and password
- NS does not expose the original filename as plain text in the tested containers
- NS adds very little fixed overhead to already incompressible data
- NS can shrink very compressible text payloads substantially when `--compress` is enabled

### Important Caveats

- these are local measurements from one machine, not universal guarantees
- the wrong-password timing is not a formal cracking cost model and should not be treated as one
- a stronger CPU, FPGA, or GPU-assisted attack setup can perform differently
- the audit above covers current-format containers created now, not historical v1/v2 containers kept only for backward decryption compatibility
- no password-based system becomes "impossible to crack" if the password itself is weak, reused, leaked, or guessable
- this is still not a substitute for a formal third-party security review

## Validation

Latest local validation completed on `2026-04-13`.

Verified locally:

- file encrypt -> decrypt round-trip with matching hash
- file encrypt -> decrypt round-trip with optional compression and matching hash
- folder encrypt -> decrypt round-trip with matching tree and file hashes
- folder encrypt -> decrypt round-trip with optional compression and matching tree and file hashes
- drive-root encrypt -> decrypt round-trip with matching restored tree
- empty folder restoration
- decryption failure with a wrong password
- decryption failure after container tampering
- measured audit run with `scripts/SecurityAudit.ps1`
- decrypt compatibility for older `.ns` containers
- published single-file binary execution through `dist/NS.exe`

## Project Layout

```text
.
|-- NS.slnx
|-- README.md
|-- dist
|   `-- NS.exe
`-- src
    `-- NS
        |-- App
        |-- Crypto
        |-- Security
        `-- Program.cs
```

## Sources Behind The KDF Choice

The move to `Argon2id` was chosen based on current primary guidance and standards:

- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Konscious.Security.Cryptography.Argon2 on NuGet](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2)
