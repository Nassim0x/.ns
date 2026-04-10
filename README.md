# NS

Secure local file, folder, and drive-content encryption for Windows, designed to stay simple.

NS turns a file, a full folder, or the contents of a drive into a single `.ns` container, then restores it later with the correct password. It is built for people who want strong modern encryption in a normal Windows terminal without dealing with a heavy vault app or a complicated workflow.

## Overview

- encrypts files, folders, and drive contents into a single `.ns` container
- restores the original file or directory structure on decrypt
- uses `AES-256-GCM` authenticated encryption
- uses `Argon2id` for new `.ns` containers
- keeps backward decrypt compatibility with older `.ns` containers
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
.\dist\NS.exe encrypt "C:\Photos\Trip-2026"
.\dist\NS.exe encrypt "E:\" "D:\Backups\drive-e.ns"
.\dist\NS.exe encrypt "C:\Docs\contract.pdf" "C:\Vault\contract"
.\dist\NS.exe decrypt "C:\Docs\contract.pdf.ns"
.\dist\NS.exe decrypt "C:\Photos\Trip-2026.ns" "C:\Restored\Trip-2026" --force
```

If the output path passed to `encrypt` does not end with `.ns`, NS appends it automatically.

## CLI

```text
NS encrypt <path> [output.ns] [--force]
NS decrypt <file.ns> [output] [--force]
NS help
```

Behavior:

- `encrypt` accepts a file, a folder, or a drive root
- `decrypt` restores either a file or a folder, depending on what was originally stored
- `--force` allows overwriting an existing output path
- running `NS.exe` without arguments starts the interactive mode

## Installation

### Portable Windows Binary

The easiest way to use NS is the published executable:

- `dist/NS.exe`

No `dotnet run` step is required.

### Build From Source

```powershell
dotnet build NS.slnx -c Release
dotnet publish .\src\NS\NS.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o dist
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
| Folder and drive handling | packed into an internal archive before encryption |

### What This Means In Practice

For newly created `.ns` files:

- the password is not used as the raw content key
- each container gets fresh random material
- tampering breaks authentication
- identical inputs do not produce identical outputs
- metadata leakage is reduced compared to a naive file wrapper

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

## Limits

NS is intentionally focused.

- it is a local encryption tool, not a vault platform
- it does not hide approximate payload size
- it has not been through a formal third-party security audit
- it is currently built around Windows usage and a Windows binary distribution

## Validation

Latest local validation completed on `2026-04-10`.

Verified locally:

- file encrypt -> decrypt round-trip with matching hash
- folder encrypt -> decrypt round-trip with matching tree and file hashes
- drive-root encrypt -> decrypt round-trip with matching restored tree
- empty folder restoration
- decryption failure with a wrong password
- decryption failure after container tampering
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
