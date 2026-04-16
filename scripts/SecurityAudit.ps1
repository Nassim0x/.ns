param(
    [string]$BinaryPath = (Join-Path $PSScriptRoot '..\dist\NS.exe'),
    [string]$Password = 'AuditPassword123!',
    [int]$RandomFileSizeMiB = 32,
    [int]$CompressibleFileSizeMiB = 8,
    [int]$WrongPasswordTrials = 5
)

$ErrorActionPreference = 'Stop'

function Invoke-NS {
    param(
        [string[]]$Arguments,
        [string]$InputText
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = $InputText | & $BinaryPath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $sw.Stop()

    [PSCustomObject]@{
        ExitCode = $exitCode
        DurationMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
        Output = ($output | Out-String).Trim()
    }
}

function New-RandomBytesFile {
    param(
        [string]$Path,
        [int]$LengthBytes
    )

    $buffer = New-Object byte[] $LengthBytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $rng.GetBytes($buffer)
        [System.IO.File]::WriteAllBytes($Path, $buffer)
    }
    finally {
        $rng.Dispose()
    }
}

function New-CompressibleFile {
    param(
        [string]$Path,
        [int]$LengthBytes
    )

    $line = ('NS-AUDIT-LINE-' * 16) + "`r`n"
    $builder = New-Object System.Text.StringBuilder

    while ($builder.Length -lt $LengthBytes) {
        [void]$builder.Append($line)
    }

    $text = $builder.ToString().Substring(0, $LengthBytes)
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.Encoding]::UTF8)
}

function Get-FileHashHex {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-Median {
    param([double[]]$Values)

    $sorted = $Values | Sort-Object

    if ($sorted.Count -eq 0) {
        return 0
    }

    if ($sorted.Count % 2 -eq 1) {
        return [math]::Round($sorted[[int]($sorted.Count / 2)], 2)
    }

    return [math]::Round((($sorted[($sorted.Count / 2) - 1] + $sorted[$sorted.Count / 2]) / 2), 2)
}

function Test-AsciiStringAbsent {
    param(
        [string]$ContainerPath,
        [string]$Needle
    )

    $bytes = [System.IO.File]::ReadAllBytes($ContainerPath)
    $needleBytes = [System.Text.Encoding]::UTF8.GetBytes($Needle)

    for ($i = 0; $i -le $bytes.Length - $needleBytes.Length; $i++) {
        $match = $true

        for ($j = 0; $j -lt $needleBytes.Length; $j++) {
            if ($bytes[$i + $j] -ne $needleBytes[$j]) {
                $match = $false
                break
            }
        }

        if ($match) {
            return $false
        }
    }

    return $true
}

function New-TamperedCopy {
    param(
        [string]$SourcePath,
        [string]$TargetPath,
        [ValidateSet('flip', 'append')]
        [string]$Mode,
        [long]$Offset = 0
    )

    Copy-Item -LiteralPath $SourcePath -Destination $TargetPath -Force

    if ($Mode -eq 'append') {
        $stream = [System.IO.File]::Open($TargetPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $stream.WriteByte(0x7A)
        }
        finally {
            $stream.Dispose()
        }

        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($TargetPath)
    $bytes[$Offset] = $bytes[$Offset] -bxor 0x01
    [System.IO.File]::WriteAllBytes($TargetPath, $bytes)
}

if (-not (Test-Path -LiteralPath $BinaryPath)) {
    throw "NS binary not found at $BinaryPath"
}

$root = Join-Path $env:TEMP ('ns-security-audit-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null

try {
    $randomFile = Join-Path $root 'audit-random.bin'
    $compressibleFile = Join-Path $root 'audit-text.txt'
    $restoredRandomFile = Join-Path $root 'audit-random-restored.bin'
    $restoredCompressibleFile = Join-Path $root 'audit-text-restored.txt'
    $randomContainer = Join-Path $root 'audit-random.ns'
    $randomContainer2 = Join-Path $root 'audit-random-second.ns'
    $compressibleContainer = Join-Path $root 'audit-text.ns'

    New-RandomBytesFile -Path $randomFile -LengthBytes ($RandomFileSizeMiB * 1MB)
    New-CompressibleFile -Path $compressibleFile -LengthBytes ($CompressibleFileSizeMiB * 1MB)

    $encryptInput = "$Password`r`n$Password`r`n"
    $decryptInput = "$Password`r`n"

    $randomEncryptResult = Invoke-NS -Arguments @('encrypt', $randomFile, $randomContainer) -InputText $encryptInput
    $randomDecryptResult = Invoke-NS -Arguments @('decrypt', $randomContainer, $restoredRandomFile, '--force') -InputText $decryptInput
    $randomEncryptResult2 = Invoke-NS -Arguments @('encrypt', $randomFile, $randomContainer2) -InputText $encryptInput

    $compressibleEncryptResult = Invoke-NS -Arguments @('encrypt', $compressibleFile, $compressibleContainer, '--compress') -InputText $encryptInput
    $compressibleDecryptResult = Invoke-NS -Arguments @('decrypt', $compressibleContainer, $restoredCompressibleFile, '--force') -InputText $decryptInput

    if ($randomEncryptResult.ExitCode -ne 0 -or $randomDecryptResult.ExitCode -ne 0 -or
        $randomEncryptResult2.ExitCode -ne 0 -or $compressibleEncryptResult.ExitCode -ne 0 -or
        $compressibleDecryptResult.ExitCode -ne 0) {
        throw 'One of the baseline audit encrypt/decrypt operations failed.'
    }

    $wrongPasswordDurations = New-Object System.Collections.Generic.List[double]

    for ($trial = 0; $trial -lt $WrongPasswordTrials; $trial++) {
        $wrongResult = Invoke-NS -Arguments @('decrypt', $randomContainer, (Join-Path $root ("wrong-$trial.bin")), '--force') -InputText "WrongPassword123!`r`n"

        if ($wrongResult.ExitCode -eq 0) {
            throw 'Wrong-password test unexpectedly succeeded.'
        }

        [void]$wrongPasswordDurations.Add($wrongResult.DurationMs)
    }

    $randomLength = (Get-Item -LiteralPath $randomFile).Length
    $randomContainerLength = (Get-Item -LiteralPath $randomContainer).Length
    $compressibleLength = (Get-Item -LiteralPath $compressibleFile).Length
    $compressibleContainerLength = (Get-Item -LiteralPath $compressibleContainer).Length

    $tamperOffsets = @(
        [PSCustomObject]@{ Name = 'magic-byte'; Mode = 'flip'; Offset = 0L },
        [PSCustomObject]@{ Name = 'wrapped-key'; Mode = 'flip'; Offset = 96L },
        [PSCustomObject]@{ Name = 'metadata'; Mode = 'flip'; Offset = 176L },
        [PSCustomObject]@{ Name = 'ciphertext-middle'; Mode = 'flip'; Offset = [math]::Floor($randomContainerLength / 2) },
        [PSCustomObject]@{ Name = 'last-byte'; Mode = 'flip'; Offset = $randomContainerLength - 1L },
        [PSCustomObject]@{ Name = 'trailing-byte'; Mode = 'append'; Offset = 0L }
    )

    $tamperResults = @()

    foreach ($case in $tamperOffsets) {
        $tamperedPath = Join-Path $root ("tampered-" + $case.Name + '.ns')
        New-TamperedCopy -SourcePath $randomContainer -TargetPath $tamperedPath -Mode $case.Mode -Offset $case.Offset
        $tamperDecryptResult = Invoke-NS -Arguments @('decrypt', $tamperedPath, (Join-Path $root ($case.Name + '.bin')), '--force') -InputText $decryptInput

        $tamperResults += [PSCustomObject]@{
            Case = $case.Name
            Rejected = ($tamperDecryptResult.ExitCode -ne 0)
            DurationMs = $tamperDecryptResult.DurationMs
        }
    }

    $results = [PSCustomObject]@{
        AuditDate = (Get-Date).ToString('yyyy-MM-dd')
        Machine = [PSCustomObject]@{
            CPU = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)
            LogicalProcessors = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty NumberOfLogicalProcessors)
            RAMGiB = [math]::Round(((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB), 1)
            OS = ((Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).OSArchitecture)
        }
        RandomFile = [PSCustomObject]@{
            SizeBytes = $randomLength
            EncryptMs = $randomEncryptResult.DurationMs
            DecryptMs = $randomDecryptResult.DurationMs
            EncryptMiBs = [math]::Round(($randomLength / 1MB) / ($randomEncryptResult.DurationMs / 1000), 2)
            DecryptMiBs = [math]::Round(($randomLength / 1MB) / ($randomDecryptResult.DurationMs / 1000), 2)
            ContainerBytes = $randomContainerLength
            OverheadBytes = $randomContainerLength - $randomLength
            RoundTripHashMatch = ((Get-FileHashHex $randomFile) -eq (Get-FileHashHex $restoredRandomFile))
            IdenticalOutputAcrossTwoEncryptions = ((Get-FileHashHex $randomContainer) -eq (Get-FileHashHex $randomContainer2))
            OriginalFilenameVisibleInContainer = -not (Test-AsciiStringAbsent -ContainerPath $randomContainer -Needle (Split-Path $randomFile -Leaf))
        }
        CompressibleFile = [PSCustomObject]@{
            SizeBytes = $compressibleLength
            EncryptMs = $compressibleEncryptResult.DurationMs
            DecryptMs = $compressibleDecryptResult.DurationMs
            ContainerBytes = $compressibleContainerLength
            CompressionRatio = [math]::Round($compressibleContainerLength / $compressibleLength, 4)
            RoundTripHashMatch = ((Get-FileHashHex $compressibleFile) -eq (Get-FileHashHex $restoredCompressibleFile))
            OriginalFilenameVisibleInContainer = -not (Test-AsciiStringAbsent -ContainerPath $compressibleContainer -Needle (Split-Path $compressibleFile -Leaf))
        }
        WrongPassword = [PSCustomObject]@{
            Trials = $WrongPasswordTrials
            MedianRejectMs = (Get-Median $wrongPasswordDurations.ToArray())
            MinRejectMs = [math]::Round(($wrongPasswordDurations | Measure-Object -Minimum).Minimum, 2)
            MaxRejectMs = [math]::Round(($wrongPasswordDurations | Measure-Object -Maximum).Maximum, 2)
            ApproxRejectsPerSecond = [math]::Round(1000 / (Get-Median $wrongPasswordDurations.ToArray()), 2)
        }
        Tamper = [PSCustomObject]@{
            Cases = $tamperResults
            RejectedAll = -not ($tamperResults | Where-Object { -not $_.Rejected })
        }
    }

    $results | ConvertTo-Json -Depth 6
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
