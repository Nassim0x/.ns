using System.Buffers;
using System.Linq;
using System.Security.Cryptography;

namespace NS.Crypto;

internal sealed partial class NsFileProtector
{
    private enum ContentProcessingMode
    {
        Strict = 1,
        RecoverWithGaps = 2,
        VerifyOnly = 3
    }

    private readonly record struct ContentProcessingResult(
        int TotalChunks,
        int DamagedDataChunks,
        int RepairedDataChunks,
        int DamagedRecoveryBlocks,
        bool HasDataLoss,
        bool UsedRecoveryParity);

    private static NsRecoveryReport BuildRecoveryReport(byte version, NsMetadata metadata, ContentProcessingResult result, bool supportsContainerRepair)
    {
        return new NsRecoveryReport
        {
            Version = version,
            OriginalName = metadata.OriginalName,
            PayloadKind = metadata.PayloadKind,
            PayloadLength = metadata.PayloadLength,
            TotalDataChunks = result.TotalChunks,
            RepairedDataChunks = result.RepairedDataChunks,
            DamagedDataChunks = result.DamagedDataChunks,
            DamagedRecoveryBlocks = result.DamagedRecoveryBlocks,
            HasDataLoss = result.HasDataLoss,
            UsedRecoveryParity = result.UsedRecoveryParity,
            SupportsContainerRepair = supportsContainerRepair
        };
    }

    private static void EncryptContent(
        string sourcePath,
        string destinationPath,
        bool overwrite,
        byte[] headerToWrite,
        byte[] associatedData,
        byte[] metadataCipher,
        byte[] metadataTag,
        byte[] noncePrefix,
        byte[] contentKey,
        byte[] repairKey,
        int chunkSize,
        int recoveryGroupSize,
        long payloadLength,
        IProgress<NsProgressUpdate>? progress)
    {
        EnsureOutputDirectory(destinationPath);
        using var input = File.OpenRead(sourcePath);
        using var contentAes = new AesGcm(contentKey, TagSize);
        using var repairAes = new AesGcm(repairKey, TagSize);
        var tempPath = CreateTemporaryPath(destinationPath);
        var plaintextBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var cipherBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var parityPlainBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var parityCipherBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var tagBuffer = new byte[TagSize];
        var parityTag = new byte[TagSize];
        var nonce = new byte[NonceSize];
        var repairNonce = new byte[NonceSize];

        try
        {
            using (var output = File.Create(tempPath))
            {
                output.Write(headerToWrite);
                output.Write(metadataCipher);
                output.Write(metadataTag);

                uint counter = 1;
                uint parityCounter = 1;
                long processedBytes = 0;
                ReportProgress(progress, "Encrypting", processedBytes, payloadLength);

                while (true)
                {
                    Array.Clear(parityPlainBuffer, 0, parityPlainBuffer.Length);
                    var groupChunkCount = 0;
                    var parityLength = 0;

                    for (var index = 0; index < recoveryGroupSize; index++)
                    {
                        var bytesRead = input.Read(plaintextBuffer, 0, chunkSize);

                        if (bytesRead == 0)
                        {
                            break;
                        }

                        groupChunkCount++;
                        parityLength = Math.Max(parityLength, bytesRead);

                        ComposeNonce(nonce, noncePrefix, counter++);
                        contentAes.Encrypt(
                            nonce,
                            plaintextBuffer.AsSpan(0, bytesRead),
                            cipherBuffer.AsSpan(0, bytesRead),
                            tagBuffer,
                            associatedData);

                        output.Write(cipherBuffer, 0, bytesRead);
                        output.Write(tagBuffer);
                        XorInto(parityPlainBuffer, plaintextBuffer, bytesRead);
                        processedBytes += bytesRead;
                        ReportProgress(progress, "Encrypting", processedBytes, payloadLength);
                    }

                    if (groupChunkCount == 0)
                    {
                        break;
                    }

                    ComposeNonce(repairNonce, noncePrefix, parityCounter++);
                    repairAes.Encrypt(
                        repairNonce,
                        parityPlainBuffer.AsSpan(0, parityLength),
                        parityCipherBuffer.AsSpan(0, parityLength),
                        parityTag,
                        associatedData);

                    output.Write(parityCipherBuffer, 0, parityLength);
                    output.Write(parityTag);
                }

                output.Flush(flushToDisk: true);
            }

            FinalizeOutput(tempPath, destinationPath, overwrite);
        }
        catch
        {
            SafeDelete(tempPath);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBuffer.AsSpan(0, plaintextBuffer.Length));
            CryptographicOperations.ZeroMemory(cipherBuffer.AsSpan(0, cipherBuffer.Length));
            CryptographicOperations.ZeroMemory(parityPlainBuffer.AsSpan(0, parityPlainBuffer.Length));
            CryptographicOperations.ZeroMemory(parityCipherBuffer.AsSpan(0, parityCipherBuffer.Length));
            CryptographicOperations.ZeroMemory(tagBuffer);
            CryptographicOperations.ZeroMemory(parityTag);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(repairNonce);
            ArrayPool<byte>.Shared.Return(plaintextBuffer);
            ArrayPool<byte>.Shared.Return(cipherBuffer);
            ArrayPool<byte>.Shared.Return(parityPlainBuffer);
            ArrayPool<byte>.Shared.Return(parityCipherBuffer);
        }
    }

    private static string RecoverContentToPath(
        Stream sourceStream,
        string destinationPath,
        bool overwrite,
        byte[] associatedData,
        byte[] noncePrefix,
        AesGcm aes,
        int chunkSize,
        long payloadLength,
        IProgress<NsProgressUpdate>? progress)
    {
        EnsureOutputDirectory(destinationPath);
        var tempPath = CreateTemporaryPath(destinationPath);

        try
        {
            using (var output = File.Create(tempPath))
            {
                ProcessContent(sourceStream, output, associatedData, noncePrefix, aes, chunkSize, payloadLength, ContentProcessingMode.RecoverWithGaps, progress);
                output.Flush(flushToDisk: true);
            }

            FinalizeOutput(tempPath, destinationPath, overwrite);
            return destinationPath;
        }
        catch
        {
            SafeDelete(tempPath);
            throw;
        }
    }

    private static ContentProcessingResult ProcessContent(
        Stream sourceStream,
        Stream output,
        byte[] associatedData,
        byte[] noncePrefix,
        AesGcm aes,
        int chunkSize,
        long payloadLength,
        ContentProcessingMode mode,
        IProgress<NsProgressUpdate>? progress)
    {
        var plaintextBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var cipherBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var tagBuffer = new byte[TagSize];
        var nonce = new byte[NonceSize];
        var zeroBuffer = new byte[Math.Min(chunkSize, DefaultChunkSize)];
        var damagedChunks = 0;
        var totalChunks = 0;
        long remaining = payloadLength;
        uint counter = 1;
        long processedBytes = 0;

        try
        {
            ReportProgress(progress, mode == ContentProcessingMode.VerifyOnly ? "Verifying" : "Recovering", processedBytes, payloadLength);

            while (remaining > 0)
            {
                var currentChunkLength = (int)Math.Min(chunkSize, remaining);
                totalChunks++;

                if (!TryReadExact(sourceStream, cipherBuffer.AsSpan(0, currentChunkLength)) ||
                    !TryReadExact(sourceStream, tagBuffer))
                {
                    damagedChunks++;

                    if (mode == ContentProcessingMode.Strict)
                    {
                        throw new InvalidDataException("The .ns file is truncated.");
                    }

                    WriteZeros(output, zeroBuffer, currentChunkLength);
                    processedBytes += currentChunkLength;
                    remaining -= currentChunkLength;
                    ReportProgress(progress, mode == ContentProcessingMode.VerifyOnly ? "Verifying" : "Recovering", processedBytes, payloadLength);

                    while (remaining > 0)
                    {
                        currentChunkLength = (int)Math.Min(chunkSize, remaining);
                        totalChunks++;
                        damagedChunks++;
                        WriteZeros(output, zeroBuffer, currentChunkLength);
                        processedBytes += currentChunkLength;
                        remaining -= currentChunkLength;
                        ReportProgress(progress, mode == ContentProcessingMode.VerifyOnly ? "Verifying" : "Recovering", processedBytes, payloadLength);
                    }

                    break;
                }

                ComposeNonce(nonce, noncePrefix, counter++);

                try
                {
                    aes.Decrypt(
                        nonce,
                        cipherBuffer.AsSpan(0, currentChunkLength),
                        tagBuffer,
                        plaintextBuffer.AsSpan(0, currentChunkLength),
                        associatedData);

                    output.Write(plaintextBuffer, 0, currentChunkLength);
                }
                catch (CryptographicException)
                {
                    damagedChunks++;

                    if (mode == ContentProcessingMode.Strict)
                    {
                        throw;
                    }

                    WriteZeros(output, zeroBuffer, currentChunkLength);
                }

                remaining -= currentChunkLength;
                processedBytes += currentChunkLength;
                ReportProgress(progress, mode == ContentProcessingMode.VerifyOnly ? "Verifying" : "Recovering", processedBytes, payloadLength);
            }

            if (sourceStream.Position != sourceStream.Length)
            {
                if (mode == ContentProcessingMode.Strict)
                {
                    throw new InvalidDataException("The .ns file contains unexpected data.");
                }

                damagedChunks++;
            }

            return new ContentProcessingResult(
                TotalChunks: totalChunks,
                DamagedDataChunks: damagedChunks,
                RepairedDataChunks: 0,
                DamagedRecoveryBlocks: 0,
                HasDataLoss: damagedChunks > 0,
                UsedRecoveryParity: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBuffer.AsSpan(0, plaintextBuffer.Length));
            CryptographicOperations.ZeroMemory(cipherBuffer.AsSpan(0, cipherBuffer.Length));
            CryptographicOperations.ZeroMemory(tagBuffer);
            CryptographicOperations.ZeroMemory(nonce);
            ArrayPool<byte>.Shared.Return(plaintextBuffer);
            ArrayPool<byte>.Shared.Return(cipherBuffer);
        }
    }

    private static ContentProcessingResult RecoverV4PayloadToPath(
        Stream sourceStream,
        string destinationPath,
        bool overwrite,
        byte[] associatedData,
        byte[] noncePrefix,
        byte[] contentKey,
        byte[] repairKey,
        int chunkSize,
        int recoveryGroupSize,
        long payloadLength,
        IProgress<NsProgressUpdate>? progress,
        bool allowDataLoss)
    {
        EnsureOutputDirectory(destinationPath);
        var tempPath = CreateTemporaryPath(destinationPath);

        try
        {
            ContentProcessingResult result;

            using (var output = File.Create(tempPath))
            {
                result = ProcessV4Content(
                    sourceStream,
                    output,
                    associatedData,
                    noncePrefix,
                    contentKey,
                    repairKey,
                    chunkSize,
                    recoveryGroupSize,
                    payloadLength,
                    allowDataLoss ? ContentProcessingMode.RecoverWithGaps : ContentProcessingMode.Strict,
                    progress);
                output.Flush(flushToDisk: true);
            }

            FinalizeOutput(tempPath, destinationPath, overwrite);
            return result;
        }
        catch
        {
            SafeDelete(tempPath);
            throw;
        }
    }

    private static ContentProcessingResult InspectV4Payload(
        Stream sourceStream,
        byte[] associatedData,
        byte[] noncePrefix,
        byte[] contentKey,
        byte[] repairKey,
        int chunkSize,
        int recoveryGroupSize,
        long payloadLength,
        IProgress<NsProgressUpdate>? progress)
    {
        using var sink = Stream.Null;
        return ProcessV4Content(
            sourceStream,
            sink,
            associatedData,
            noncePrefix,
            contentKey,
            repairKey,
            chunkSize,
            recoveryGroupSize,
            payloadLength,
            ContentProcessingMode.VerifyOnly,
            progress);
    }

    private static ContentProcessingResult ProcessV4Content(
        Stream sourceStream,
        Stream output,
        byte[] associatedData,
        byte[] noncePrefix,
        byte[] contentKey,
        byte[] repairKey,
        int chunkSize,
        int recoveryGroupSize,
        long payloadLength,
        ContentProcessingMode mode,
        IProgress<NsProgressUpdate>? progress)
    {
        using var contentAes = new AesGcm(contentKey, TagSize);
        using var repairAes = new AesGcm(repairKey, TagSize);

        var cipherBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var parityCipherBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var parityPlainBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var dataTag = new byte[TagSize];
        var parityTag = new byte[TagSize];
        var dataNonce = new byte[NonceSize];
        var repairNonce = new byte[NonceSize];
        var zeroBuffer = new byte[Math.Min(chunkSize, DefaultChunkSize)];

        var totalChunks = 0;
        var damagedDataChunks = 0;
        var repairedDataChunks = 0;
        var damagedRecoveryBlocks = 0;
        var hasDataLoss = false;
        var usedRecoveryParity = false;
        long remaining = payloadLength;
        uint dataCounter = 1;
        uint parityCounter = 1;
        long processedBytes = 0;

        try
        {
            var progressLabel = mode switch
            {
                ContentProcessingMode.Strict => "Decrypting",
                ContentProcessingMode.VerifyOnly => "Verifying",
                _ => "Recovering"
            };
            ReportProgress(progress, progressLabel, processedBytes, payloadLength);

            while (remaining > 0)
            {
                var groupRemainingStart = remaining;
                var parityLength = (int)Math.Min(chunkSize, groupRemainingStart);
                var groupChunkCount = (int)Math.Min(recoveryGroupSize, (groupRemainingStart + chunkSize - 1) / chunkSize);
                var plaintextChunks = Enumerable.Repeat(Array.Empty<byte>(), groupChunkCount).ToArray();
                var chunkLengths = new int[groupChunkCount];
                var corruptedIndices = new List<int>(capacity: 2);
                var groupTruncated = false;
                var truncatedChunkIndex = -1;

                for (var index = 0; index < groupChunkCount; index++)
                {
                    var currentChunkLength = (int)Math.Min(chunkSize, remaining);
                    chunkLengths[index] = currentChunkLength;
                    totalChunks++;

                    if (!TryReadExact(sourceStream, cipherBuffer.AsSpan(0, currentChunkLength)) ||
                        !TryReadExact(sourceStream, dataTag))
                    {
                        damagedDataChunks++;
                        corruptedIndices.Add(index);
                        groupTruncated = true;
                        truncatedChunkIndex = index;
                        break;
                    }

                    ComposeNonce(dataNonce, noncePrefix, dataCounter++);
                    var plaintextChunk = new byte[currentChunkLength];

                    try
                    {
                        contentAes.Decrypt(
                            dataNonce,
                            cipherBuffer.AsSpan(0, currentChunkLength),
                            dataTag,
                            plaintextChunk,
                            associatedData);

                        plaintextChunks[index] = plaintextChunk;
                    }
                    catch (CryptographicException)
                    {
                        damagedDataChunks++;
                        corruptedIndices.Add(index);
                        plaintextChunks[index] = Array.Empty<byte>();
                    }

                    remaining -= currentChunkLength;
                }

                var parityPresent = TryReadExact(sourceStream, parityCipherBuffer.AsSpan(0, parityLength)) &&
                                    TryReadExact(sourceStream, parityTag);
                var parityValid = false;

                if (parityPresent)
                {
                    ComposeNonce(repairNonce, noncePrefix, parityCounter++);

                    try
                    {
                        repairAes.Decrypt(
                            repairNonce,
                            parityCipherBuffer.AsSpan(0, parityLength),
                            parityTag,
                            parityPlainBuffer.AsSpan(0, parityLength),
                            associatedData);
                        parityValid = true;
                    }
                    catch (CryptographicException)
                    {
                        damagedRecoveryBlocks++;
                    }
                }
                else
                {
                    damagedRecoveryBlocks++;
                }

                if (corruptedIndices.Count == 1 && parityValid)
                {
                    var missingIndex = corruptedIndices[0];
                    var repairedChunk = new byte[chunkLengths[missingIndex]];
                    parityPlainBuffer.AsSpan(0, chunkLengths[missingIndex]).CopyTo(repairedChunk);

                    for (var index = 0; index < groupChunkCount; index++)
                    {
                        if (index == missingIndex || plaintextChunks[index].Length == 0)
                        {
                            continue;
                        }

                        XorInto(repairedChunk, plaintextChunks[index], repairedChunk.Length);
                    }

                    plaintextChunks[missingIndex] = repairedChunk;
                    repairedDataChunks++;
                    usedRecoveryParity = true;
                    corruptedIndices.Clear();
                }

                var canWriteGroup = corruptedIndices.Count == 0 || mode != ContentProcessingMode.Strict;

                if (!canWriteGroup)
                {
                    throw new InvalidDataException("The .ns file contains damage that cannot be repaired automatically.");
                }

                var writableChunkCount = groupTruncated ? truncatedChunkIndex + 1 : groupChunkCount;

                for (var index = 0; index < writableChunkCount; index++)
                {
                    var chunkLength = chunkLengths[index];

                    if (plaintextChunks[index].Length == 0)
                    {
                        WriteZeros(output, zeroBuffer, chunkLength);
                        hasDataLoss = true;

                        if (groupTruncated && index == truncatedChunkIndex)
                        {
                            remaining -= chunkLength;
                        }
                    }
                    else
                    {
                        output.Write(plaintextChunks[index], 0, chunkLength);
                    }

                    processedBytes += chunkLength;
                    ReportProgress(progress, progressLabel, processedBytes, payloadLength);
                }

                if (groupTruncated)
                {
                    while (remaining > 0)
                    {
                        var currentChunkLength = (int)Math.Min(chunkSize, remaining);
                        totalChunks++;
                        damagedDataChunks++;
                        WriteZeros(output, zeroBuffer, currentChunkLength);
                        processedBytes += currentChunkLength;
                        remaining -= currentChunkLength;
                        hasDataLoss = true;
                        ReportProgress(progress, progressLabel, processedBytes, payloadLength);
                    }

                    break;
                }
            }

            if (sourceStream.Position != sourceStream.Length)
            {
                if (mode == ContentProcessingMode.Strict)
                {
                    throw new InvalidDataException("The .ns file contains unexpected data.");
                }

                damagedRecoveryBlocks++;
            }

            if (mode == ContentProcessingMode.Strict && damagedDataChunks > repairedDataChunks)
            {
                throw new InvalidDataException("The .ns file contains damage that cannot be repaired automatically.");
            }

            return new ContentProcessingResult(
                TotalChunks: totalChunks,
                DamagedDataChunks: damagedDataChunks,
                RepairedDataChunks: repairedDataChunks,
                DamagedRecoveryBlocks: damagedRecoveryBlocks,
                HasDataLoss: hasDataLoss,
                UsedRecoveryParity: usedRecoveryParity);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cipherBuffer.AsSpan(0, cipherBuffer.Length));
            CryptographicOperations.ZeroMemory(parityCipherBuffer.AsSpan(0, parityCipherBuffer.Length));
            CryptographicOperations.ZeroMemory(parityPlainBuffer.AsSpan(0, parityPlainBuffer.Length));
            CryptographicOperations.ZeroMemory(dataTag);
            CryptographicOperations.ZeroMemory(parityTag);
            CryptographicOperations.ZeroMemory(dataNonce);
            CryptographicOperations.ZeroMemory(repairNonce);
            ArrayPool<byte>.Shared.Return(cipherBuffer);
            ArrayPool<byte>.Shared.Return(parityCipherBuffer);
            ArrayPool<byte>.Shared.Return(parityPlainBuffer);
        }
    }

    private static bool TryReadExact(Stream stream, Span<byte> buffer)
    {
        var totalRead = 0;

        while (totalRead < buffer.Length)
        {
            var bytesRead = stream.Read(buffer[totalRead..]);

            if (bytesRead == 0)
            {
                return false;
            }

            totalRead += bytesRead;
        }

        return true;
    }

    private static void WriteZeros(Stream output, byte[] zeroBuffer, int length)
    {
        var remaining = length;

        while (remaining > 0)
        {
            var current = Math.Min(remaining, zeroBuffer.Length);
            output.Write(zeroBuffer, 0, current);
            remaining -= current;
        }
    }

    private static void XorInto(byte[] destination, byte[] source, int length)
    {
        for (var index = 0; index < length; index++)
        {
            destination[index] ^= index < source.Length ? source[index] : (byte)0;
        }
    }

    private static string ResolveRecoveryOutputPath(string sourcePath, string? outputPath, NsMetadata metadata, bool exposeRawPayload)
    {
        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            var candidate = Path.GetFullPath(outputPath);

            if (exposeRawPayload && !candidate.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                candidate += ".zip";
            }

            return candidate;
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(sourcePath)) ?? Environment.CurrentDirectory;

        if (exposeRawPayload)
        {
            return Path.Combine(directory, $"{AppendSuffixBeforeExtension(Path.GetFileNameWithoutExtension(sourcePath), ".recovered")}.zip");
        }

        return Path.Combine(directory, AppendSuffixBeforeExtension(metadata.OriginalName, ".recovered"));
    }

    private static string ResolveRepairOutputPath(string sourcePath, string? outputPath)
    {
        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            return Path.GetFullPath(outputPath.EndsWith(".ns", StringComparison.OrdinalIgnoreCase) ? outputPath : $"{outputPath}.ns");
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(sourcePath)) ?? Environment.CurrentDirectory;
        var fileName = Path.GetFileNameWithoutExtension(sourcePath);
        return Path.Combine(directory, $"{AppendSuffixBeforeExtension(fileName, ".repaired")}.ns");
    }

    private static string AppendSuffixBeforeExtension(string fileName, string suffix)
    {
        var extension = Path.GetExtension(fileName);
        var stem = Path.GetFileNameWithoutExtension(fileName);
        return string.IsNullOrWhiteSpace(extension) ? $"{fileName}{suffix}" : $"{stem}{suffix}{extension}";
    }

    private static string CreateTemporaryPayloadPath()
    {
        return Path.Combine(Path.GetTempPath(), $"ns-{Guid.NewGuid():N}.payload");
    }
}
