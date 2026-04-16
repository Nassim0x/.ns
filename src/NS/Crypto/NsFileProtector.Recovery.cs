using System.Security.Cryptography;

namespace NS.Crypto;

internal sealed partial class NsFileProtector
{
    private string RecoverV4File(Stream sourceStream, string sourcePath, string? outputPath, ReadOnlySpan<char> password, bool overwrite, IProgress<NsProgressUpdate>? progress, out NsRecoveryReport report)
    {
        return DecryptOrRecoverV4File(sourceStream, sourcePath, outputPath, password, overwrite, progress, allowDataLoss: true, recoverArchivesAsPayload: true, out report);
    }

    private NsRecoveryReport VerifyV4File(Stream sourceStream, ReadOnlySpan<char> password, IProgress<NsProgressUpdate>? progress)
    {
        return InspectV4File(sourceStream, password, progress);
    }

    private string RepairV4File(Stream sourceStream, string sourcePath, string? outputPath, ReadOnlySpan<char> password, bool overwrite, IProgress<NsProgressUpdate>? progress, out NsRecoveryReport report)
    {
        var headerPrefix = ReadV4HeaderPrefix(sourceStream, out var iterations, out var memorySizeKiB, out var parallelism, out var chunkSize, out var recoveryGroupSize, out var salt, out var noncePrefix, out var metadataNonce, out var metadataLength, out var keyWrapNonce);
        var wrappedFileKey = new byte[FileKeySize];
        var wrappedFileKeyTag = new byte[TagSize];
        sourceStream.ReadExactly(wrappedFileKey);
        sourceStream.ReadExactly(wrappedFileKeyTag);

        var passwordKey = DeriveArgon2idPasswordKey(password, salt, iterations, memorySizeKiB, parallelism);
        var fileKey = new byte[FileKeySize];
        var fullHeader = BuildFullHeader(headerPrefix, wrappedFileKey, wrappedFileKeyTag, V4FullHeaderSize);

        try
        {
            using (var keyWrapAes = new AesGcm(passwordKey, TagSize))
            {
                keyWrapAes.Decrypt(keyWrapNonce, wrappedFileKey, wrappedFileKeyTag, fileKey, headerPrefix);
            }

            var metadataKey = DeriveSubKey(fileKey, salt, "ns:metadata");
            var contentKey = DeriveSubKey(fileKey, salt, "ns:content");
            var repairKey = DeriveSubKey(fileKey, salt, "ns:repair");
            var metadataCipher = new byte[metadataLength];
            var metadataTag = new byte[TagSize];

            try
            {
                sourceStream.ReadExactly(metadataCipher);
                sourceStream.ReadExactly(metadataTag);

                var metadataPayload = new byte[metadataLength];

                try
                {
                    using (var metadataAes = new AesGcm(metadataKey, TagSize))
                    {
                        metadataAes.Decrypt(metadataNonce, metadataCipher, metadataTag, metadataPayload, fullHeader);
                    }

                    var metadata = NsMetadata.ParseV3(metadataPayload);
                    var contentAssociatedData = BuildContentAssociatedData(fullHeader, metadataCipher, metadataTag);
                    var tempPayloadPath = CreateTemporaryPayloadPath();

                    try
                    {
                        var processingResult = RecoverV4PayloadToPath(sourceStream, tempPayloadPath, overwrite: true, contentAssociatedData, noncePrefix, contentKey, repairKey, chunkSize, recoveryGroupSize, metadata.PayloadLength, progress, allowDataLoss: false);
                        report = BuildRecoveryReport(Version4, metadata, processingResult, supportsContainerRepair: !processingResult.HasDataLoss);

                        if (processingResult.HasDataLoss)
                        {
                            throw new InvalidOperationException("The .ns container cannot be repaired without data loss. Use recover to salvage what remains.");
                        }

                        var repairedOutputPath = ResolveRepairOutputPath(sourcePath, outputPath);
                        EnsureDifferentPaths(sourcePath, repairedOutputPath);
                        using var preparedPayload = new PreparedPayload(tempPayloadPath, metadata.PayloadLength, metadata.OriginalName, metadata.PayloadKind, ownsPayloadPath: true);
                        EncryptPreparedPayload(preparedPayload, repairedOutputPath, password, overwrite, progress);
                        return repairedOutputPath;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(contentAssociatedData);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(metadataPayload);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(metadataKey);
                CryptographicOperations.ZeroMemory(contentKey);
                CryptographicOperations.ZeroMemory(repairKey);
                CryptographicOperations.ZeroMemory(metadataCipher);
                CryptographicOperations.ZeroMemory(metadataTag);
            }
        }
        catch (CryptographicException)
        {
            throw new InvalidDataException("Wrong password or modified .ns file.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(headerPrefix);
            CryptographicOperations.ZeroMemory(fullHeader);
            CryptographicOperations.ZeroMemory(passwordKey);
            CryptographicOperations.ZeroMemory(fileKey);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(noncePrefix);
            CryptographicOperations.ZeroMemory(metadataNonce);
            CryptographicOperations.ZeroMemory(keyWrapNonce);
            CryptographicOperations.ZeroMemory(wrappedFileKey);
            CryptographicOperations.ZeroMemory(wrappedFileKeyTag);
        }
    }

    private NsRecoveryReport InspectV4File(Stream sourceStream, ReadOnlySpan<char> password, IProgress<NsProgressUpdate>? progress)
    {
        var headerPrefix = ReadV4HeaderPrefix(sourceStream, out var iterations, out var memorySizeKiB, out var parallelism, out var chunkSize, out var recoveryGroupSize, out var salt, out var noncePrefix, out var metadataNonce, out var metadataLength, out var keyWrapNonce);
        var wrappedFileKey = new byte[FileKeySize];
        var wrappedFileKeyTag = new byte[TagSize];
        sourceStream.ReadExactly(wrappedFileKey);
        sourceStream.ReadExactly(wrappedFileKeyTag);

        var passwordKey = DeriveArgon2idPasswordKey(password, salt, iterations, memorySizeKiB, parallelism);
        var fileKey = new byte[FileKeySize];
        var fullHeader = BuildFullHeader(headerPrefix, wrappedFileKey, wrappedFileKeyTag, V4FullHeaderSize);

        try
        {
            using (var keyWrapAes = new AesGcm(passwordKey, TagSize))
            {
                keyWrapAes.Decrypt(keyWrapNonce, wrappedFileKey, wrappedFileKeyTag, fileKey, headerPrefix);
            }

            var metadataKey = DeriveSubKey(fileKey, salt, "ns:metadata");
            var contentKey = DeriveSubKey(fileKey, salt, "ns:content");
            var repairKey = DeriveSubKey(fileKey, salt, "ns:repair");
            var metadataCipher = new byte[metadataLength];
            var metadataTag = new byte[TagSize];

            try
            {
                sourceStream.ReadExactly(metadataCipher);
                sourceStream.ReadExactly(metadataTag);

                var metadataPayload = new byte[metadataLength];

                try
                {
                    using (var metadataAes = new AesGcm(metadataKey, TagSize))
                    {
                        metadataAes.Decrypt(metadataNonce, metadataCipher, metadataTag, metadataPayload, fullHeader);
                    }

                    var metadata = NsMetadata.ParseV3(metadataPayload);
                    var contentAssociatedData = BuildContentAssociatedData(fullHeader, metadataCipher, metadataTag);

                    try
                    {
                        var result = InspectV4Payload(sourceStream, contentAssociatedData, noncePrefix, contentKey, repairKey, chunkSize, recoveryGroupSize, metadata.PayloadLength, progress);
                        return BuildRecoveryReport(Version4, metadata, result, supportsContainerRepair: !result.HasDataLoss);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(contentAssociatedData);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(metadataPayload);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(metadataKey);
                CryptographicOperations.ZeroMemory(contentKey);
                CryptographicOperations.ZeroMemory(repairKey);
                CryptographicOperations.ZeroMemory(metadataCipher);
                CryptographicOperations.ZeroMemory(metadataTag);
            }
        }
        catch (CryptographicException)
        {
            throw new InvalidDataException("Wrong password or modified .ns file.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(headerPrefix);
            CryptographicOperations.ZeroMemory(fullHeader);
            CryptographicOperations.ZeroMemory(passwordKey);
            CryptographicOperations.ZeroMemory(fileKey);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(noncePrefix);
            CryptographicOperations.ZeroMemory(metadataNonce);
            CryptographicOperations.ZeroMemory(keyWrapNonce);
            CryptographicOperations.ZeroMemory(wrappedFileKey);
            CryptographicOperations.ZeroMemory(wrappedFileKeyTag);
        }
    }

    private string DecryptOrRecoverV4File(Stream sourceStream, string sourcePath, string? outputPath, ReadOnlySpan<char> password, bool overwrite, IProgress<NsProgressUpdate>? progress, bool allowDataLoss, bool recoverArchivesAsPayload, out NsRecoveryReport report)
    {
        var headerPrefix = ReadV4HeaderPrefix(sourceStream, out var iterations, out var memorySizeKiB, out var parallelism, out var chunkSize, out var recoveryGroupSize, out var salt, out var noncePrefix, out var metadataNonce, out var metadataLength, out var keyWrapNonce);
        var wrappedFileKey = new byte[FileKeySize];
        var wrappedFileKeyTag = new byte[TagSize];
        sourceStream.ReadExactly(wrappedFileKey);
        sourceStream.ReadExactly(wrappedFileKeyTag);

        var passwordKey = DeriveArgon2idPasswordKey(password, salt, iterations, memorySizeKiB, parallelism);
        var fileKey = new byte[FileKeySize];
        var fullHeader = BuildFullHeader(headerPrefix, wrappedFileKey, wrappedFileKeyTag, V4FullHeaderSize);

        try
        {
            using (var keyWrapAes = new AesGcm(passwordKey, TagSize))
            {
                keyWrapAes.Decrypt(keyWrapNonce, wrappedFileKey, wrappedFileKeyTag, fileKey, headerPrefix);
            }

            var metadataKey = DeriveSubKey(fileKey, salt, "ns:metadata");
            var contentKey = DeriveSubKey(fileKey, salt, "ns:content");
            var repairKey = DeriveSubKey(fileKey, salt, "ns:repair");
            var metadataCipher = new byte[metadataLength];
            var metadataTag = new byte[TagSize];

            try
            {
                sourceStream.ReadExactly(metadataCipher);
                sourceStream.ReadExactly(metadataTag);

                var metadataPayload = new byte[metadataLength];

                try
                {
                    using (var metadataAes = new AesGcm(metadataKey, TagSize))
                    {
                        metadataAes.Decrypt(metadataNonce, metadataCipher, metadataTag, metadataPayload, fullHeader);
                    }

                    var metadata = NsMetadata.ParseV3(metadataPayload);
                    var contentAssociatedData = BuildContentAssociatedData(fullHeader, metadataCipher, metadataTag);

                    try
                    {
                        if (!allowDataLoss && !recoverArchivesAsPayload && metadata.PayloadKind is NsPayloadKind.Directory or NsPayloadKind.CompressedFile)
                        {
                            var tempArchivePath = CreateTemporaryArchivePath();

                            try
                            {
                                var processingResult = RecoverV4PayloadToPath(sourceStream, tempArchivePath, overwrite: true, contentAssociatedData, noncePrefix, contentKey, repairKey, chunkSize, recoveryGroupSize, metadata.PayloadLength, progress, allowDataLoss: false);
                                report = BuildRecoveryReport(Version4, metadata, processingResult, supportsContainerRepair: !processingResult.HasDataLoss);

                                var destinationPath = ResolveDecryptPath(sourcePath, outputPath, metadata);
                                EnsureDifferentPaths(sourcePath, destinationPath);

                                if (metadata.PayloadKind == NsPayloadKind.Directory)
                                {
                                    RestoreDirectoryPayload(tempArchivePath, destinationPath, overwrite, progress);
                                }
                                else
                                {
                                    RestoreCompressedFilePayload(tempArchivePath, destinationPath, overwrite, progress);
                                }

                                return destinationPath;
                            }
                            finally
                            {
                                SafeDelete(tempArchivePath);
                            }
                        }

                        var exposeRawPayload = recoverArchivesAsPayload && metadata.PayloadKind is NsPayloadKind.Directory or NsPayloadKind.CompressedFile;
                        var destination = allowDataLoss
                            ? ResolveRecoveryOutputPath(sourcePath, outputPath, metadata, exposeRawPayload)
                            : ResolveDecryptPath(sourcePath, outputPath, metadata);

                        EnsureDifferentPaths(sourcePath, destination);
                        var result = RecoverV4PayloadToPath(sourceStream, destination, overwrite, contentAssociatedData, noncePrefix, contentKey, repairKey, chunkSize, recoveryGroupSize, metadata.PayloadLength, progress, allowDataLoss);
                        report = BuildRecoveryReport(Version4, metadata, result, supportsContainerRepair: !result.HasDataLoss);
                        return destination;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(contentAssociatedData);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(metadataPayload);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(metadataKey);
                CryptographicOperations.ZeroMemory(contentKey);
                CryptographicOperations.ZeroMemory(repairKey);
                CryptographicOperations.ZeroMemory(metadataCipher);
                CryptographicOperations.ZeroMemory(metadataTag);
            }
        }
        catch (CryptographicException)
        {
            throw new InvalidDataException("Wrong password or modified .ns file.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(headerPrefix);
            CryptographicOperations.ZeroMemory(fullHeader);
            CryptographicOperations.ZeroMemory(passwordKey);
            CryptographicOperations.ZeroMemory(fileKey);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(noncePrefix);
            CryptographicOperations.ZeroMemory(metadataNonce);
            CryptographicOperations.ZeroMemory(keyWrapNonce);
            CryptographicOperations.ZeroMemory(wrappedFileKey);
            CryptographicOperations.ZeroMemory(wrappedFileKeyTag);
        }
    }
}
