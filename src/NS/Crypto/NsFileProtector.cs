using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace NS.Crypto;

internal sealed class NsFileProtector
{
    private static ReadOnlySpan<byte> Magic => "NSF1"u8;

    private const byte Version1 = 1;
    private const byte Version2 = 2;
    private const byte Version3 = 3;

    private const int LegacySaltSize = 16;
    private const int SaltSizeV2 = 32;
    private const int SaltSizeV3 = 32;
    private const int NoncePrefixSize = 8;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int FileKeySize = 32;
    private const int DefaultChunkSize = 64 * 1024;

    private const int LegacyHeaderPrefixSize = 4 + 1 + 4 + 4 + LegacySaltSize + NoncePrefixSize + 4;
    private const int V2HeaderPrefixSize = 4 + 1 + 4 + 4 + SaltSizeV2 + NoncePrefixSize + NonceSize + 4 + NonceSize;
    private const int V3HeaderPrefixSize = 4 + 1 + 4 + 4 + 4 + 4 + SaltSizeV3 + NoncePrefixSize + NonceSize + 4 + NonceSize;
    private const int WrappedSectionSize = FileKeySize + TagSize;
    private const int V2FullHeaderSize = V2HeaderPrefixSize + WrappedSectionSize;
    private const int V3FullHeaderSize = V3HeaderPrefixSize + WrappedSectionSize;

    private const int LegacyIterations = 600_000;
    private const int MaxMetadataSize = 8 * 1024;
    private const int MetadataPaddingBlockSizeV2 = 256;
    private const int MetadataPaddingBlockSizeV3 = 256;
    private const int MinimumEncryptionPasswordLength = 12;
    private const int DefaultArgon2Iterations = 3;
    private const int DefaultArgon2MemorySizeKiB = 64 * 1024;

    public void EncryptFile(string inputPath, string outputPath, ReadOnlySpan<char> password, bool overwrite)
    {
        EnsurePasswordPolicy(password);

        var sourcePath = Path.GetFullPath(inputPath);
        var destinationPath = Path.GetFullPath(outputPath);

        if (!File.Exists(sourcePath) && !Directory.Exists(sourcePath))
        {
            throw new FileNotFoundException("The path to encrypt was not found.", sourcePath);
        }

        EnsureDifferentPaths(sourcePath, destinationPath);

        using var preparedPayload = PrepareEncryptionPayload(sourcePath);
        var metadata = new NsMetadata
        {
            OriginalName = preparedPayload.OriginalName,
            PayloadLength = preparedPayload.PayloadLength,
            PayloadKind = preparedPayload.PayloadKind
        };

        var metadataPayload = metadata.ToV3Bytes();
        var salt = RandomNumberGenerator.GetBytes(SaltSizeV3);
        var noncePrefix = RandomNumberGenerator.GetBytes(NoncePrefixSize);
        var metadataNonce = RandomNumberGenerator.GetBytes(NonceSize);
        var keyWrapNonce = RandomNumberGenerator.GetBytes(NonceSize);
        var fileKey = RandomNumberGenerator.GetBytes(FileKeySize);
        var wrappedFileKey = new byte[FileKeySize];
        var wrappedFileKeyTag = new byte[TagSize];
        var metadataCipher = new byte[metadataPayload.Length];
        var metadataTag = new byte[TagSize];

        var parallelism = Math.Clamp(Environment.ProcessorCount, 1, 4);
        var headerPrefix = BuildV3HeaderPrefix(
            DefaultArgon2Iterations,
            DefaultArgon2MemorySizeKiB,
            parallelism,
            DefaultChunkSize,
            salt,
            noncePrefix,
            metadataNonce,
            metadataPayload.Length,
            keyWrapNonce);

        var passwordKey = DeriveArgon2idPasswordKey(password, salt, DefaultArgon2Iterations, DefaultArgon2MemorySizeKiB, parallelism);

        try
        {
            using (var keyWrapAes = new AesGcm(passwordKey, TagSize))
            {
                keyWrapAes.Encrypt(keyWrapNonce, fileKey, wrappedFileKey, wrappedFileKeyTag, headerPrefix);
            }

            var fullHeader = BuildFullHeader(headerPrefix, wrappedFileKey, wrappedFileKeyTag, V3FullHeaderSize);
            var metadataKey = DeriveSubKey(fileKey, salt, "ns:metadata");
            var contentKey = DeriveSubKey(fileKey, salt, "ns:content");

            try
            {
                using (var metadataAes = new AesGcm(metadataKey, TagSize))
                {
                    metadataAes.Encrypt(metadataNonce, metadataPayload, metadataCipher, metadataTag, fullHeader);
                }

                var contentAssociatedData = BuildContentAssociatedData(fullHeader, metadataCipher, metadataTag);

                try
                {
                    EncryptContent(
                        preparedPayload.PayloadPath,
                        destinationPath,
                        overwrite,
                        fullHeader,
                        contentAssociatedData,
                        metadataCipher,
                        metadataTag,
                        noncePrefix,
                        contentKey);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(contentAssociatedData);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(fullHeader);
                CryptographicOperations.ZeroMemory(metadataKey);
                CryptographicOperations.ZeroMemory(contentKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordKey);
            CryptographicOperations.ZeroMemory(fileKey);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(noncePrefix);
            CryptographicOperations.ZeroMemory(metadataNonce);
            CryptographicOperations.ZeroMemory(keyWrapNonce);
            CryptographicOperations.ZeroMemory(wrappedFileKey);
            CryptographicOperations.ZeroMemory(wrappedFileKeyTag);
            CryptographicOperations.ZeroMemory(metadataPayload);
            CryptographicOperations.ZeroMemory(metadataCipher);
            CryptographicOperations.ZeroMemory(metadataTag);
        }
    }

    public string DecryptFile(string inputPath, string? outputPath, ReadOnlySpan<char> password, bool overwrite)
    {
        var sourcePath = Path.GetFullPath(inputPath);

        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException("The .ns file was not found.", sourcePath);
        }

        using var sourceStream = File.OpenRead(sourcePath);
        var version = ReadVersion(sourceStream);
        sourceStream.Position = 0;

        return version switch
        {
            Version1 => DecryptFileV1(sourceStream, sourcePath, outputPath, password, overwrite),
            Version2 => DecryptFileV2(sourceStream, sourcePath, outputPath, password, overwrite),
            Version3 => DecryptFileV3(sourceStream, sourcePath, outputPath, password, overwrite),
            _ => throw new InvalidDataException("Unsupported .ns version.")
        };
    }

    private string DecryptFileV3(Stream sourceStream, string sourcePath, string? outputPath, ReadOnlySpan<char> password, bool overwrite)
    {
        var headerPrefix = ReadV3HeaderPrefix(
            sourceStream,
            out var iterations,
            out var memorySizeKiB,
            out var parallelism,
            out var chunkSize,
            out var salt,
            out var noncePrefix,
            out var metadataNonce,
            out var metadataLength,
            out var keyWrapNonce);

        var wrappedFileKey = new byte[FileKeySize];
        var wrappedFileKeyTag = new byte[TagSize];
        sourceStream.ReadExactly(wrappedFileKey);
        sourceStream.ReadExactly(wrappedFileKeyTag);

        var passwordKey = DeriveArgon2idPasswordKey(password, salt, iterations, memorySizeKiB, parallelism);
        var fileKey = new byte[FileKeySize];
        var fullHeader = BuildFullHeader(headerPrefix, wrappedFileKey, wrappedFileKeyTag, V3FullHeaderSize);

        try
        {
            try
            {
                using var keyWrapAes = new AesGcm(passwordKey, TagSize);
                keyWrapAes.Decrypt(keyWrapNonce, wrappedFileKey, wrappedFileKeyTag, fileKey, headerPrefix);
            }
            catch (CryptographicException)
            {
                throw new InvalidDataException("Wrong password or modified .ns file.");
            }

            var metadataKey = DeriveSubKey(fileKey, salt, "ns:metadata");
            var contentKey = DeriveSubKey(fileKey, salt, "ns:content");
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
                    var destinationPath = ResolveDecryptPath(sourcePath, outputPath, metadata);
                    var contentAssociatedData = BuildContentAssociatedData(fullHeader, metadataCipher, metadataTag);

                    try
                    {
                        EnsureDifferentPaths(sourcePath, destinationPath);

                        if (metadata.PayloadKind == NsPayloadKind.Directory)
                        {
                            var tempArchivePath = CreateTemporaryArchivePath();

                            try
                            {
                                DecryptContent(sourceStream, tempArchivePath, true, contentAssociatedData, noncePrefix, contentKey, chunkSize, metadata.PayloadLength);
                                RestoreDirectoryPayload(tempArchivePath, destinationPath, overwrite);
                            }
                            finally
                            {
                                SafeDelete(tempArchivePath);
                            }
                        }
                        else
                        {
                            DecryptContent(sourceStream, destinationPath, overwrite, contentAssociatedData, noncePrefix, contentKey, chunkSize, metadata.PayloadLength);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(contentAssociatedData);
                    }

                    return destinationPath;
                }
                catch (CryptographicException)
                {
                    throw new InvalidDataException("Wrong password or modified .ns file.");
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
                CryptographicOperations.ZeroMemory(metadataCipher);
                CryptographicOperations.ZeroMemory(metadataTag);
            }
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

    private string DecryptFileV2(Stream sourceStream, string sourcePath, string? outputPath, ReadOnlySpan<char> password, bool overwrite)
    {
        var headerPrefix = ReadV2HeaderPrefix(
            sourceStream,
            out var iterations,
            out var chunkSize,
            out var salt,
            out var noncePrefix,
            out var metadataNonce,
            out var metadataLength,
            out var keyWrapNonce);

        var wrappedFileKey = new byte[FileKeySize];
        var wrappedFileKeyTag = new byte[TagSize];
        sourceStream.ReadExactly(wrappedFileKey);
        sourceStream.ReadExactly(wrappedFileKeyTag);

        var passwordKey = DeriveLegacyPasswordKey(password, salt, iterations);
        var fileKey = new byte[FileKeySize];
        var fullHeader = BuildFullHeader(headerPrefix, wrappedFileKey, wrappedFileKeyTag, V2FullHeaderSize);

        try
        {
            try
            {
                using var keyWrapAes = new AesGcm(passwordKey, TagSize);
                keyWrapAes.Decrypt(keyWrapNonce, wrappedFileKey, wrappedFileKeyTag, fileKey, headerPrefix);
            }
            catch (CryptographicException)
            {
                throw new InvalidDataException("Wrong password or modified .ns file.");
            }

            var metadataKey = DeriveSubKey(fileKey, salt, "ns:metadata");
            var contentKey = DeriveSubKey(fileKey, salt, "ns:content");
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

                    var metadata = NsMetadata.ParseV2(metadataPayload);
                    var destinationPath = ResolveDecryptPath(sourcePath, outputPath, metadata);
                    var contentAssociatedData = BuildContentAssociatedData(fullHeader, metadataCipher, metadataTag);

                    try
                    {
                        EnsureDifferentPaths(sourcePath, destinationPath);
                        DecryptContent(sourceStream, destinationPath, overwrite, contentAssociatedData, noncePrefix, contentKey, chunkSize, metadata.PayloadLength);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(contentAssociatedData);
                    }

                    return destinationPath;
                }
                catch (CryptographicException)
                {
                    throw new InvalidDataException("Wrong password or modified .ns file.");
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
                CryptographicOperations.ZeroMemory(metadataCipher);
                CryptographicOperations.ZeroMemory(metadataTag);
            }
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

    private string DecryptFileV1(Stream sourceStream, string sourcePath, string? outputPath, ReadOnlySpan<char> password, bool overwrite)
    {
        var headerPrefix = ReadLegacyHeaderPrefix(sourceStream, out var iterations, out var chunkSize, out var salt, out var noncePrefix, out var metadataLength);
        var key = DeriveLegacyPasswordKey(password, salt, iterations);
        var metadataCipher = new byte[metadataLength];
        var metadataTag = new byte[TagSize];

        try
        {
            sourceStream.ReadExactly(metadataCipher);
            sourceStream.ReadExactly(metadataTag);

            using var aes = new AesGcm(key, TagSize);
            var metadataPayload = new byte[metadataLength];

            try
            {
                DecryptMetadataLegacy(aes, headerPrefix, noncePrefix, metadataCipher, metadataTag, metadataPayload);
                var metadata = NsMetadata.ParseLegacy(metadataPayload);
                var destinationPath = ResolveDecryptPath(sourcePath, outputPath, metadata);

                EnsureDifferentPaths(sourcePath, destinationPath);
                DecryptContent(sourceStream, destinationPath, overwrite, headerPrefix, noncePrefix, aes, chunkSize, metadata.PayloadLength);
                return destinationPath;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(metadataPayload);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(headerPrefix);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(metadataCipher);
            CryptographicOperations.ZeroMemory(metadataTag);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(noncePrefix);
        }
    }

    private static PreparedPayload PrepareEncryptionPayload(string sourcePath)
    {
        if (File.Exists(sourcePath))
        {
            return new PreparedPayload(sourcePath, new FileInfo(sourcePath).Length, Path.GetFileName(sourcePath), NsPayloadKind.File);
        }

        if (!Directory.Exists(sourcePath))
        {
            throw new FileNotFoundException("The path to encrypt was not found.", sourcePath);
        }

        EnsureSafeDirectorySource(sourcePath);
        var originalName = GetDirectoryDisplayName(sourcePath);

        if (string.IsNullOrWhiteSpace(originalName))
        {
            throw new InvalidOperationException("Root directories cannot be encrypted directly.");
        }

        var archivePath = CreateTemporaryArchivePath();
        CreateDirectoryArchive(sourcePath, archivePath);
        return new PreparedPayload(archivePath, new FileInfo(archivePath).Length, originalName, NsPayloadKind.Directory, ownsPayloadPath: true);
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
        byte[] contentKey)
    {
        using var aes = new AesGcm(contentKey, TagSize);
        EncryptContent(sourcePath, destinationPath, overwrite, headerToWrite, associatedData, metadataCipher, metadataTag, noncePrefix, aes);
    }

    private static void DecryptContent(
        Stream sourceStream,
        string destinationPath,
        bool overwrite,
        byte[] associatedData,
        byte[] noncePrefix,
        byte[] contentKey,
        int chunkSize,
        long payloadLength)
    {
        using var aes = new AesGcm(contentKey, TagSize);
        DecryptContent(sourceStream, destinationPath, overwrite, associatedData, noncePrefix, aes, chunkSize, payloadLength);
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
        AesGcm aes)
    {
        EnsureOutputDirectory(destinationPath);
        using var input = File.OpenRead(sourcePath);
        var tempPath = CreateTemporaryPath(destinationPath);
        var plaintextBuffer = ArrayPool<byte>.Shared.Rent(DefaultChunkSize);
        var cipherBuffer = ArrayPool<byte>.Shared.Rent(DefaultChunkSize);
        var tagBuffer = new byte[TagSize];
        var nonce = new byte[NonceSize];

        try
        {
            using (var output = File.Create(tempPath))
            {
                output.Write(headerToWrite);
                output.Write(metadataCipher);
                output.Write(metadataTag);

                uint counter = 1;

                while (true)
                {
                    var bytesRead = input.Read(plaintextBuffer, 0, DefaultChunkSize);

                    if (bytesRead == 0)
                    {
                        break;
                    }

                    ComposeNonce(nonce, noncePrefix, counter++);
                    aes.Encrypt(
                        nonce,
                        plaintextBuffer.AsSpan(0, bytesRead),
                        cipherBuffer.AsSpan(0, bytesRead),
                        tagBuffer,
                        associatedData);

                    output.Write(cipherBuffer, 0, bytesRead);
                    output.Write(tagBuffer);
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
            CryptographicOperations.ZeroMemory(tagBuffer);
            CryptographicOperations.ZeroMemory(nonce);
            ArrayPool<byte>.Shared.Return(plaintextBuffer);
            ArrayPool<byte>.Shared.Return(cipherBuffer);
        }
    }

    private static void DecryptMetadataLegacy(
        AesGcm aes,
        byte[] headerPrefix,
        byte[] noncePrefix,
        byte[] metadataCipher,
        byte[] metadataTag,
        byte[] metadataPayload)
    {
        var nonce = new byte[NonceSize];

        try
        {
            ComposeNonce(nonce, noncePrefix, counter: 0);
            aes.Decrypt(nonce, metadataCipher, metadataTag, metadataPayload, headerPrefix);
        }
        catch (CryptographicException)
        {
            throw new InvalidDataException("Wrong password or modified .ns file.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static byte[] BuildV3HeaderPrefix(
        int iterations,
        int memorySizeKiB,
        int parallelism,
        int chunkSize,
        byte[] salt,
        byte[] noncePrefix,
        byte[] metadataNonce,
        int metadataLength,
        byte[] keyWrapNonce)
    {
        var prefix = new byte[V3HeaderPrefixSize];
        Magic.CopyTo(prefix);
        prefix[4] = Version3;
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(5, sizeof(int)), iterations);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(9, sizeof(int)), memorySizeKiB);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(13, sizeof(int)), parallelism);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(17, sizeof(int)), chunkSize);
        salt.CopyTo(prefix.AsSpan(21, SaltSizeV3));
        noncePrefix.CopyTo(prefix.AsSpan(21 + SaltSizeV3, NoncePrefixSize));
        metadataNonce.CopyTo(prefix.AsSpan(21 + SaltSizeV3 + NoncePrefixSize, NonceSize));
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(21 + SaltSizeV3 + NoncePrefixSize + NonceSize, sizeof(int)), metadataLength);
        keyWrapNonce.CopyTo(prefix.AsSpan(21 + SaltSizeV3 + NoncePrefixSize + NonceSize + sizeof(int), NonceSize));
        return prefix;
    }

    private static byte[] BuildFullHeader(byte[] headerPrefix, byte[] wrappedFileKey, byte[] wrappedFileKeyTag, int fullHeaderSize)
    {
        var fullHeader = new byte[fullHeaderSize];
        headerPrefix.CopyTo(fullHeader, 0);
        wrappedFileKey.CopyTo(fullHeader, headerPrefix.Length);
        wrappedFileKeyTag.CopyTo(fullHeader, headerPrefix.Length + wrappedFileKey.Length);
        return fullHeader;
    }

    private static byte[] ReadLegacyHeaderPrefix(
        Stream sourceStream,
        out int iterations,
        out int chunkSize,
        out byte[] salt,
        out byte[] noncePrefix,
        out int metadataLength)
    {
        var prefix = new byte[LegacyHeaderPrefixSize];
        sourceStream.ReadExactly(prefix);

        if (!prefix.AsSpan(0, 4).SequenceEqual(Magic))
        {
            throw new InvalidDataException("This file does not use the expected .ns format.");
        }

        if (prefix[4] != Version1)
        {
            throw new InvalidDataException("Unsupported .ns version.");
        }

        iterations = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(5, sizeof(int)));
        chunkSize = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, sizeof(int)));
        salt = prefix.AsSpan(13, LegacySaltSize).ToArray();
        noncePrefix = prefix.AsSpan(13 + LegacySaltSize, NoncePrefixSize).ToArray();
        metadataLength = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13 + LegacySaltSize + NoncePrefixSize, sizeof(int)));

        if (iterations < 100_000 || iterations > 5_000_000)
        {
            throw new InvalidDataException("Invalid KDF parameter.");
        }

        if (chunkSize < 4 * 1024 || chunkSize > 4 * 1024 * 1024)
        {
            throw new InvalidDataException("Invalid block size.");
        }

        if (metadataLength <= 0 || metadataLength > MaxMetadataSize)
        {
            throw new InvalidDataException("Invalid metadata block.");
        }

        return prefix;
    }

    private static byte[] ReadV2HeaderPrefix(
        Stream sourceStream,
        out int iterations,
        out int chunkSize,
        out byte[] salt,
        out byte[] noncePrefix,
        out byte[] metadataNonce,
        out int metadataLength,
        out byte[] keyWrapNonce)
    {
        var prefix = new byte[V2HeaderPrefixSize];
        sourceStream.ReadExactly(prefix);

        if (!prefix.AsSpan(0, 4).SequenceEqual(Magic))
        {
            throw new InvalidDataException("This file does not use the expected .ns format.");
        }

        if (prefix[4] != Version2)
        {
            throw new InvalidDataException("Unsupported .ns version.");
        }

        iterations = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(5, sizeof(int)));
        chunkSize = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, sizeof(int)));
        salt = prefix.AsSpan(13, SaltSizeV2).ToArray();
        noncePrefix = prefix.AsSpan(13 + SaltSizeV2, NoncePrefixSize).ToArray();
        metadataNonce = prefix.AsSpan(13 + SaltSizeV2 + NoncePrefixSize, NonceSize).ToArray();
        metadataLength = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13 + SaltSizeV2 + NoncePrefixSize + NonceSize, sizeof(int)));
        keyWrapNonce = prefix.AsSpan(13 + SaltSizeV2 + NoncePrefixSize + NonceSize + sizeof(int), NonceSize).ToArray();

        if (iterations < 500_000 || iterations > 20_000_000)
        {
            throw new InvalidDataException("Invalid KDF parameter.");
        }

        if (chunkSize < 4 * 1024 || chunkSize > 4 * 1024 * 1024)
        {
            throw new InvalidDataException("Invalid block size.");
        }

        if (metadataLength <= 0 || metadataLength > MaxMetadataSize || metadataLength % MetadataPaddingBlockSizeV2 != 0)
        {
            throw new InvalidDataException("Invalid metadata block.");
        }

        return prefix;
    }

    private static byte[] ReadV3HeaderPrefix(
        Stream sourceStream,
        out int iterations,
        out int memorySizeKiB,
        out int parallelism,
        out int chunkSize,
        out byte[] salt,
        out byte[] noncePrefix,
        out byte[] metadataNonce,
        out int metadataLength,
        out byte[] keyWrapNonce)
    {
        var prefix = new byte[V3HeaderPrefixSize];
        sourceStream.ReadExactly(prefix);

        if (!prefix.AsSpan(0, 4).SequenceEqual(Magic))
        {
            throw new InvalidDataException("This file does not use the expected .ns format.");
        }

        if (prefix[4] != Version3)
        {
            throw new InvalidDataException("Unsupported .ns version.");
        }

        iterations = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(5, sizeof(int)));
        memorySizeKiB = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, sizeof(int)));
        parallelism = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13, sizeof(int)));
        chunkSize = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(17, sizeof(int)));
        salt = prefix.AsSpan(21, SaltSizeV3).ToArray();
        noncePrefix = prefix.AsSpan(21 + SaltSizeV3, NoncePrefixSize).ToArray();
        metadataNonce = prefix.AsSpan(21 + SaltSizeV3 + NoncePrefixSize, NonceSize).ToArray();
        metadataLength = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(21 + SaltSizeV3 + NoncePrefixSize + NonceSize, sizeof(int)));
        keyWrapNonce = prefix.AsSpan(21 + SaltSizeV3 + NoncePrefixSize + NonceSize + sizeof(int), NonceSize).ToArray();

        if (iterations < 1 || iterations > 10)
        {
            throw new InvalidDataException("Invalid KDF parameter.");
        }

        if (memorySizeKiB < 19 * 1024 || memorySizeKiB > 1024 * 1024)
        {
            throw new InvalidDataException("Invalid KDF memory cost.");
        }

        if (parallelism < 1 || parallelism > 16)
        {
            throw new InvalidDataException("Invalid KDF parallelism.");
        }

        if (chunkSize < 4 * 1024 || chunkSize > 4 * 1024 * 1024)
        {
            throw new InvalidDataException("Invalid block size.");
        }

        if (metadataLength <= 0 || metadataLength > MaxMetadataSize || metadataLength % MetadataPaddingBlockSizeV3 != 0)
        {
            throw new InvalidDataException("Invalid metadata block.");
        }

        return prefix;
    }

    private static byte ReadVersion(Stream sourceStream)
    {
        Span<byte> prelude = stackalloc byte[5];
        sourceStream.ReadExactly(prelude);

        if (!prelude[..4].SequenceEqual(Magic))
        {
            throw new InvalidDataException("This file does not use the expected .ns format.");
        }

        return prelude[4];
    }

    private static void DecryptContent(
        Stream sourceStream,
        string destinationPath,
        bool overwrite,
        byte[] associatedData,
        byte[] noncePrefix,
        AesGcm aes,
        int chunkSize,
        long payloadLength)
    {
        EnsureOutputDirectory(destinationPath);
        var tempPath = CreateTemporaryPath(destinationPath);
        var plaintextBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var cipherBuffer = ArrayPool<byte>.Shared.Rent(chunkSize);
        var tagBuffer = new byte[TagSize];
        var nonce = new byte[NonceSize];

        try
        {
            using (var output = File.Create(tempPath))
            {
                long remaining = payloadLength;
                uint counter = 1;

                while (remaining > 0)
                {
                    var currentChunkLength = (int)Math.Min(chunkSize, remaining);
                    sourceStream.ReadExactly(cipherBuffer.AsSpan(0, currentChunkLength));
                    sourceStream.ReadExactly(tagBuffer);

                    ComposeNonce(nonce, noncePrefix, counter++);
                    aes.Decrypt(
                        nonce,
                        cipherBuffer.AsSpan(0, currentChunkLength),
                        tagBuffer,
                        plaintextBuffer.AsSpan(0, currentChunkLength),
                        associatedData);

                    output.Write(plaintextBuffer, 0, currentChunkLength);
                    remaining -= currentChunkLength;
                }

                if (sourceStream.Position != sourceStream.Length)
                {
                    throw new InvalidDataException("The .ns file contains unexpected data.");
                }

                output.Flush(flushToDisk: true);
            }

            FinalizeOutput(tempPath, destinationPath, overwrite);
        }
        catch (CryptographicException)
        {
            SafeDelete(tempPath);
            throw new InvalidDataException("Wrong password or modified .ns file.");
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
            CryptographicOperations.ZeroMemory(tagBuffer);
            CryptographicOperations.ZeroMemory(nonce);
            ArrayPool<byte>.Shared.Return(plaintextBuffer);
            ArrayPool<byte>.Shared.Return(cipherBuffer);
        }
    }

    private static byte[] DeriveLegacyPasswordKey(ReadOnlySpan<char> password, byte[] salt, int iterations)
    {
        var passwordChars = password.ToArray();
        var passwordBytes = Encoding.UTF8.GetBytes(passwordChars);

        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA512, KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(passwordChars.AsSpan()));
        }
    }

    private static byte[] DeriveArgon2idPasswordKey(ReadOnlySpan<char> password, byte[] salt, int iterations, int memorySizeKiB, int parallelism)
    {
        var passwordChars = password.ToArray();
        var passwordBytes = Encoding.UTF8.GetBytes(passwordChars);
        var associatedData = "NS:V3:ARGON2ID"u8.ToArray();

        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                Iterations = iterations,
                MemorySize = memorySizeKiB,
                DegreeOfParallelism = parallelism,
                AssociatedData = associatedData
            };

            return argon2.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(passwordChars.AsSpan()));
        }
    }

    private static byte[] DeriveSubKey(byte[] inputKeyMaterial, byte[] salt, string context)
    {
        var contextBytes = Encoding.UTF8.GetBytes(context);
        byte[]? pseudoRandomKey = null;

        try
        {
            using (var extract = new HMACSHA512(salt))
            {
                pseudoRandomKey = extract.ComputeHash(inputKeyMaterial);
            }

            var expandInput = new byte[contextBytes.Length + 1];
            contextBytes.CopyTo(expandInput, 0);
            expandInput[^1] = 0x01;

            try
            {
                using var expand = new HMACSHA512(pseudoRandomKey);
                return expand.ComputeHash(expandInput).AsSpan(0, KeySize).ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expandInput);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contextBytes);

            if (pseudoRandomKey is not null)
            {
                CryptographicOperations.ZeroMemory(pseudoRandomKey);
            }
        }
    }

    private static byte[] BuildContentAssociatedData(byte[] fullHeader, byte[] metadataCipher, byte[] metadataTag)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(fullHeader);
        hash.AppendData(metadataCipher);
        hash.AppendData(metadataTag);
        return hash.GetHashAndReset();
    }

    private static void EnsurePasswordPolicy(ReadOnlySpan<char> password)
    {
        if (password.Length < MinimumEncryptionPasswordLength)
        {
            throw new InvalidOperationException("Password must be at least 12 characters long.");
        }
    }

    private static void ComposeNonce(Span<byte> nonce, ReadOnlySpan<byte> prefix, uint counter)
    {
        prefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt32BigEndian(nonce[prefix.Length..], counter);
    }

    private static string ResolveDecryptPath(string sourcePath, string? outputPath, NsMetadata metadata)
    {
        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            return Path.GetFullPath(outputPath);
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(sourcePath)) ?? Environment.CurrentDirectory;
        return Path.Combine(directory, metadata.OriginalName);
    }

    private static void EnsureDifferentPaths(string sourcePath, string destinationPath)
    {
        if (string.Equals(sourcePath, destinationPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Source and output paths must be different.");
        }
    }

    private static string CreateTemporaryPath(string destinationPath)
    {
        var directory = Path.GetDirectoryName(destinationPath) ?? Environment.CurrentDirectory;
        var name = Path.GetFileName(destinationPath);
        return Path.Combine(directory, $".{name}.{Guid.NewGuid():N}.tmp");
    }

    private static string CreateTemporaryArchivePath()
    {
        return Path.Combine(Path.GetTempPath(), $"ns-{Guid.NewGuid():N}.zip");
    }

    private static void EnsureOutputDirectory(string destinationPath)
    {
        var directory = Path.GetDirectoryName(destinationPath);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private static void FinalizeOutput(string tempPath, string destinationPath, bool overwrite)
    {
        if ((File.Exists(destinationPath) || Directory.Exists(destinationPath)) && !overwrite)
        {
            SafeDelete(tempPath);
            throw new IOException("Output path already exists. Use --force to overwrite it.");
        }

        File.Move(tempPath, destinationPath, overwrite);
    }

    private static void CreateDirectoryArchive(string sourceDirectory, string archivePath)
    {
        using var stream = File.Create(archivePath);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: false, entryNameEncoding: Encoding.UTF8);
        var stack = new Stack<string>();
        stack.Push(Path.GetFullPath(sourceDirectory));

        while (stack.Count > 0)
        {
            var currentDirectory = stack.Pop();
            EnsureSafeDirectorySource(currentDirectory);

            foreach (var directory in Directory.GetDirectories(currentDirectory))
            {
                EnsureSafeDirectorySource(directory);
                var relativeDirectory = NormalizeArchiveEntryName(Path.GetRelativePath(sourceDirectory, directory));

                if (!string.IsNullOrEmpty(relativeDirectory))
                {
                    archive.CreateEntry($"{relativeDirectory}/");
                }

                stack.Push(directory);
            }

            foreach (var file in Directory.GetFiles(currentDirectory))
            {
                EnsureSafeFileSource(file);
                var relativeFile = NormalizeArchiveEntryName(Path.GetRelativePath(sourceDirectory, file));
                var entry = archive.CreateEntry(relativeFile, CompressionLevel.NoCompression);
                entry.LastWriteTime = File.GetLastWriteTimeUtc(file);

                using var input = File.OpenRead(file);
                using var output = entry.Open();
                input.CopyTo(output);
            }
        }
    }

    private static void RestoreDirectoryPayload(string archivePath, string destinationPath, bool overwrite)
    {
        var fullDestinationPath = Path.GetFullPath(destinationPath);
        EnsureSafeDirectoryTarget(fullDestinationPath);

        if (File.Exists(fullDestinationPath))
        {
            if (!overwrite)
            {
                throw new IOException("Output path already exists. Use --force to overwrite it.");
            }

            File.Delete(fullDestinationPath);
        }

        if (Directory.Exists(fullDestinationPath))
        {
            if (!overwrite)
            {
                throw new IOException("Output path already exists. Use --force to overwrite it.");
            }

            Directory.Delete(fullDestinationPath, recursive: true);
        }

        Directory.CreateDirectory(fullDestinationPath);

        try
        {
            ExtractDirectoryArchive(archivePath, fullDestinationPath);
        }
        catch
        {
            try
            {
                if (Directory.Exists(fullDestinationPath))
                {
                    Directory.Delete(fullDestinationPath, recursive: true);
                }
            }
            catch
            {
            }

            throw;
        }
    }

    private static void ExtractDirectoryArchive(string archivePath, string destinationDirectory)
    {
        using var archive = ZipFile.OpenRead(archivePath);
        var fullDestination = EnsureTrailingSeparator(Path.GetFullPath(destinationDirectory));

        foreach (var entry in archive.Entries)
        {
            var normalizedEntry = NormalizeArchiveEntryName(entry.FullName);

            if (string.IsNullOrWhiteSpace(normalizedEntry))
            {
                continue;
            }

            var isDirectory = entry.FullName.EndsWith("/", StringComparison.Ordinal);
            var relativePath = isDirectory ? normalizedEntry.TrimEnd('/') : normalizedEntry;
            var targetPath = Path.GetFullPath(Path.Combine(destinationDirectory, relativePath.Replace('/', Path.DirectorySeparatorChar)));

            if (!targetPath.StartsWith(fullDestination, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Corrupted directory payload.");
            }

            if (isDirectory)
            {
                Directory.CreateDirectory(targetPath);
                continue;
            }

            var parentDirectory = Path.GetDirectoryName(targetPath) ?? destinationDirectory;
            Directory.CreateDirectory(parentDirectory);

            using var input = entry.Open();
            using var output = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None);
            input.CopyTo(output);

            try
            {
                File.SetLastWriteTimeUtc(targetPath, entry.LastWriteTime.UtcDateTime);
            }
            catch
            {
            }
        }
    }

    private static string NormalizeArchiveEntryName(string relativePath)
    {
        var normalized = relativePath.Replace('\\', '/').Trim('/');

        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }

        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Any(segment => segment is "." or ".."))
        {
            throw new InvalidDataException("Corrupted directory payload.");
        }

        return string.Join('/', segments);
    }

    private static string EnsureTrailingSeparator(string path)
    {
        return path.EndsWith(Path.DirectorySeparatorChar) || path.EndsWith(Path.AltDirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;
    }

    private static void EnsureSafeDirectorySource(string path)
    {
        var attributes = File.GetAttributes(path);

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("Folders containing reparse points are not supported.");
        }
    }

    private static void EnsureSafeFileSource(string path)
    {
        var attributes = File.GetAttributes(path);

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("Reparse points are not supported inside encrypted folders.");
        }
    }

    private static void EnsureSafeDirectoryTarget(string path)
    {
        var fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (string.IsNullOrWhiteSpace(Path.GetFileName(fullPath)))
        {
            throw new InvalidOperationException("Refusing to overwrite a root directory.");
        }
    }

    private static string GetDirectoryDisplayName(string sourceDirectory)
    {
        var trimmed = sourceDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return Path.GetFileName(trimmed);
    }

    private static void SafeDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    private sealed class PreparedPayload : IDisposable
    {
        public PreparedPayload(string payloadPath, long payloadLength, string originalName, NsPayloadKind payloadKind, bool ownsPayloadPath = false)
        {
            PayloadPath = payloadPath;
            PayloadLength = payloadLength;
            OriginalName = originalName;
            PayloadKind = payloadKind;
            OwnsPayloadPath = ownsPayloadPath;
        }

        public string PayloadPath { get; }

        public long PayloadLength { get; }

        public string OriginalName { get; }

        public NsPayloadKind PayloadKind { get; }

        private bool OwnsPayloadPath { get; }

        public void Dispose()
        {
            if (OwnsPayloadPath)
            {
                SafeDelete(PayloadPath);
            }
        }
    }
}
