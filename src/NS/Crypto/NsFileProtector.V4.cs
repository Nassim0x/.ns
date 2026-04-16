using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NS.Crypto;

internal sealed partial class NsFileProtector
{
    private static byte[] BuildV4HeaderPrefix(
        int iterations,
        int memorySizeKiB,
        int parallelism,
        int chunkSize,
        int recoveryGroupSize,
        byte[] salt,
        byte[] noncePrefix,
        byte[] metadataNonce,
        int metadataLength,
        byte[] keyWrapNonce)
    {
        var prefix = new byte[V4HeaderPrefixSize];
        Magic.CopyTo(prefix);
        prefix[4] = Version4;
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(5, sizeof(int)), iterations);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(9, sizeof(int)), memorySizeKiB);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(13, sizeof(int)), parallelism);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(17, sizeof(int)), chunkSize);
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(21, sizeof(int)), recoveryGroupSize);
        salt.CopyTo(prefix.AsSpan(25, SaltSizeV3));
        noncePrefix.CopyTo(prefix.AsSpan(25 + SaltSizeV3, NoncePrefixSize));
        metadataNonce.CopyTo(prefix.AsSpan(25 + SaltSizeV3 + NoncePrefixSize, NonceSize));
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(25 + SaltSizeV3 + NoncePrefixSize + NonceSize, sizeof(int)), metadataLength);
        keyWrapNonce.CopyTo(prefix.AsSpan(25 + SaltSizeV3 + NoncePrefixSize + NonceSize + sizeof(int), NonceSize));
        return prefix;
    }

    private static byte[] ReadV4HeaderPrefix(
        Stream sourceStream,
        out int iterations,
        out int memorySizeKiB,
        out int parallelism,
        out int chunkSize,
        out int recoveryGroupSize,
        out byte[] salt,
        out byte[] noncePrefix,
        out byte[] metadataNonce,
        out int metadataLength,
        out byte[] keyWrapNonce)
    {
        var prefix = new byte[V4HeaderPrefixSize];
        sourceStream.ReadExactly(prefix);

        if (!prefix.AsSpan(0, 4).SequenceEqual(Magic))
        {
            throw new InvalidDataException("This file does not use the expected .ns format.");
        }

        if (prefix[4] != Version4)
        {
            throw new InvalidDataException("Unsupported .ns version.");
        }

        iterations = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(5, sizeof(int)));
        memorySizeKiB = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(9, sizeof(int)));
        parallelism = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(13, sizeof(int)));
        chunkSize = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(17, sizeof(int)));
        recoveryGroupSize = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(21, sizeof(int)));
        salt = prefix.AsSpan(25, SaltSizeV3).ToArray();
        noncePrefix = prefix.AsSpan(25 + SaltSizeV3, NoncePrefixSize).ToArray();
        metadataNonce = prefix.AsSpan(25 + SaltSizeV3 + NoncePrefixSize, NonceSize).ToArray();
        metadataLength = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(25 + SaltSizeV3 + NoncePrefixSize + NonceSize, sizeof(int)));
        keyWrapNonce = prefix.AsSpan(25 + SaltSizeV3 + NoncePrefixSize + NonceSize + sizeof(int), NonceSize).ToArray();

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

        if (recoveryGroupSize < 1 || recoveryGroupSize > 256)
        {
            throw new InvalidDataException("Invalid recovery group size.");
        }

        if (metadataLength <= 0 || metadataLength > MaxMetadataSize || metadataLength % MetadataPaddingBlockSizeV3 != 0)
        {
            throw new InvalidDataException("Invalid metadata block.");
        }

        return prefix;
    }
}
