using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NS.Crypto;

internal enum NsPayloadKind : byte
{
    File = 1,
    Directory = 2
}

internal sealed class NsMetadata
{
    private const int MaxNameLength = 4096;
    private const int PaddingBlockSize = 256;

    public required string OriginalName { get; init; }

    public required long PayloadLength { get; init; }

    public required NsPayloadKind PayloadKind { get; init; }

    public byte[] ToLegacyBytes()
    {
        var nameBytes = Encoding.UTF8.GetBytes(OriginalName);
        var payload = new byte[sizeof(long) + sizeof(int) + nameBytes.Length];

        BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(0, sizeof(long)), PayloadLength);
        BinaryPrimitives.WriteInt32LittleEndian(payload.AsSpan(sizeof(long), sizeof(int)), nameBytes.Length);
        nameBytes.CopyTo(payload.AsSpan(sizeof(long) + sizeof(int)));

        return payload;
    }

    public byte[] ToV3Bytes()
    {
        var nameBytes = Encoding.UTF8.GetBytes(OriginalName);
        var corePayload = new byte[sizeof(byte) + sizeof(long) + sizeof(int) + nameBytes.Length];
        corePayload[0] = (byte)PayloadKind;
        BinaryPrimitives.WriteInt64LittleEndian(corePayload.AsSpan(sizeof(byte), sizeof(long)), PayloadLength);
        BinaryPrimitives.WriteInt32LittleEndian(corePayload.AsSpan(sizeof(byte) + sizeof(long), sizeof(int)), nameBytes.Length);
        nameBytes.CopyTo(corePayload.AsSpan(sizeof(byte) + sizeof(long) + sizeof(int)));
        return Pad(corePayload);
    }

    public static NsMetadata ParseLegacy(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < sizeof(long) + sizeof(int))
        {
            throw new InvalidDataException("Invalid .ns metadata.");
        }

        var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(payload[..sizeof(long)]);
        var nameLength = BinaryPrimitives.ReadInt32LittleEndian(payload.Slice(sizeof(long), sizeof(int)));

        if (payloadLength < 0 || nameLength <= 0 || nameLength > MaxNameLength)
        {
            throw new InvalidDataException("Corrupted .ns metadata.");
        }

        var nameStart = sizeof(long) + sizeof(int);

        if (payload.Length != nameStart + nameLength)
        {
            throw new InvalidDataException("Truncated .ns metadata.");
        }

        var originalName = Encoding.UTF8.GetString(payload.Slice(nameStart, nameLength));

        if (string.IsNullOrWhiteSpace(originalName))
        {
            throw new InvalidDataException("Invalid original name.");
        }

        return new NsMetadata
        {
            OriginalName = Path.GetFileName(originalName),
            PayloadLength = payloadLength,
            PayloadKind = NsPayloadKind.File
        };
    }

    public static NsMetadata ParseV2(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < sizeof(long) + sizeof(int))
        {
            throw new InvalidDataException("Invalid .ns metadata.");
        }

        var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(payload[..sizeof(long)]);
        var nameLength = BinaryPrimitives.ReadInt32LittleEndian(payload.Slice(sizeof(long), sizeof(int)));

        if (payloadLength < 0 || nameLength <= 0 || nameLength > MaxNameLength)
        {
            throw new InvalidDataException("Corrupted .ns metadata.");
        }

        var nameStart = sizeof(long) + sizeof(int);

        if (payload.Length < nameStart + nameLength)
        {
            throw new InvalidDataException("Truncated .ns metadata.");
        }

        var originalName = Encoding.UTF8.GetString(payload.Slice(nameStart, nameLength));

        if (string.IsNullOrWhiteSpace(originalName))
        {
            throw new InvalidDataException("Invalid original name.");
        }

        return new NsMetadata
        {
            OriginalName = Path.GetFileName(originalName),
            PayloadLength = payloadLength,
            PayloadKind = NsPayloadKind.File
        };
    }

    public static NsMetadata ParseV3(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < sizeof(byte) + sizeof(long) + sizeof(int))
        {
            throw new InvalidDataException("Invalid .ns metadata.");
        }

        var payloadKind = payload[0] switch
        {
            (byte)NsPayloadKind.File => NsPayloadKind.File,
            (byte)NsPayloadKind.Directory => NsPayloadKind.Directory,
            _ => throw new InvalidDataException("Unsupported payload type.")
        };

        var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(payload.Slice(sizeof(byte), sizeof(long)));
        var nameLength = BinaryPrimitives.ReadInt32LittleEndian(payload.Slice(sizeof(byte) + sizeof(long), sizeof(int)));

        if (payloadLength < 0 || nameLength <= 0 || nameLength > MaxNameLength)
        {
            throw new InvalidDataException("Corrupted .ns metadata.");
        }

        var nameStart = sizeof(byte) + sizeof(long) + sizeof(int);

        if (payload.Length < nameStart + nameLength)
        {
            throw new InvalidDataException("Truncated .ns metadata.");
        }

        var originalName = Encoding.UTF8.GetString(payload.Slice(nameStart, nameLength));

        if (string.IsNullOrWhiteSpace(originalName))
        {
            throw new InvalidDataException("Invalid original name.");
        }

        return new NsMetadata
        {
            OriginalName = Path.GetFileName(originalName),
            PayloadLength = payloadLength,
            PayloadKind = payloadKind
        };
    }

    private static byte[] Pad(byte[] corePayload)
    {
        var paddedLength = ((corePayload.Length + PaddingBlockSize - 1) / PaddingBlockSize) * PaddingBlockSize;
        var payload = RandomNumberGenerator.GetBytes(paddedLength);

        try
        {
            corePayload.CopyTo(payload, 0);
            return payload;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(corePayload);
        }
    }
}
