namespace NS.Crypto;

internal enum NsRecoveryStatus
{
    Healthy = 1,
    Degraded = 2,
    SelfRepaired = 3,
    RecoveredWithDataLoss = 4,
    Unrecoverable = 5
}

internal sealed class NsRecoveryReport
{
    public required byte Version { get; init; }

    public required string OriginalName { get; init; }

    public required NsPayloadKind PayloadKind { get; init; }

    public required long PayloadLength { get; init; }

    public required int TotalDataChunks { get; init; }

    public int RepairedDataChunks { get; init; }

    public int DamagedDataChunks { get; init; }

    public int DamagedRecoveryBlocks { get; init; }

    public bool UsedRecoveryParity { get; init; }

    public bool HasDataLoss { get; init; }

    public bool SupportsContainerRepair { get; init; }

    public NsRecoveryStatus Status =>
        HasDataLoss
            ? NsRecoveryStatus.RecoveredWithDataLoss
            : RepairedDataChunks > 0
                ? NsRecoveryStatus.SelfRepaired
                : DamagedDataChunks > 0 || DamagedRecoveryBlocks > 0
                    ? NsRecoveryStatus.Degraded
                    : NsRecoveryStatus.Healthy;
}
