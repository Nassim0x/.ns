namespace NS.Crypto;

internal readonly record struct NsProgressUpdate(string Label, long ProcessedBytes, long TotalBytes)
{
    public static NsProgressUpdate Create(string label, long processedBytes, long totalBytes)
    {
        return new NsProgressUpdate(label, processedBytes, totalBytes);
    }
}
