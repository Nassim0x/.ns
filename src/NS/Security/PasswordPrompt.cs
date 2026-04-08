using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace NS.Security;

internal sealed class PasswordBundle : IDisposable
{
    public PasswordBundle(char[] password)
    {
        Password = password;
    }

    public char[] Password { get; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(Password.AsSpan()));
    }

    public static PasswordBundle CreateForEncryption()
    {
        while (true)
        {
            var password = PasswordPrompt.ReadSecret("Password: ");
            var confirmation = PasswordPrompt.ReadSecret("Confirm: ");

            if (password.Length == 0)
            {
                Array.Clear(confirmation, 0, confirmation.Length);
                Array.Clear(password, 0, password.Length);
                Console.WriteLine("Password cannot be empty.");
                continue;
            }

            if (password.Length < 12)
            {
                Array.Clear(confirmation, 0, confirmation.Length);
                Array.Clear(password, 0, password.Length);
                Console.WriteLine("Password must be at least 12 characters long.");
                continue;
            }

            if (password.AsSpan().SequenceEqual(confirmation))
            {
                Array.Clear(confirmation, 0, confirmation.Length);
                return new PasswordBundle(password);
            }

            Array.Clear(password, 0, password.Length);
            Array.Clear(confirmation, 0, confirmation.Length);
            Console.WriteLine("Passwords do not match.");
        }
    }

    public static PasswordBundle CreateForDecryption()
    {
        var password = PasswordPrompt.ReadSecret("Password: ");

        if (password.Length == 0)
        {
            Array.Clear(password, 0, password.Length);
            throw new InvalidOperationException("Password cannot be empty.");
        }

        return new PasswordBundle(password);
    }
}

internal static class PasswordPrompt
{
    public static char[] ReadSecret(string prompt)
    {
        Console.Write(prompt);

        if (Console.IsInputRedirected)
        {
            return (Console.ReadLine() ?? string.Empty).ToCharArray();
        }

        var buffer = new List<char>();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return buffer.ToArray();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Count > 0)
                {
                    buffer.RemoveAt(buffer.Count - 1);
                    Console.Write("\b \b");
                }

                continue;
            }

            if (char.IsControl(key.KeyChar))
            {
                continue;
            }

            buffer.Add(key.KeyChar);
            Console.Write('*');
        }
    }
}
