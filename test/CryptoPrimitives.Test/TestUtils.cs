using System.Numerics;
using System.Security.Cryptography;

namespace CryptoPrimitives.Test;

public static class TestUtils
{
    public static BigInteger CreateLargestNumber(int byteLength)
    {
        byte[] bytes = new byte[byteLength];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = 0xFF; // All bits set to 1
        }

        return new BigInteger(bytes, true, true);
    }

    public static byte[] CreateMessage(int length = 100)
    {
        byte[] message = new byte[length];
        RandomNumberGenerator.Fill(message);
        return message;
    }
}
