using System.Numerics;

namespace CryptoPrimitives.BlindSignature;

public static class BigIntegerExtensions
{
    /// <summary>
    ///     Calculates the multiplicative inverse of <paramref name="number"/> modulo <paramref name="modulus"/>.
    ///     <para>
    ///         Uses the extended euclidean algorithm <see href="https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures"/>
    ///     </para>
    /// </summary>
    /// <param name="number">The number.</param>
    /// <param name="modulus">The modulus.</param>
    /// <returns>The multiplicative inverse of <paramref name="number"/> modulo <paramref name="modulus"/>.</returns>
    public static BigInteger MultiplicativeInverse(this BigInteger number, BigInteger modulus)
    {
        BigInteger t = 0;
        BigInteger newT = 1;
        BigInteger r = modulus;
        BigInteger newR = number;

        while (newR != 0)
        {
            BigInteger q = r / newR;

            BigInteger temp = newR;
            newR = r - q * temp;
            r = temp;

            temp = newT;
            newT = t - q * temp;
            t = temp;
        }

        if (t < 0)
        {
            t += modulus;
        }

        return t;
    }
}
