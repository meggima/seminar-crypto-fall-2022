using System.Numerics;

namespace CryptoPrimitives.BlindSignature;

public class PrimalityChecker : IPrimalityChecker
{
    private readonly IRandom _random;

    public PrimalityChecker(IRandom random)
    {
        _random = random;
    }

    /// <summary>
    ///     Tests whether a given number is prime using the Miller-Rabin primality test
    ///     <see href="https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test"/>.
    ///     
    ///     <para>
    ///         In some cases the algorithm might yield an incorrect result due to its probabilistic nature.
    ///     </para>
    /// </summary>
    /// <param name="number">The number to check for primality.</param>
    /// <returns>True if the number is suspected to be prime. False otherwise.</returns>
    public bool IsPrime(BigInteger number)
    {
        if (number == 2 || number == 3)
        {
            return true;
        }

        if (number < 2 || BigInteger.Remainder(number, 2) == 0)
        {
            return false;
        }

        BigInteger d = number - 1;
        int s = 0;

        while (d % 2 == 0)
        {
            d /= 2;
            s += 1;
        }

        for (int trials = 0; trials < 5; trials++)
        {
            BigInteger a = _random.GetRandomNumber(number - 1);
            BigInteger x = BigInteger.ModPow(a, d, number);

            if (x == 1 || x == number - 1)
            {
                continue;
            }

            for (int r = 1; r < s; r++)
            {
                x = BigInteger.ModPow(x, 2, number);

                if (x == 1)
                {
                    return false;
                }

                if (x == number - 1)
                {
                    break;
                }
            }

            if (x != number - 1)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    ///     Tests whether given numbers <paramref name="a"/> and <paramref name="b"/>
    ///     are co-prime using the euclidean algorithm.
    /// </summary>
    /// <param name="a">The first number.</param>
    /// <param name="b">The second number.</param>
    /// <returns>True if the numbers are co-prime. False otherwise.</returns>
    public bool IsCoprime(BigInteger a, BigInteger b)
    {
        BigInteger aTemp = a;
        BigInteger bTemp = b;

        while (bTemp != 0)
        {
            BigInteger temp = bTemp;
            bTemp = aTemp % bTemp;
            aTemp = temp;
        }

        return aTemp == 1;
    }
}
