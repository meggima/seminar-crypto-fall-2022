using System.Numerics;

namespace CryptoPrimitives.BlindSignature;

public interface IRandom
{
    BigInteger GetRandomNumber(BigInteger max);
}
