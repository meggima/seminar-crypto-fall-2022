using System.Numerics;

namespace CryptoPrimitives.Common;

public interface IRandom
{
    BigInteger GetRandomNumber(BigInteger max);
}
