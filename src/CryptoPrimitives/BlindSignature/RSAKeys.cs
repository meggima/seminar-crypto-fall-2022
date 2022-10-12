using System.Numerics;

namespace CryptoPrimitives.BlindSignature;

public record RSAPublicKey(BigInteger N, BigInteger PublicExponent);

public record RSAPrivateKey(BigInteger N, BigInteger PrivateExponent);
