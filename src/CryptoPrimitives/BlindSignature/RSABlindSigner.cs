using System.Numerics;
using System.Security.Cryptography;
using CryptoPrimitives.Common;

namespace CryptoPrimitives.BlindSignature;

/// <summary>
///     Implements a blind signature scheme based on RSA <see href="https://en.wikipedia.org/wiki/Blind_signature#Blind_RSA_signatures"/>.
/// </summary>
public class RSABlindSigner
{
    private readonly IRandom _random;

    private readonly IPrimalityChecker _primalityChecker;

    private readonly SHA1 _hashFunction;

    public RSABlindSigner(IRandom random, IPrimalityChecker primalityChecker)
    {
        _random = random;
        _primalityChecker = primalityChecker;
        _hashFunction = SHA1.Create();
    }

    /// <summary>
    ///     Generates an RSA public/private key pair.
    /// </summary>
    /// <param name="keyLength">The length of the key in bits.</param>
    /// <returns>An RSA public/private key pair.</returns>
    public (RSAPublicKey, RSAPrivateKey) GenerateKey(int keyLength)
    {
        BigInteger p = PickRandomPrime(keyLength);
        BigInteger q = PickRandomPrime(keyLength);

        BigInteger n = p * q;

        BigInteger phi = (p - 1) * (q - 1);

        BigInteger e = FindPublicExponent(keyLength, phi);
        BigInteger d = FindPrivateExponent(phi, e);

        return (new RSAPublicKey(n, e), new RSAPrivateKey(n, d));
    }

    /// <summary>
    ///     Blinds a message.
    /// </summary>
    /// <param name="message">The message to blind.</param>
    /// <param name="verifierKey">The verifier key.</param>
    /// <returns>The blinded message and the blinding factor.</returns>
    public (byte[] BlindedMessage, BigInteger BlindingFactor) Blind(byte[] message, RSAPublicKey verifierKey)
    {
        BigInteger hash = ComputeHash(message, verifierKey.N);
        BigInteger r = _random.GetRandomNumber(verifierKey.N);

        BigInteger blindedMessage = hash * BigInteger.ModPow(r, verifierKey.PublicExponent, verifierKey.N) % verifierKey.N;

        return (blindedMessage.ToByteArray(true, true), r);
    }

    /// <summary>
    ///     Signs a given <paramref name="message"/> using the given <paramref name="signerKey"/>.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <param name="signerKey">The key to use for signing.</param>
    /// <returns>The signature for the <paramref name="message"/>.</returns>
    public BigInteger Sign(byte[] message, RSAPrivateKey signerKey)
    {
        BigInteger blindedMessageAsNumber = new BigInteger(message, true, true);

        BigInteger signature = BigInteger.ModPow(blindedMessageAsNumber, signerKey.PrivateExponent, signerKey.N);

        return signature;
    }

    /// <summary>
    ///     Unblinds a given <paramref name="blindSignature"/> using the given <paramref name="blindingFactor"/>.
    /// </summary>
    /// <param name="blindSignature">The blind signature.</param>
    /// <param name="blindingFactor">The blinding factor.</param>
    /// <param name="verifierKey">The verifier key.</param>
    /// <returns></returns>
    public BigInteger Unblind(BigInteger blindSignature, BigInteger blindingFactor, RSAPublicKey verifierKey)
    {
        return blindSignature * blindingFactor.MultiplicativeInverse(verifierKey.N) % verifierKey.N;
    }

    /// <summary>
    ///     Verifies whether the <paramref name="signature"/> for the given <paramref name="message"/> is valid.
    /// </summary>
    /// <param name="signature">The signature.</param>
    /// <param name="message">The message.</param>
    /// <param name="verifierKey">The verifier key.</param>
    /// <returns>True if the signature is valid. False otherwise.</returns>
    public bool Verify(BigInteger signature, byte[] message, RSAPublicKey verifierKey)
    {
        BigInteger hash = ComputeHash(message, verifierKey.N);
        return BigInteger.ModPow(signature, verifierKey.PublicExponent, verifierKey.N) == hash;
    }

    private BigInteger ComputeHash(byte[] bytes, BigInteger modulus)
    {
        byte[] messageHash = _hashFunction.ComputeHash(bytes);
        return new BigInteger(messageHash, true, true) % modulus;
    }

    private BigInteger PickRandomPrime(int keyLength)
    {
        while (true)
        {
            BigInteger candidate = _random.GetRandomNumber(BigInteger.Pow(2, keyLength));

            if (_primalityChecker.IsPrime(candidate))
            {
                return candidate;
            }
        }
    }

    private BigInteger FindPublicExponent(int keyLength, BigInteger phi)
    {
        while (true)
        {
            BigInteger candidateE = _random.GetRandomNumber(BigInteger.Pow(2, keyLength));

            if (_primalityChecker.IsCoprime(candidateE, phi))
            {
                return candidateE;
            }
        }
    }

    private static BigInteger FindPrivateExponent(BigInteger phi, BigInteger e) => e.MultiplicativeInverse(phi);
}
