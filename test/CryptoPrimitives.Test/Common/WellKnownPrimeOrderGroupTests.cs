﻿using CryptoPrimitives.Common;
using FluentAssertions;
using System.Globalization;
using System.Numerics;
using Xunit;

namespace CryptoPrimitives.Test.Common;

public class WellKnownPrimeOrderGroupTests
{
    [Fact]
    public void GroupShouldBeCorrect()
    {
        // Test data are taken from RFC 5114
        // https://datatracker.ietf.org/doc/html/rfc5114#appendix-A.3

        // Arrange
        BigInteger privateKey = BigInteger.Parse(
            ("0" +
            "0881382C DB87660C" +
            "6DC13E61 4938D5B9 C8B2F248 581CC5E3 1B354543 97FCE50E").Replace(" ", string.Empty), NumberStyles.AllowHexSpecifier);

        // Act
        BigInteger publicKey = BigInteger.ModPow(WellKnownPrimeOrderGroups.RFC5114_2_3_256.Generator, privateKey, WellKnownPrimeOrderGroups.RFC5114_2_3_256.Prime);

        // Assert

        BigInteger expectedPublicKey = BigInteger.Parse(
           ("0" +
           "2E9380C8 323AF975 45BC4941 DEB0EC37" +
           "42C62FE0 ECE824A6 ABDBE66C 59BEE024 2911BFB9 67235CEB" +
           "A35AE13E 4EC752BE 630B92DC 4BDE2847 A9C62CB8 15274542" +
           "1FB7EB60 A63C0FE9 159FCCE7 26CE7CD8 523D7450 667EF840" +
           "E4919121 EB5F01C8 C9B0D3D6 48A93BFB 75689E82 44AC134A" +
           "F544711C E79A02DC C3422668 4780DDDC B4985941 06C37F5B" +
           "C7985648 7AF5AB02 2A2E5E42 F09897C1 A85A11EA 0212AF04" +
           "D9B4CEBC 937C3C1A 3E15A8A0 342E3376 15C84E7F E3B8B9B8" +
           "7FB1E73A 15AF12A3 0D746E06 DFC34F29 0D797CE5 1AA13AA7" +
           "85BF6658 AFF5E4B0 93003CBE AF665B3C 2E113A3A 4E905269" +
           "341DC071 1426685F 4EF37E86 8A8126FF 3F2279B5 7CA67E29").Replace(" ", string.Empty), NumberStyles.AllowHexSpecifier);

        publicKey.Should().Be(expectedPublicKey);
    }
}
