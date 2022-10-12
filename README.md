# Cryptographic primitives

This project implements various cryptographic protocols that can be used in applications like electronic voting:

- Blind signatures based on RSA (see [Blind RSA signatures](https://en.wikipedia.org/wiki/Blind_signature#Blind_RSA_signatures))

The project was created during the seminar "Cryptography and Data Security: E-Voting" at the university of Bern, Switzerland in fall 2022.

> The implementations are **NOT** intended for production usage and serve only for demo purposes.

## Getting started

Install the [.NET 6 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/6.0).

The project is packaged as a library and, thus, contains no executable. Instead you can run the tests to see the implementation in action:

Open a terminal and navigate to the root of the project.

Then run the command `dotnet test` to run the tests.