using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Criptarea_RSA
{
    public class RSA
    {
        private BigInteger p, q, n, phi, e, d;

        public BigInteger PublicKeyN => n;
        public BigInteger PublicKeyE => e;

        public RSA()
        {
            GenerateKeys();
        }

        private void GenerateKeys()
        {
            // Generate two large distinct primes
            p = GenerateLargePrime(512);
            q = GenerateLargePrime(512);
            while (p == q) // Ensure p and q are distinct
            {
                q = GenerateLargePrime(512);
            }

            n = p * q;
            phi = (p - 1) * (q - 1);

            // Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
            e = 65537; // Common public exponent
            if (GCD(e, phi) != 1)
            {
                throw new Exception("e and φ(n) are not coprime. Key generation failed.");
            }

            // Compute the modular inverse of e mod φ(n)
            d = ModInverse(e, phi);
        }

        // Encrypt message: c = m^e mod n
        public BigInteger Encrypt(BigInteger message)
        {
            if (message < 0 || message >= n)
            {
                throw new ArgumentOutOfRangeException(nameof(message), "Message must be in the range [0, n-1].");
            }
            return ModularExponentiation(message, e, n);
        }

        // Decrypt message: m = c^d mod n
        public BigInteger Decrypt(BigInteger cipher)
        {
            if (cipher < 0 || cipher >= n)
            {
                throw new ArgumentOutOfRangeException(nameof(cipher), "Cipher must be in the range [0, n-1].");
            }
            return ModularExponentiation(cipher, d, n);
        }

        private BigInteger GenerateLargePrime(int bits)
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                BigInteger prime;
                do
                {
                    prime = GenerateRandomOddNumber(rng, bits);
                } while (!IsProbablePrime(prime));
                return prime;
            }
        }

        private BigInteger GenerateRandomOddNumber(RandomNumberGenerator rng, int bits)
        {
            byte[] bytes = new byte[bits / 8];
            rng.GetBytes(bytes);
            bytes[bytes.Length - 1] |= 0x80; // Ensure the highest bit is set for correct bit length
            bytes[0] |= 0x01; // Ensure the number is odd
            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        private bool IsProbablePrime(BigInteger n, int k = 10)
        {
            if (n < 2) return false;
            if (n != 2 && n % 2 == 0) return false;

            BigInteger d = n - 1;
            int r = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                r++;
            }

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                for (int i = 0; i < k; i++)
                {
                    BigInteger a = GenerateRandomInRange(rng, 2, n - 2);
                    BigInteger x = ModularExponentiation(a, d, n);
                    if (x == 1 || x == n - 1) continue;

                    bool composite = true;
                    for (int j = 0; j < r - 1; j++)
                    {
                        x = ModularExponentiation(x, 2, n);
                        if (x == n - 1)
                        {
                            composite = false;
                            break;
                        }
                    }
                    if (composite) return false;
                }
            }
            return true;
        }

        private BigInteger GenerateRandomInRange(RandomNumberGenerator rng, BigInteger min, BigInteger max)
        {
            BigInteger range = max - min + 1;
            byte[] bytes = range.ToByteArray(isUnsigned: true, isBigEndian: true);
            BigInteger randomValue;
            do
            {
                rng.GetBytes(bytes);
                randomValue = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            } while (randomValue >= range);
            return randomValue + min;
        }

        private BigInteger GCD(BigInteger a, BigInteger b)
        {
            while (b != 0)
            {
                BigInteger temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        private BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m, t, q;
            BigInteger x0 = 0, x1 = 1;

            while (a > 1)
            {
                q = a / m;
                t = m;

                m = a % m;
                a = t;
                t = x0;

                x0 = x1 - q * x0;
                x1 = t;
            }

            if (x1 < 0) x1 += m0;

            return x1;
        }

        private BigInteger ModularExponentiation(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        {
            BigInteger result = 1;
            baseValue %= modulus;
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                {
                    result = (result * baseValue) % modulus;
                }
                baseValue = (baseValue * baseValue) % modulus;
                exponent >>= 1;
            }
            return result;
        }

        public static void Main()
        {
            RSA rsa = new RSA();
            Console.WriteLine("Cheia publică (n, e):");
            Console.WriteLine($"n: {rsa.PublicKeyN}");
            Console.WriteLine($"e: {rsa.PublicKeyE}");

            BigInteger message = 12345;
            Console.WriteLine($"\nMesajul original: {message}");

            BigInteger cipher = rsa.Encrypt(message);
            Console.WriteLine($"Mesajul criptat: {cipher}");

            BigInteger decryptedMessage = rsa.Decrypt(cipher);
            Console.WriteLine($"Mesajul decriptat: {decryptedMessage}");
        }
    }
}
