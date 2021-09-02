"""
Note: This code was written for a very specific CTF, so the RSA functions are *really* lazy
however given the complexity of the maths in deriving the modulus from the signatures (at least for me!)
I used similar methods to generate the RSA keys, in theory this could work for other forms of RSA algorithms
as long as there is no padding.
"""

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, isPrime
import modulus


def create_rsa_key():
    e = getPrime(128)
    while True:
        p, q = getPrime(512), getPrime(512)
        if (p - 1) % e and (q - 1) % e:
            break

    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))

    return p, q, n, e, d


def sign(message, privkey):
    n, d = privkey
    return pow(message, d, n)


def verify(message, signature, pubkey):
    n, e = pubkey
    if pow(signature, e, n) == message:
        return True
    else:
        return False


def main():
    """
    Step 1: Create RSA Key components p, q, n, e, and d
    Step 2: Combine (n,e) and (n, d) into the public and private key respectively
    Step 3: Create a lists to hold messages, cipher text, message_prime and cipher_prime
        As defined in modulus.factor() parameters
    Step 4: Generate a list of messages (recommend 3-4 minimum) convert them to long, and append them to messages
    Step 5: Sign (and verify) all the messages
    Step 6: Create message_primes (e.g. pow(message,2)), create cipher_primes (e.g. sign(message_prime, privkey))
    Step 7: run a baseline test to ensure the maths were create to exploit the multiplicative property of the RSA math
    Step 8: call modulus.factor() to factor the greatest common divisor to derive modulus n
    Step 9: compare divisor_n with known n as a assertion to verify the maths
    :return:
    """
    p, q, n, e, d = create_rsa_key()
    pubkey = (n, e)
    privkey = (n, d)

    # messages to be signed
    m = []
    # cipher text of signatures
    c = []
    # message prime (message^2)
    mp = []
    # cipher of prime (sign(mp)
    cp = []
    # list of gcd arguments to determine the modulus n

    # Append as many additional messages you want to increase the chance for modulus to be found
    m.append(bytes_to_long(b"This is a message"))
    m.append(bytes_to_long(b"This is a second message"))
    m.append(bytes_to_long(b"Another message to test the signature"))
    m.append(bytes_to_long(b"Yet, another message to test the signature"))

    # sign each of the messages (e.g. ciphertext)
    for iterator in range(len(m)):
        c.append(sign(m[iterator], privkey))

        # verify each of the signatures that were just created
        print(f"Signature for m{iterator} Validated") \
            if verify(m[iterator], c[iterator], pubkey) \
            else print(f"Signature m{iterator} NOT valid!")

    # create each message prime and the cipher prime
    for iterator in range(len(m)):
        # Add the message prime, and the cipher for the message prime
        mp.append(pow(m[iterator], 2))
        cp.append(sign(mp[iterator], privkey))

    """
    This section was put together to check the math of the various algorithms using the multiplicative properties
    """
    c1_square_mod_n = pow(c[0], 2, n)
    print(f"cp[0] == pow(c1^2%n)") if cp[0] == c1_square_mod_n else print(f"cp[0] != pow(c1^2%n")

    derived_n = modulus.factor(m, c, mp, cp)

    print(f"Derived Modulus Equals Known Modulus") \
        if derived_n == n \
        else print(f"Derived Modulus DOES NOT Equal Known Modulus")


# With great trumpet and fanfare!!!!
main()

