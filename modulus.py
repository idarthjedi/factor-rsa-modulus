import math


def factor(messages: list, cipher_text: list, messages_prime: list, cipher_prime: list):
    """
    This function will factor modulus n given a series of precomputed RSA signatures.  Note: This function is only
    known to work in certain CTF scenarios where the message is converted to a long (e.g. bytes_to_long from pycryptodome)
    and the signature is based directly on the message, and the message is not padded before signed.

    For more information on how this works see:
        https://www.youtube.com/watch?v=4zahvcJ9glg
        https://www.youtube.com/watch?v=oOcTVTpUsPQ
        https://crypto.stackexchange.com/questions/43583/deduce-modulus-n-from-public-exponent-and-encrypted-data

    :param messages: A list of of short messages converted longs (bytes_to_long)
    :param cipher_text: A corresponding list of signatures such that cipher_text[x] = sign(messages[x], privkey)
    :param messages_prime: A list of messages raised to the power of 2, such that
        message_prime[x] = pow(messages[x], 2)
    :param cipher_prime: A list of cipher texts obtained from signing message_prime, such that
        cipher_prime[x] = signature(message_prime, privatekey).
    :return: The greatest common divisor between all the cipher_text[x]^2-cipher_prime[x],..
    """
    # list of gcd arguments to determine the modulus n
    list_of_gcd_arguments = []

    for iterator in range(len(messages)):
        list_of_gcd_arguments.append(pow(cipher_text[iterator], 2) - cipher_prime[iterator])
    derived_n = math.gcd(*list_of_gcd_arguments)

    return derived_n

