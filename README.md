# find RSA Modulus

This code was written to support a CTF on a popular hacking-learning platform.  The CTF included access to an oracle for signatures of an RSA 1024 private key, but no access to the public key.  With a requirement for forging a signature related to a known plain text string.

The maths have been identified in the stackexchange link located at https://crypto.stackexchange.com/questions/43583/deduce-modulus-n-from-public-exponent-and-encrypted-data.

The maths may be a little hard to understand (unless you speak l33t maths), so I converted the MathML/TeX lingo to python code. 

I highly recommend understanding the maths, this code is really here to help you learn the maths, not to help you script-kiddie you're way to the flag. :P

A special thanks to Hilbert on said platform, as he patiently helped me both learn and understand said math l33t speak!

DISCLAIMER:

I make no warranties on the applicability or usefulness of this code.  It has been designed for learning purposes only.

/r DarthJedi
