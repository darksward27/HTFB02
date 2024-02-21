import csv
from Pyfhel import Pyfhel, PyCtxt 

bfv_params = {
    'scheme': 'BFV',    # can also be 'bfv'
    'n': 2**13,         # Polynomial modulus degree, the num. of slots per plaintext,
                        #  of elements to be encoded in a single ciphertext in a
                        #  2 by n/2 rectangular matrix (mind this shape for rotations!)
                        #  Typ. 2^D for D in [10, 16]
    't': 65537,         # Plaintext modulus. Encrypted operations happen modulo t
                        #  Must be prime such that t-1 be divisible by 2^N.
    't_bits': 20,       # Number of bits in t. Used to generate a suitable value
                        #  for t. Overrides t if specified.
    'sec': 128,         # Security parameter. The equivalent length of AES key in bits.
                        #  Sets the ciphertext modulus q, can be one of {128, 192, 256}
                        #  More means more security but also slower computation.
}

def encrypt_data( data):
        HE = Pyfhel()
        HE.contextGen(**bfv_params)
        HE.keyGen()
        encrypted_data = []
        for d in data:
            ctxt = PyCtxt()
            HE.encrypt(ctxt, d)
            encrypted_data.append(ctxt)
        return encrypted_data

hu = encrypt_data(23)

print(hu)