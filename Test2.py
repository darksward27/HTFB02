import numpy as np
from Pyfhel import Pyfhel, PyPtxt, PyCtxt

# Create a Pyfhel object
HE = Pyfhel()

# Initialize context with a prime modulus, a security level, and an encryption scheme
HE.contextGen(65537, 128, "HElib")

# Generate encryption keys
HE.keyGen()

# Sample dataset (assuming it's a list of integers)
dataset = [10, 20, 30, 40, 50]

# Encrypt the dataset
encrypted_dataset = []
for x in dataset:
    ptxt = PyPtxt([x], HE)
    ctxt = HE.encrypt(ptxt)
    encrypted_dataset.append(ctxt)

# Print the encrypted dataset
print("Encrypted dataset:", encrypted_dataset)
