import numpy as np
import seal

# Create a SEAL context
parms = seal.EncryptionParameters(seal.scheme_type.bfv)
parms.set_poly_modulus_degree(4096)
parms.set_coeff_modulus(seal.CoeffModulus.Create(4096, [60, 40])) 
parms.set_plain_modulus(seal.PlainModulus.Batching(4096, 20))
context = seal.SEALContext(parms)

# Generate keys
keygen = seal.KeyGenerator(context)
public_key = keygen.create_public_key()
secret_key = keygen.secret_key()

# Create an encryptor
encryptor = seal.Encryptor(context, public_key)
decyptor = seal.Decryptor(context,secret_key)
# Sample dataset (assuming it's a list of integers)
dataset = [10, 20, 30, 40, 50]

# Encrypt the dataset
encrypted_dataset = [encryptor.encrypt(seal.Plaintext(str(x))) for x in dataset]


# Print the encrypted dataset
print("Encrypted dataset:", encrypted_dataset)

