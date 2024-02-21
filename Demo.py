import numpy as np
import seal

parms = seal.EncryptionParameters(seal.scheme_type.bfv)
parms.set_poly_modulus_degree(4096)
parms.set_coeff_modulus(seal.CoeffModulus.Create(4096, [60, 40])) 
parms.set_plain_modulus(seal.PlainModulus.Batching(4096, 20))
context = seal.SEALContext(parms)

keygen = seal.KeyGenerator(context)
public_key = keygen.create_public_key()
secret_key = keygen.secret_key()

encryptor = seal.Encryptor(context, public_key)
dataset = [10, 20, 30, 40, 50]

encrypted_dataset = [encryptor.encrypt(seal.Plaintext(str(x))) for x in dataset]

print("Encrypted and decrypted values:")
for x, encrypted_data in zip(dataset, encrypted_dataset):
    print("Original value:", x)
    print("Encrypted value:", encrypted_data.to_string())

decryptor = seal.Decryptor(context, secret_key)
print("Original values:")
for encrypted_data in encrypted_dataset:
    decrypted_data = seal.Plaintext()
    decryptor.decrypt(encrypted_data, decrypted_data)
    original_value = int(decrypted_data.to_string())
    print(original_value)



number1 = 5
number2 = 10
encrypted_number1 = encryptor.encrypt(seal.Plaintext(str(number1)))
encrypted_number2 = encryptor.encrypt(seal.Plaintext(str(number2)))

# Perform addition on the encrypted values
encrypted_result = seal.Ciphertext()
seal.Evaluator.square(encrypted_number1)
encrypted_result = encrypted_number1

# Decrypt the result to get the plaintext
decrypted_result = seal.Plaintext()
decryptor.decrypt(encrypted_result, decrypted_result)

# Print the decrypted result
print("Decrypted result of addition:", int(decrypted_result.to_string()))