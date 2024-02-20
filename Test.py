import csv
import seal

def encrypt_attribute(value, encoder, encryptor):
    plain = seal.Plaintext()
    encoder.encode(value, plain)
    encrypted = seal.Ciphertext()
    encryptor.encrypt(plain, encrypted)
    return encrypted

def encrypt_dataset(filename, context, public_key):
    encoder = seal.CKKSEncoder(context)
    encryptor = seal.Encryptor(context, public_key)

    encrypted_dataset = []

    with open(filename, 'r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            encrypted_row = {}
            for attribute in row:
                value = int(row[attribute]) 
                encrypted_value = encrypt_attribute(value, encoder, encryptor)
                encrypted_row[attribute] = encrypted_value
            encrypted_dataset.append(encrypted_row)

    return encrypted_dataset

parms = seal.EncryptionParameters(seal.scheme_type.bfv)
parms.set_poly_modulus_degree(8192)
parms.set_coeff_modulus(seal.CoeffModulus.BFVDefault(8192))
parms.set_plain_modulus(1 << 20)

context = seal.SEALContext(parms)
keygen = seal.KeyGenerator(context)
public_key = keygen.create_public_key()
secret_key = keygen.secret_key()

encrypted_dataset = encrypt_dataset('dataset.csv', context, public_key)

