import numpy as np
import seal
from seal import *
import random

# Function to encrypt a vector using homomorphic encryption
def encrypt_vector(context, encoder, encryptor, vec):
    plaintext = Plaintext()
    encoder.encode(vec, scale)
    encryptor.encrypt(plaintext)
    return plaintext

# Function to decrypt a vector using homomorphic encryption
def decrypt_vector(context, encoder, decryptor, ciphertext):
    plaintext = Plaintext()
    decryptor.decrypt(ciphertext, plaintext)
    return encoder.decode(plaintext)

# Generate sample data
# Assume you have a dataset with features (X) and labels (y)
# Here, we generate random data for demonstration purposes
num_samples = 1000
num_features = 6  # Including the intercept term

# Sample data generation (random for demonstration)
X = np.random.rand(num_samples, num_features - 1)  # Exclude intercept term
X_intercept = np.ones((num_samples, 1))  # Add intercept term
X = np.concatenate((X, X_intercept), axis=1)  # Append intercept term to features
y = np.random.randint(2, size=num_samples)  # Binary labels (0 or 1)

# Map feature names to indices
feature_indices = {
    "Age": 0,
    "Income": 1,
    "Credit_score": 2,
    "Number_of_open_credit_accounts": 3,
    "Loan_amount": 4,
    "Loan_term": 5
}

# Select features for encryption
selected_features = ["Age", "Income", "Credit_score", "Number_of_open_credit_accounts", "Loan_amount", "Loan_term"]
X_selected = X[:, [feature_indices[feat] for feat in selected_features]]

# Initialize homomorphic encryption parameters (same as before)
parms = EncryptionParameters(scheme_type.bfv)
poly_modulus_degree = 4096
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))

context = SEALContext(parms)
encoder = BatchEncoder(context)
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()

encryptor = Encryptor(context, public_key)
decryptor = Decryptor(context, secret_key)

# Prepare data for encryption
scale = 2.0 ** 20
X_encrypted = [encrypt_vector(context, encoder, encryptor, x) for x in X_selected]
y_encrypted = encrypt_vector(context, encoder, encryptor, y)

# Train a logistic regression model (same as before)
from sklearn.linear_model import LogisticRegression

# Decrypt training labels (not needed for prediction, just for training)
y_decrypted = decrypt_vector(context, encoder, decryptor, encrypt_vector(context, encoder, encryptor, y))

model = LogisticRegression()
model.fit(X_encrypted, y_encrypted)

# The rest of the code remains the same


# Predict on encrypted data
def predict_on_encrypted_data(model, context, encoder, decryptor, encrypted_data):
    coefficients = model.coef_.flatten()
    intercept = model.intercept_[0]

    encrypted_result = Ciphertext()
    evaluator = Evaluator(context)

    for i in range(len(coefficients)):
        temp = Ciphertext()
        evaluator.multiply_plain(encrypted_data[i], coefficients[i], temp)
        if i == 0:
            encrypted_result = temp
        else:
            evaluator.add(encrypted_result, temp, encrypted_result)

    encrypted_intercept = encrypt_vector(context, encoder, encryptor, np.array([intercept]))
    evaluator.add_plain(encrypted_result, encrypted_intercept, encrypted_result)

    return encrypted_result

# Encrypt model coefficients
model_encrypted = predict_on_encrypted_data(model, context, encoder, decryptor, X_encrypted)

# Decrypt prediction results (not needed for deployment, just for verification)
y_pred_encrypted = predict_on_encrypted_data(model, context, encoder, decryptor, X_encrypted)
y_pred_decrypted = decrypt_vector(context, encoder, decryptor, y_pred_encrypted)
