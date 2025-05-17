#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

std::string generate_ecdsa_key() {
  // 1. Create EC_KEY object with SECP256R1 curve
  EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!key) {
    throw std::runtime_error("Failed to create key object");
  }

  // 2. Generate the key pair
  if (!EC_KEY_generate_key(key)) {
    EC_KEY_free(key);
    throw std::runtime_error("Failed to generate key");
  }

  // 3. Write private key to a string (PEM format) using BIO
  BIO *bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_ECPrivateKey(bio, key, nullptr, nullptr, 0, nullptr,
                                  nullptr)) {
    BIO_free(bio);
    EC_KEY_free(key);
    throw std::runtime_error("Failed to write private key");
  }

  char *data;
  long len = BIO_get_mem_data(bio, &data);
  std::string private_key(data, len);

  // 4. Write public key to a string (PEM format) using BIO
  BIO_reset(bio);
  if (!PEM_write_bio_EC_PUBKEY(bio, key)) {
    BIO_free(bio);
    EC_KEY_free(key);
    throw std::runtime_error("Failed to write public key");
  }
  len = BIO_get_mem_data(bio, &data);
  std::string public_key(data, len);

  // Clean up
  BIO_free(bio);
  EC_KEY_free(key);

  return public_key + "\n" + private_key;
}

namespace py = pybind11;

PYBIND11_MODULE(ecdsa_keygen, m) {
  m.def("generate_ecdsa_key", &generate_ecdsa_key,
        "Generate SECP256R1 ECDSA key pair");
}
