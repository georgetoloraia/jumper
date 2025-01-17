#include <gmp.h>
#include <gmpxx.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <vector>
#include <stdexcept>
#include <cstdlib>

class ECPoint {
public:
    mpz_t x, y;
    bool infinity;

    ECPoint() : infinity(false) {
        mpz_init(x);
        mpz_init(y);
    }

    ECPoint(const char* x_val, const char* y_val, bool infinity = false) : infinity(infinity) {
        mpz_init_set_str(x, x_val, 16);
        mpz_init_set_str(y, y_val, 16);
    }

    ~ECPoint() {
        mpz_clear(x);
        mpz_clear(y);
    }

    ECPoint(const ECPoint& other) : infinity(other.infinity) {
        mpz_init_set(x, other.x);
        mpz_init_set(y, other.y);
    }

    ECPoint& operator=(const ECPoint& other) {
        if (this != &other) {
            mpz_set(x, other.x);
            mpz_set(y, other.y);
            infinity = other.infinity;
        }
        return *this;
    }

    friend std::ostream& operator<<(std::ostream& os, const ECPoint& point);
};

std::ostream& operator<<(std::ostream& os, const ECPoint& point) {
    if (point.infinity) {
        os << "Point at infinity";
    } else {
        char* x_str = mpz_get_str(NULL, 16, point.x);
        char* y_str = mpz_get_str(NULL, 16, point.y);
        os << "(" << x_str << ", " << y_str << ")";
        free(x_str); // Free memory allocated by mpz_get_str
        free(y_str); // Free memory allocated by mpz_get_str
    }
    return os;
}

class Secp256k1 {
public:
    static const char* p;
    static const char* a;
    static const char* b;
    static const ECPoint G;
    static const char* n;

    static ECPoint point_add(const ECPoint& p1, const ECPoint& p2);
    static ECPoint scalar_mult(const mpz_t& k, const ECPoint& point, std::vector<ECPoint>& steps);
};

const char* Secp256k1::p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
const char* Secp256k1::a = "0";
const char* Secp256k1::b = "7";
const ECPoint Secp256k1::G = ECPoint(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
);
const char* Secp256k1::n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

ECPoint Secp256k1::point_add(const ECPoint& p1, const ECPoint& p2) {
    if (p1.infinity) return p2;
    if (p2.infinity) return p1;

    mpz_t lambda, temp, x3, y3;
    mpz_inits(lambda, temp, x3, y3, NULL);

    mpz_t p_mod;
    mpz_init_set_str(p_mod, Secp256k1::p, 16);

    if (mpz_cmp(p1.x, p2.x) == 0 && mpz_cmp(p1.y, p2.y) != 0) {
        mpz_clears(lambda, temp, x3, y3, p_mod, NULL);
        return ECPoint("0", "0", true); // Point at infinity
    }

    if (mpz_cmp(p1.x, p2.x) == 0 && mpz_cmp(p1.y, p2.y) == 0) {
        mpz_mul(temp, p1.x, p1.x);
        mpz_mul_ui(temp, temp, 3);
        mpz_add_ui(temp, temp, 0);
        mpz_mul_ui(lambda, p1.y, 2);
        mpz_invert(lambda, lambda, p_mod);
        mpz_mul(lambda, lambda, temp);
        mpz_mod(lambda, lambda, p_mod);
    } else {
        mpz_sub(temp, p2.y, p1.y);
        mpz_sub(lambda, p2.x, p1.x);
        mpz_invert(lambda, lambda, p_mod);
        mpz_mul(lambda, lambda, temp);
        mpz_mod(lambda, lambda, p_mod);
    }

    mpz_mul(x3, lambda, lambda);
    mpz_sub(x3, x3, p1.x);
    mpz_sub(x3, x3, p2.x);
    mpz_mod(x3, x3, p_mod);

    mpz_sub(y3, p1.x, x3);
    mpz_mul(y3, y3, lambda);
    mpz_sub(y3, y3, p1.y);
    mpz_mod(y3, y3, p_mod);

    ECPoint result(mpz_get_str(NULL, 16, x3), mpz_get_str(NULL, 16, y3));

    mpz_clears(lambda, temp, x3, y3, p_mod, NULL);
    return result;
}

ECPoint Secp256k1::scalar_mult(const mpz_t& k, const ECPoint& point, std::vector<ECPoint>& steps) {
    ECPoint result("0", "0", true); // Point at infinity
    ECPoint addend = point;

    mpz_t current_k;
    mpz_init_set(current_k, k);

    while (mpz_cmp_ui(current_k, 0) > 0) {
        if (mpz_odd_p(current_k)) {
            result = point_add(result, addend);
            steps.push_back(result);
        }
        addend = point_add(addend, addend);
        mpz_fdiv_q_2exp(current_k, current_k, 1);
    }

    mpz_clear(current_k);
    return result;
}

// Hash a point with SHA256 and RIPEMD-160
std::string hash_point(const ECPoint& point) {
    if (point.infinity) throw std::runtime_error("Cannot hash the point at infinity");

    std::vector<unsigned char> compressed_key;
    compressed_key.push_back(mpz_even_p(point.y) ? 0x02 : 0x03);

    size_t count = (mpz_sizeinbase(point.x, 2) + 7) / 8;
    compressed_key.resize(1 + count);
    mpz_export(&compressed_key[1], &count, 1, 1, 0, 0, point.x);

    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(compressed_key.data(), compressed_key.size(), sha256_hash);

    unsigned char ripemd160_hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

    if (EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, sha256_hash, SHA256_DIGEST_LENGTH) != 1 ||
        EVP_DigestFinal_ex(ctx, ripemd160_hash, &hash_length) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to compute RIPEMD-160 hash");
    }

    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)ripemd160_hash[i];
    }
    return ss.str();
}

int main() {
    mpz_t private_key;
    mpz_init(private_key);

    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, std::random_device{}());

    std::ofstream file("steps.txt", std::ios::app);

    const std::string target_hash = "739437bb3dd6d1983e66629c5f08c70e52769371";

    while (true) {
        // Generate random private key
        mpz_urandomm(private_key, rand_state, mpz_class("147573952589676412927").get_mpz_t());
        mpz_add(private_key, private_key, mpz_class("73786976294838206464").get_mpz_t());

        std::vector<ECPoint> steps; // Store scalar multiplication steps
        ECPoint public_key = Secp256k1::scalar_mult(private_key, Secp256k1::G, steps);

        for (size_t i = 0; i < steps.size(); ++i) {
            try {
                // Process the step
                std::string rmd160 = hash_point(steps[i]);

                // Check for partial or full match
                if (rmd160.substr(0, 5) == "73943") {
                    std::cout << "Partial Match: " << rmd160 << "\nPrivate Key: " 
                              << mpz_get_str(NULL, 10, private_key) << std::endl;

                    file << "Step " << i + 1 << ": " << steps[i] 
                         << "\nPartial Match: " << rmd160 << "\nPrivate Key: " 
                         << mpz_get_str(NULL, 10, private_key) << std::endl;

                    if (rmd160 == target_hash) {
                        std::cout << "Full Match Found!\n";
                        std::cout << "Private Key: " << mpz_get_str(NULL, 10, private_key) << std::endl;

                        file << "Full Match Found!\n";
                        file << "Step " << i + 1 << ": " << steps[i] 
                             << "\nMatching Hash: " << rmd160 
                             << "\nPrivate Key: " << mpz_get_str(NULL, 10, private_key) << std::endl;

                        // Exit cleanly
                        mpz_clear(private_key);
                        gmp_randclear(rand_state);
                        file.close();
                        return 0;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
                continue;
            }
        }

        // Clear the `steps` vector (let its destructor handle cleanup)
        steps.clear();
    }

    // Clear GMP variables
    mpz_clear(private_key);
    gmp_randclear(rand_state);
    return 0;
}
