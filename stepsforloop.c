// #include <stdio.h>
// #include <iostream>
// #include <stdlib.h>
// #include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include <gmp.h>

// ECPoint structure
typedef struct {
    mpz_t x;
    mpz_t y;
    bool infinity;
} ECPoint;

// Secp256k1 constants
static mpz_t p, a, b, n;
static ECPoint G;
static const int h = 1;

// Function declarations
void init_ECPoint(ECPoint* point);
void free_ECPoint(ECPoint* point);
void point_add(ECPoint* result, const ECPoint* p1, const ECPoint* p2);
void scalar_mult(ECPoint* result, const mpz_t k, const ECPoint* point);
void generate_public_key(ECPoint* public_key, const mpz_t private_key);
void hash_point(char* output, const ECPoint* point);
void send_telegram_message(const char* message);

// Initialize constants
void init_constants() {
    mpz_init_set_str(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_init_set_ui(a, 0);
    mpz_init_set_ui(b, 7);
    mpz_init_set_str(n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    
    init_ECPoint(&G);
    mpz_set_str(G.x, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_set_str(G.y, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    G.infinity = false;
}

void init_ECPoint(ECPoint* point) {
    mpz_init(point->x);
    mpz_init(point->y);
    point->infinity = false;
}

void free_ECPoint(ECPoint* point) {
    mpz_clear(point->x);
    mpz_clear(point->y);
}

void point_add(ECPoint* result, const ECPoint* p1, const ECPoint* p2) {
    if (p1->infinity) {
        mpz_set(result->x, p2->x);
        mpz_set(result->y, p2->y);
        result->infinity = p2->infinity;
        return;
    }
    if (p2->infinity) {
        mpz_set(result->x, p1->x);
        mpz_set(result->y, p1->y);
        result->infinity = p1->infinity;
        return;
    }

    mpz_t lam, temp1, temp2;
    mpz_init(lam);
    mpz_init(temp1);
    mpz_init(temp2);

    if (mpz_cmp(p1->x, p2->x) == 0) {
        if (mpz_cmp(p1->y, p2->y) != 0) {
            result->infinity = true;
            mpz_clear(lam);
            mpz_clear(temp1);
            mpz_clear(temp2);
            return;
        }
        
        // Point doubling
        mpz_mul(temp1, p1->x, p1->x);
        mpz_mul_ui(temp1, temp1, 3);
        mpz_add(temp1, temp1, a);
        
        mpz_mul_ui(temp2, p1->y, 2);
        mpz_invert(temp2, temp2, p);
        
        mpz_mul(lam, temp1, temp2);
        mpz_mod(lam, lam, p);
    } else {
        mpz_sub(temp1, p2->y, p1->y);
        mpz_sub(temp2, p2->x, p1->x);
        mpz_invert(temp2, temp2, p);
        mpz_mul(lam, temp1, temp2);
        mpz_mod(lam, lam, p);
    }

    // Calculate x3
    mpz_mul(temp1, lam, lam);
    mpz_sub(temp1, temp1, p1->x);
    mpz_sub(temp1, temp1, p2->x);
    mpz_mod(result->x, temp1, p);

    // Calculate y3
    mpz_sub(temp1, p1->x, result->x);
    mpz_mul(temp1, lam, temp1);
    mpz_sub(temp1, temp1, p1->y);
    mpz_mod(result->y, temp1, p);

    result->infinity = false;

    mpz_clear(lam);
    mpz_clear(temp1);
    mpz_clear(temp2);
}

void scalar_mult(ECPoint* result, const mpz_t k, const ECPoint* point) {
    ECPoint temp, addend;
    init_ECPoint(&temp);
    init_ECPoint(&addend);
    
    temp.infinity = true;
    mpz_set(addend.x, point->x);
    mpz_set(addend.y, point->y);
    
    mpz_t k_copy;
    mpz_init_set(k_copy, k);
    
    while (mpz_sgn(k_copy) > 0) {
        if (mpz_odd_p(k_copy)) {
            point_add(&temp, &temp, &addend);
        }
        point_add(&addend, &addend, &addend);
        mpz_tdiv_q_2exp(k_copy, k_copy, 1);
    }
    
    mpz_set(result->x, temp.x);
    mpz_set(result->y, temp.y);
    result->infinity = temp.infinity;
    
    mpz_clear(k_copy);
    free_ECPoint(&temp);
    free_ECPoint(&addend);
}

void generate_public_key(ECPoint* public_key, const mpz_t private_key) {
    scalar_mult(public_key, private_key, &G);
}


void hash_point(char* output, const ECPoint* point) {
    if (point->infinity) {
        strcpy(output, "");
        return;
    }

    unsigned char prefix = mpz_odd_p(point->y) ? 0x03 : 0x02;
    unsigned char x_bytes[32];
    mpz_export(x_bytes, NULL, 1, 1, 1, 0, point->x);

    unsigned char data[33];
    data[0] = prefix;
    memcpy(data + 1, x_bytes, 32);

    unsigned char sha256_result[SHA256_DIGEST_LENGTH];
    unsigned char ripemd160_result[RIPEMD160_DIGEST_LENGTH];

    // SHA-256 using EVP API
    EVP_MD_CTX* sha256_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(sha256_ctx, data, 33);
    EVP_DigestFinal_ex(sha256_ctx, sha256_result, NULL);
    EVP_MD_CTX_free(sha256_ctx);

    // RIPEMD-160 using EVP API
    EVP_MD_CTX* ripemd160_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ripemd160_ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(ripemd160_ctx, sha256_result, SHA256_DIGEST_LENGTH);
    EVP_DigestFinal_ex(ripemd160_ctx, ripemd160_result, NULL);
    EVP_MD_CTX_free(ripemd160_ctx);

    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", ripemd160_result[i]);
    }
}


void send_telegram_message(const char* message) {
    CURL *curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if(curl) {
        char url[512];
        snprintf(url, sizeof(url), 
                "https://api.telegram.org/bot6526185567:AAHt8a2409V36PAwaL9y4uPw2YZC1ytrFyo/sendMessage");
        
        char post_fields[1024];
        snprintf(post_fields, sizeof(post_fields), 
                "chat_id=7037604847&text=%s", message);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
        
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }
        
        curl_easy_cleanup(curl);
    }
}

int main() {
    init_constants();
    curl_global_init(CURL_GLOBAL_ALL);

    const char* target_hash = "739437bb3dd6d1983e66629c5f08c70e52769371";
    mpz_t private_key, offset;
    mpz_init(private_key);
    mpz_init_set_str(offset, "73786976294838206464", 10);  // Initialize offset as a GMP integer

    gmp_randstate_t state;
    gmp_randinit_default(state);

    ECPoint public_key;
    init_ECPoint(&public_key);

    while (1) {
        mpz_urandomb(private_key, state, 64);  // Generate a random 64-bit number
        mpz_add(private_key, private_key, offset);  // Add the offset to private_key

        generate_public_key(&public_key, private_key);

        char hash[41];
        hash_point(hash, &public_key);

        if (strncmp(hash, "739437b", 7) == 0) {
            char message[256];
            gmp_sprintf(message, "Match found! Private Key: %Zd\n%s", private_key, hash);
            printf("%s\n", message);
            send_telegram_message(message);

            if (strcmp(hash, target_hash) == 0) {
                printf("Target hash found!\n");
                break;
            }
        }
    }

    free_ECPoint(&public_key);
    mpz_clear(private_key);
    mpz_clear(offset);
    gmp_randclear(state);
    curl_global_cleanup();

    return 0;
}
