#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <random>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <curl/curl.h>

class ECPoint {
public:
    uint64_t x;
    uint64_t y;
    bool infinity;

    ECPoint(uint64_t x = 0, uint64_t y = 0, bool infinity = false)
        : x(x), y(y), infinity(infinity) {}

    std::string toString() const {
        if (infinity) {
            return "Point at infinity";
        }
        return "(" + std::to_string(x) + ", " + std::to_string(y) + ")";
    }
};

class Secp256k1 {
public:
    static const uint64_t p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    static const uint64_t a = 0;
    static const uint64_t b = 7;
    static const ECPoint G;
    static const uint64_t n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    static const uint64_t h = 1;

    static ECPoint point_add(const ECPoint& p1, const ECPoint& p2) {
        if (p1.infinity) return p2;
        if (p2.infinity) return p1;

        if (p1.x == p2.x && p1.y != p2.y) {
            return ECPoint(0, 0, true);
        }

        uint64_t lam;
        if (p1.x == p2.x && p1.y == p2.y) {
            if (p1.y == 0) return ECPoint(0, 0, true);
            lam = ((3 * p1.x * p1.x + a) * modInverse(2 * p1.y, p)) % p;
        } else {
            lam = ((p2.y - p1.y) * modInverse(p2.x - p1.x, p)) % p;
        }

        uint64_t x3 = (lam * lam - p1.x - p2.x) % p;
        uint64_t y3 = (lam * (p1.x - x3) - p1.y) % p;
        return ECPoint(x3, y3);
    }

    static std::pair<ECPoint, std::vector<ECPoint>> scalar_mult(uint64_t k, const ECPoint& point) {
        ECPoint result(0, 0, true);
        ECPoint addend = point;
        std::vector<ECPoint> steps;

        while (k) {
            if (k & 1) {
                result = point_add(result, addend);
                steps.push_back(result);
            }
            addend = point_add(addend, addend);
            steps.push_back(addend);
            k >>= 1;
        }

        return {result, steps};
    }

    static std::pair<ECPoint, std::vector<ECPoint>> generate_public_key(uint64_t private_key) {
        return scalar_mult(private_key, G);
    }

    static std::string hash_point(const ECPoint& point) {
        if (point.infinity) {
            throw std::runtime_error("Cannot hash the point at infinity.");
        }

        unsigned char prefix = (point.y % 2 == 0) ? 0x02 : 0x03;
        unsigned char x_bytes[32];
        for (int i = 0; i < 32; i++) {
            x_bytes[31 - i] = (point.x >> (i * 8)) & 0xFF;
        }

        // SHA256
        unsigned char sha256_result[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256_ctx;
        SHA256_Init(&sha256_ctx);
        SHA256_Update(&sha256_ctx, &prefix, 1);
        SHA256_Update(&sha256_ctx, x_bytes, 32);
        SHA256_Final(sha256_result, &sha256_ctx);

        // RIPEMD160
        unsigned char ripemd160_result[RIPEMD160_DIGEST_LENGTH];
        RIPEMD160_CTX ripemd160_ctx;
        RIPEMD160_Init(&ripemd160_ctx);
        RIPEMD160_Update(&ripemd160_ctx, sha256_result, SHA256_DIGEST_LENGTH);
        RIPEMD160_Final(ripemd160_result, &ripemd160_ctx);

        std::stringstream ss;
        for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)ripemd160_result[i];
        }
        return ss.str();
    }

private:
    static uint64_t modInverse(uint64_t a, uint64_t m) {
        int64_t m0 = m;
        int64_t y = 0, x = 1;

        if (m == 1) return 0;

        while (a > 1) {
            int64_t q = a / m;
            int64_t t = m;
            m = a % m;
            a = t;
            t = y;
            y = x - q * y;
            x = t;
        }

        if (x < 0) x += m0;
        return x;
    }
};

// Initialize static constant
const ECPoint Secp256k1::G(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798ULL,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8ULL
);

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void send_telegram_message(const std::string& message) {
    CURL* curl = curl_easy_init();
    if (curl) {
        const std::string BOT_TOKEN = "6526185567:AAHt8a2409V36PAwaL9y4uPw2YZC1ytrFyo";
        const std::string CHAT_ID = "7037604847";
        std::string url = "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage";
        
        std::string payload = "{\"chat_id\":\"" + CHAT_ID + "\",\"text\":\"" + message + "\"}";
        std::string response;

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Failed to send Telegram message: " << curl_easy_strerror(res) << std::endl;
        } else {
            std::cout << "Telegram message sent successfully!" << std::endl;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}

int main() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(73786976294838206464ULL, 147573952589676412927ULL);

    const std::string target_hash = "739437bb3dd6d1983e66629c5f08c70e52769371";
    std::ofstream file("steps.txt", std::ios::app);

    while (true) {
        uint64_t private_key = dis(gen);
        auto [public_key, steps] = Secp256k1::generate_public_key(private_key);

        for (size_t i = 0; i < steps.size(); i++) {
            try {
                std::string rmd = Secp256k1::hash_point(steps[i]);
                if (rmd.substr(0, 7) == "739437b") {
                    std::cout << "Matching Hash: " << rmd << "\nFrom: " << private_key << std::endl;
                    send_telegram_message("Match found! Private Key: " + std::to_string(private_key) + "\n" + rmd);
                    
                    if (rmd == target_hash) {
                        std::cout << "Matching step found at step " << i + 1 << "!" << std::endl;
                        file << "Step " << i + 1 << ": " << steps[i].toString() << "\n";
                        file << "Matching Hash: " << rmd << "\nFrom: " << private_key;
                        file.close();
                        return 0;
                    }
                }
            } catch (const std::exception& e) {
                continue;
            }
        }
    }

    return 0;
}