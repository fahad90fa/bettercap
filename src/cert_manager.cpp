#include "cert_manager.h"
#include "logger.h"
#include "config.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <atomic>

namespace phantom {

CertManager::CertManager() = default;

CertManager::~CertManager() {
    if (ca_cert_) X509_free(ca_cert_);
    if (ca_key_) EVP_PKEY_free(ca_key_);
}

bool CertManager::Initialize(const std::string& ca_cert_path,
                             const std::string& ca_key_path) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (initialized_) return true;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (!ca_cert_path.empty() && !ca_key_path.empty()) {
        if (LoadCa(ca_cert_path, ca_key_path)) {
            initialized_ = true;
            LOG_SUCCESS("CA loaded from disk");
            return true;
        }
        LOG_WARN("Failed to load CA from disk, generating new one...");
    }

    if (GenerateCa()) {
        SaveCa();
        initialized_ = true;
        LOG_SUCCESS("New CA generated and saved");
        return true;
    }

    LOG_ERROR("Failed to initialize certificate manager");
    return false;
}

bool CertManager::GenerateCa() {
    EVP_PKEY* pkey = nullptr;
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, 4096, bn, nullptr);
    BN_free(bn);

    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    X509* cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), ca_validity_days_ * 86400);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)ca_cn_.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        (const unsigned char*)"PHANTOM", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
        (const unsigned char*)"US", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* bc = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(cert, bc, -1);
    X509_EXTENSION_free(bc);

    X509_EXTENSION* ku = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage,
        "critical,keyCertSign,cRLSign");
    X509_add_ext(cert, ku, -1);
    X509_EXTENSION_free(ku);

    X509_EXTENSION* ski = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, "hash");
    X509_add_ext(cert, ski, -1);
    X509_EXTENSION_free(ski);

    X509_sign(cert, pkey, EVP_sha256());

    BIO* cert_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, cert);
    char* cert_data = nullptr;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    ca_cert_pem_ = std::string(cert_data, cert_len);
    BIO_free(cert_bio);

    BIO* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* key_data = nullptr;
    long key_len = BIO_get_mem_data(key_bio, &key_data);
    ca_key_pem_ = std::string(key_data, key_len);
    BIO_free(key_bio);

    ca_cert_ = cert;
    ca_key_ = pkey;

    return true;
}

bool CertManager::LoadCa(const std::string& cert_path, const std::string& key_path) {
    FILE* f = fopen(cert_path.c_str(), "r");
    if (!f) return false;
    X509* cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!cert) return false;

    f = fopen(key_path.c_str(), "r");
    if (!f) { X509_free(cert); return false; }
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!pkey) { X509_free(cert); return false; }

    std::ifstream cert_file(cert_path);
    ca_cert_pem_ = std::string((std::istreambuf_iterator<char>(cert_file)), std::istreambuf_iterator<char>());

    std::ifstream key_file(key_path);
    ca_key_pem_ = std::string((std::istreambuf_iterator<char>(key_file)), std::istreambuf_iterator<char>());

    if (ca_cert_) X509_free(ca_cert_);
    if (ca_key_) EVP_PKEY_free(ca_key_);
    ca_cert_ = cert;
    ca_key_ = pkey;
    return true;
}

bool CertManager::SaveCa() {
    if (ca_cert_pem_.empty() || ca_key_pem_.empty()) return false;

    std::ofstream cert_file(CA_CERT_FILE);
    cert_file << ca_cert_pem_;
    cert_file.close();

    std::ofstream key_file(CA_KEY_FILE);
    key_file << ca_key_pem_;
    key_file.close();

    LOG_INFO("CA saved to " + std::string(CA_CERT_FILE) + " and " + std::string(CA_KEY_FILE));
    return true;
}

LeafCert CertManager::GenerateLeaf(const std::string& domain) {
    LeafCert leaf;

    EVP_PKEY* pkey = nullptr;
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    BN_free(bn);
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    X509* cert = X509_new();
    X509_set_version(cert, 2);

    static std::atomic<uint64_t> serial_counter{1};
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial_counter.fetch_add(1));
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), leaf_validity_days_ * 86400);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)domain.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        (const unsigned char*)"PHANTOM Leaf", -1, -1, 0);

    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert_));

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert_, cert, nullptr, nullptr, 0);

    std::string san = "DNS:" + domain;
    if (domain.find("*.") == std::string::npos) {
        size_t dot = domain.find('.');
        if (dot != std::string::npos) {
            san += ",DNS:*." + domain.substr(dot + 1);
        }
    }
    X509_EXTENSION* san_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san.c_str());
    if (san_ext) {
        X509_add_ext(cert, san_ext, -1);
        X509_EXTENSION_free(san_ext);
    }

    X509_EXTENSION* bc = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:FALSE");
    if (bc) {
        X509_add_ext(cert, bc, -1);
        X509_EXTENSION_free(bc);
    }

    X509_EXTENSION* eku = X509V3_EXT_conf_nid(nullptr, &ctx, NID_ext_key_usage, "serverAuth");
    if (eku) {
        X509_add_ext(cert, eku, -1);
        X509_EXTENSION_free(eku);
    }

    X509_sign(cert, ca_key_, EVP_sha256());

    BIO* cert_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, cert);
    char* cert_data = nullptr;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    leaf.cert_pem = std::string(cert_data, cert_len);
    BIO_free(cert_bio);

    BIO* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* key_data = nullptr;
    long key_len = BIO_get_mem_data(key_bio, &key_data);
    leaf.key_pem = std::string(key_data, key_len);
    BIO_free(key_bio);

    leaf.expires_at = std::chrono::system_clock::now() + std::chrono::hours(leaf_validity_days_ * 24);

    X509_free(cert);
    EVP_PKEY_free(pkey);

    LOG_DEBUG("Generated leaf cert for: " + domain);
    return leaf;
}

const LeafCert& CertManager::GetCertForDomain(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!initialized_) {
        static LeafCert empty;
        LOG_ERROR("CertManager not initialized");
        return empty;
    }

    std::string norm = domain;
    std::transform(norm.begin(), norm.end(), norm.begin(), ::tolower);

    auto it = cert_cache_.find(norm);
    if (it != cert_cache_.end()) {
        auto now = std::chrono::system_clock::now();
        if (it->second.expires_at > now + std::chrono::hours(24)) {
            return it->second;
        }
        cert_cache_.erase(it);
    }

    cert_cache_[norm] = GenerateLeaf(norm);
    return cert_cache_[norm];
}

} // namespace phantom
