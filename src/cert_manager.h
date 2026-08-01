#pragma once
#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <chrono>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

namespace phantom {

struct LeafCert {
    std::string cert_pem;
    std::string key_pem;
    std::chrono::system_clock::time_point expires_at;
};

class CertManager {
public:
    static CertManager& Instance() {
        static CertManager cm;
        return cm;
    }

    bool Initialize(const std::string& ca_cert_path = "",
                    const std::string& ca_key_path = "");
    const LeafCert& GetCertForDomain(const std::string& domain);
    std::string GetCaCertPem() const { return ca_cert_pem_; }
    void SetCaCommonName(const std::string& cn) { ca_cn_ = cn; }
    void SetLeafValidityDays(int days) { leaf_validity_days_ = days; }

private:
    CertManager();
    ~CertManager();

    bool GenerateCa();
    bool LoadCa(const std::string& cert_path, const std::string& key_path);
    LeafCert GenerateLeaf(const std::string& domain);
    bool SaveCa();

    EVP_PKEY* ca_key_ = nullptr;
    X509* ca_cert_ = nullptr;
    std::string ca_cert_pem_;
    std::string ca_key_pem_;
    std::string ca_cn_ = "PHANTOM Root CA";
    int ca_validity_days_ = 365;
    int leaf_validity_days_ = 90;

    std::map<std::string, LeafCert> cert_cache_;
    std::mutex mtx_;
    bool initialized_ = false;
};

} // namespace phantom
