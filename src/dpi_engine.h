#pragma once
#include "types.h"
#include <string>
#include <vector>

namespace phantom {

class DpiEngine {
public:
    static DpiEngine& Instance() {
        static DpiEngine engine;
        return engine;
    }

    ParsedActivity AnalyzeTransaction(const HttpTransaction& txn);
    std::vector<CapturedCredential> ExtractCredentials(const HttpTransaction& txn);

private:
    DpiEngine() = default;

    ParsedActivity ParseInstagram(const HttpTransaction& txn);
    ParsedActivity ParseYouTube(const HttpTransaction& txn);
    ParsedActivity ParseFacebook(const HttpTransaction& txn);
    ParsedActivity ParseTwitter(const HttpTransaction& txn);
    ParsedActivity ParseTikTok(const HttpTransaction& txn);
    ParsedActivity ParseWhatsApp(const HttpTransaction& txn);
    ParsedActivity ParseTelegram(const HttpTransaction& txn);
    ParsedActivity ParseDiscord(const HttpTransaction& txn);
    ParsedActivity ParseReddit(const HttpTransaction& txn);
    ParsedActivity ParseNetflix(const HttpTransaction& txn);
    ParsedActivity ParseSpotify(const HttpTransaction& txn);
};

} // namespace phantom
