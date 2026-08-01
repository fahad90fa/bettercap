#include "dpi_engine.h"
#include "config.h"
#include "logger.h"
#include <algorithm>

namespace phantom {

ParsedActivity DpiEngine::AnalyzeTransaction(const HttpTransaction& txn) {
    ParsedActivity activity;
    activity.timestamp = std::chrono::system_clock::now();
    activity.url = txn.full_url;
    activity.page_url = txn.full_url;
    AppType app = DetectAppFromDomain(txn.host);
    activity.app = app;
    activity.app_label = AppTypeToString(app);
    activity.activity = ActivityType::GENERAL_BROWSE;
    activity.activity_label = ActivityTypeToString(ActivityType::GENERAL_BROWSE);
    activity.title = txn.host;
    return activity;
}

std::vector<CapturedCredential> DpiEngine::ExtractCredentials(const HttpTransaction& txn) {
    std::vector<CapturedCredential> out;
    if (txn.request_body.empty()) return out;
    if (txn.request_body.find("password") != std::string::npos ||
        txn.request_body.find("token") != std::string::npos ||
        txn.request_body.find("username") != std::string::npos) {
        CapturedCredential cred;
        cred.service = txn.host;
        cred.url = txn.full_url;
        cred.method = txn.method;
        cred.timestamp = std::chrono::system_clock::now();
        cred.credential_type = "form_submit";
        out.push_back(cred);
    }
    return out;
}

ParsedActivity DpiEngine::ParseInstagram(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseYouTube(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseFacebook(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseTwitter(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseTikTok(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseWhatsApp(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseTelegram(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseDiscord(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseReddit(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseNetflix(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }
ParsedActivity DpiEngine::ParseSpotify(const HttpTransaction& txn) { return AnalyzeTransaction(txn); }

} // namespace phantom
