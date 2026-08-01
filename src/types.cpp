#include "types.h"
#include "config.h"
#include <algorithm>
#include <unordered_map>

namespace phantom {

static const std::unordered_map<std::string, AppType> DOMAIN_APP_MAP = {
    {"instagram.com", AppType::INSTAGRAM},
    {"i.instagram.com", AppType::INSTAGRAM},
    {"graph.instagram.com", AppType::INSTAGRAM},
    {"youtube.com", AppType::YOUTUBE},
    {"youtu.be", AppType::YOUTUBE},
    {"youtubei.googleapis.com", AppType::YOUTUBE},
    {"ytimg.com", AppType::YOUTUBE},
    {"facebook.com", AppType::FACEBOOK},
    {"fbcdn.net", AppType::FACEBOOK},
    {"x.com", AppType::TWITTER},
    {"twitter.com", AppType::TWITTER},
    {"twimg.com", AppType::TWITTER},
    {"tiktok.com", AppType::TIKTOK},
    {"tiktokv.com", AppType::TIKTOK},
    {"whatsapp.com", AppType::WHATSAPP},
    {"telegram.org", AppType::TELEGRAM},
    {"t.me", AppType::TELEGRAM},
    {"discord.com", AppType::DISCORD},
    {"discordapp.com", AppType::DISCORD},
    {"discord.gg", AppType::DISCORD},
    {"reddit.com", AppType::REDDIT},
    {"redditstatic.com", AppType::REDDIT},
    {"netflix.com", AppType::NETFLIX},
    {"nflxvideo.net", AppType::NETFLIX},
    {"spotify.com", AppType::SPOTIFY},
    {"scdn.co", AppType::SPOTIFY},
};

std::string AppTypeToString(AppType t) {
    switch (t) {
        case AppType::INSTAGRAM:    return "Instagram";
        case AppType::YOUTUBE:      return "YouTube";
        case AppType::FACEBOOK:     return "Facebook";
        case AppType::TWITTER:      return "X/Twitter";
        case AppType::TIKTOK:       return "TikTok";
        case AppType::WHATSAPP:     return "WhatsApp";
        case AppType::TELEGRAM:     return "Telegram";
        case AppType::DISCORD:      return "Discord";
        case AppType::REDDIT:       return "Reddit";
        case AppType::NETFLIX:      return "Netflix";
        case AppType::SPOTIFY:      return "Spotify";
        case AppType::GENERIC_HTTP: return "HTTP";
        case AppType::GENERIC_HTTPS:return "HTTPS";
        case AppType::DNS:          return "DNS";
        default:                    return "Unknown";
    }
}

std::string ActivityTypeToString(ActivityType t) {
    switch (t) {
        case ActivityType::VIEWING_REEL:     return "Watching Reel";
        case ActivityType::VIEWING_STORY:    return "Viewing Story";
        case ActivityType::VIEWING_POST:     return "Viewing Post";
        case ActivityType::VIEWING_VIDEO:    return "Watching Video";
        case ActivityType::WATCHING_LIVE:    return "Watching Live";
        case ActivityType::BROWSING_FEED:    return "Browsing Feed";
        case ActivityType::SENDING_MESSAGE:  return "Sending Message";
        case ActivityType::MAKING_CALL:      return "Making Call";
        case ActivityType::SEARCHING:        return "Searching";
        case ActivityType::PROFILE_VIEW:     return "Viewing Profile";
        case ActivityType::LIKING:           return "Liking Content";
        case ActivityType::COMMENTING:       return "Commenting";
        case ActivityType::SHARING:          return "Sharing";
        case ActivityType::STREAMING_MUSIC:  return "Streaming Music";
        case ActivityType::STREAMING_VIDEO:  return "Streaming Video";
        case ActivityType::GENERAL_BROWSE:   return "Browsing";
        case ActivityType::LOGIN:            return "Logging In";
        case ActivityType::AUTH_TOKEN:       return "Auth Token Captured";
        case ActivityType::FILE_DOWNLOAD:    return "Downloading File";
        case ActivityType::API_CALL:         return "API Call";
        default:                             return "Unknown Activity";
    }
}

AppType DetectAppFromDomain(const std::string& host) {
    auto it = DOMAIN_APP_MAP.find(host);
    if (it != DOMAIN_APP_MAP.end()) return it->second;

    for (const auto& [domain, app] : DOMAIN_APP_MAP) {
        if (host.size() > domain.size()) {
            size_t pos = host.size() - domain.size() - 1;
            if (host[pos] == '.' && host.substr(pos + 1) == domain) {
                return app;
            }
        }
    }

    return AppType::GENERIC_HTTPS;
}

} // namespace phantom
