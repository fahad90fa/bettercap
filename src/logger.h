#pragma once
#include <string>
#include <mutex>
#include <fstream>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <map>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace phantom {

enum class LogLevel {
    DEBUG, INFO, WARN, ERROR, SUCCESS, ACTIVITY, CREDENTIAL
};

class Logger {
public:
    static Logger& Instance() {
        static Logger l;
        return l;
    }

    void Init(const std::string& log_dir) {
        std::lock_guard<std::mutex> lock(mtx_);
        log_dir_ = log_dir;
#ifdef _WIN32
        CreateDirectoryA(log_dir_.c_str(), nullptr);
#else
        mkdir(log_dir_.c_str(), 0755);
#endif
        activity_log_.open(log_dir_ + "/activity_feed.jsonl", std::ios::app);
    }

    void Log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        char time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%H:%M:%S", localtime(&time_t));

        std::string prefix;
        switch (level) {
            case LogLevel::DEBUG:     prefix = "\033[90m[DBG]\033[0m"; break;
            case LogLevel::INFO:      prefix = "\033[94m[INF]\033[0m"; break;
            case LogLevel::WARN:      prefix = "\033[93m[WRN]\033[0m"; break;
            case LogLevel::ERROR:     prefix = "\033[91m[ERR]\033[0m"; break;
            case LogLevel::SUCCESS:   prefix = "\033[92m[ + ]\033[0m"; break;
            case LogLevel::ACTIVITY:  prefix = "\033[95m[ACT]\033[0m"; break;
            case LogLevel::CREDENTIAL:prefix = "\033[91m[CREDS]\033[0m"; break;
        }

        std::cout << prefix << " " << time_buf << "."
                  << std::setfill('0') << std::setw(3) << ms.count()
                  << std::setfill(' ')
                  << " " << message << std::endl;
    }

    // Writes pre-formatted, multi-line text to stdout under the same lock
    // Log() uses, so a multi-statement block (e.g. a device table) can't get
    // a log line spliced into the middle of it by a concurrent Log() call.
    void WriteRaw(const std::string& text) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::cout << text;
    }

    void LogActivity(const std::string& json_line) {
        if (activity_log_.is_open()) {
            activity_log_ << json_line << std::endl;
        }
    }

    void LogDevice(const std::string& mac, const std::string& json_line) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = device_logs_.find(mac);
        if (it == device_logs_.end()) {
            std::string filename = log_dir_ + "/device_" + mac + ".jsonl";
            device_logs_[mac].open(filename, std::ios::app);
        }
        device_logs_[mac] << json_line << std::endl;
    }

private:
    Logger() = default;
    std::mutex mtx_;
    std::string log_dir_;
    std::ofstream activity_log_;
    std::map<std::string, std::ofstream> device_logs_;
};

#define LOG_DEBUG(msg)   phantom::Logger::Instance().Log(phantom::LogLevel::DEBUG, msg)
#define LOG_INFO(msg)    phantom::Logger::Instance().Log(phantom::LogLevel::INFO, msg)
#define LOG_WARN(msg)    phantom::Logger::Instance().Log(phantom::LogLevel::WARN, msg)
#define LOG_ERROR(msg)   phantom::Logger::Instance().Log(phantom::LogLevel::ERROR, msg)
#define LOG_SUCCESS(msg) phantom::Logger::Instance().Log(phantom::LogLevel::SUCCESS, msg)
#define LOG_ACTIVITY(msg) phantom::Logger::Instance().Log(phantom::LogLevel::ACTIVITY, msg)
#define LOG_CREDENTIAL(msg) phantom::Logger::Instance().Log(phantom::LogLevel::CREDENTIAL, msg)

} // namespace phantom
