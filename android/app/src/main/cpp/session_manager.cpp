#include "session_manager.h"
#include <chrono>
#include <algorithm>
#include <unistd.h>

SessionManager &SessionManager::getInstance()
{
    static SessionManager instance;
    return instance;
}

SessionInfo *SessionManager::getSession(const SessionKey &key)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(key);
    if (it != sessions_.end())
    {
        return &it->second;
    }

    // Create new session
    SessionInfo new_session;
    new_session.last_activity = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count();
    new_session.is_active = true;

    sessions_[key] = new_session;
    return &sessions_[key];
}

void SessionManager::updateSession(const SessionKey &key, int bytes, bool is_outgoing)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(key);
    if (it != sessions_.end())
    {
        SessionInfo &session = it->second;

        if (is_outgoing)
        {
            session.bytes_sent += bytes;
            session.packets_sent++;
        }
        else
        {
            session.bytes_received += bytes;
            session.packets_received++;
        }

        session.last_activity = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count();
    }
}

void SessionManager::closeSession(const SessionKey &key)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(key);
    if (it != sessions_.end())
    {
        if (it->second.socket_fd != -1)
        {
            close(it->second.socket_fd);
        }
        sessions_.erase(it);
    }
}

void SessionManager::cleanupOldSessions()
{
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();

    auto it = sessions_.begin();
    while (it != sessions_.end())
    {
        if (current_time - it->second.last_activity > SESSION_TIMEOUT_MS)
        {
            if (it->second.socket_fd != -1)
            {
                close(it->second.socket_fd);
            }
            it = sessions_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void SessionManager::updateProtocolStats(const std::string &protocol, int bytes)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (protocol_stats_.find(protocol) == protocol_stats_.end())
    {
        protocol_stats_[protocol] = ProtocolStats(protocol);
    }

    protocol_stats_[protocol].packet_count++;
    protocol_stats_[protocol].total_bytes += bytes;
}

std::vector<ProtocolStats> SessionManager::getProtocolStats()
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ProtocolStats> stats;
    for (const auto &pair : protocol_stats_)
    {
        stats.push_back(pair.second);
    }

    // Sort by packet count (descending)
    std::sort(stats.begin(), stats.end(),
              [](const ProtocolStats &a, const ProtocolStats &b)
              {
                  return a.packet_count > b.packet_count;
              });

    return stats;
}

void SessionManager::resetStats()
{
    std::lock_guard<std::mutex> lock(mutex_);
    protocol_stats_.clear();
    sessions_.clear();
}
