#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <unordered_map>
#include <string>
#include <mutex>
#include <cstdint>

struct SessionKey
{
    std::string source_ip;
    uint16_t source_port;
    std::string dest_ip;
    uint16_t dest_port;
    std::string protocol;

    bool operator==(const SessionKey &other) const
    {
        return source_ip == other.source_ip &&
               source_port == other.source_port &&
               dest_ip == other.dest_ip &&
               dest_port == other.dest_port &&
               protocol == other.protocol;
    }
};

struct SessionKeyHash
{
    std::size_t operator()(const SessionKey &key) const
    {
        return std::hash<std::string>()(key.source_ip + ":" +
                                        std::to_string(key.source_port) + "->" +
                                        key.dest_ip + ":" +
                                        std::to_string(key.dest_port) + ":" +
                                        key.protocol);
    }
};

struct SessionInfo
{
    int socket_fd;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t last_activity;
    bool is_active;

    SessionInfo() : socket_fd(-1), bytes_sent(0), bytes_received(0),
                    packets_sent(0), packets_received(0), last_activity(0), is_active(false) {}
};

struct ProtocolStats
{
    std::string protocol;
    uint64_t packet_count;
    uint64_t total_bytes;

    ProtocolStats(const std::string &proto = "") : protocol(proto), packet_count(0), total_bytes(0) {}
};

class SessionManager
{
public:
    static SessionManager &getInstance();

    SessionInfo *getSession(const SessionKey &key);
    void updateSession(const SessionKey &key, int bytes, bool is_outgoing);
    void closeSession(const SessionKey &key);
    void cleanupOldSessions();

    void updateProtocolStats(const std::string &protocol, int bytes);
    std::vector<ProtocolStats> getProtocolStats();
    void resetStats();

private:
    SessionManager() = default;
    std::unordered_map<SessionKey, SessionInfo, SessionKeyHash> sessions_;
    std::unordered_map<std::string, ProtocolStats> protocol_stats_;
    std::mutex mutex_;

    static const uint64_t SESSION_TIMEOUT_MS = 300000; // 5 minutes
};

#endif // SESSION_MANAGER_H
