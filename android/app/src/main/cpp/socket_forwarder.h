#ifndef SOCKET_FORWARDER_H
#define SOCKET_FORWARDER_H

#include "session_manager.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread>
#include <atomic>

class SocketForwarder
{
public:
    static SocketForwarder &getInstance();

    bool forwardPacket(const SessionKey &key, const uint8_t *packet, int length);
    void cleanup();

private:
    SocketForwarder() = default;

    int createSocket(const std::string &protocol);
    bool connectToDestination(int socket_fd, const std::string &dest_ip, uint16_t dest_port);
    void handleSocketData(int socket_fd, const SessionKey &key);

    std::atomic<bool> is_running_{true};
};

#endif // SOCKET_FORWARDER_H
