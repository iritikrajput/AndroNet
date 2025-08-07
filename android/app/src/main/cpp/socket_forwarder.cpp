#include "socket_forwarder.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <android/log.h>

#define TAG "SocketForwarder"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

SocketForwarder &SocketForwarder::getInstance()
{
    static SocketForwarder instance;
    return instance;
}

bool SocketForwarder::forwardPacket(const SessionKey &key, const uint8_t *packet, int length)
{
    SessionManager &session_mgr = SessionManager::getInstance();
    SessionInfo *session = session_mgr.getSession(key);

    if (!session)
    {
        LOGE("Failed to get session for forwarding");
        return false;
    }

    // Create socket if not exists
    if (session->socket_fd == -1)
    {
        session->socket_fd = createSocket(key.protocol);
        if (session->socket_fd == -1)
        {
            LOGE("Failed to create socket");
            return false;
        }

        if (!connectToDestination(session->socket_fd, key.dest_ip, key.dest_port))
        {
            LOGE("Failed to connect to destination");
            close(session->socket_fd);
            session->socket_fd = -1;
            return false;
        }

        // Start thread to handle incoming data
        std::thread data_thread(&SocketForwarder::handleSocketData, this,
                                session->socket_fd, key);
        data_thread.detach();
    }

    // Forward the packet
    ssize_t sent = send(session->socket_fd, packet, length, 0);
    if (sent > 0)
    {
        session_mgr.updateSession(key, sent, true);
        return true;
    }
    else
    {
        LOGE("Failed to send data: %d", errno);
        return false;
    }
}

int SocketForwarder::createSocket(const std::string &protocol)
{
    int socket_fd;

    if (protocol == "TCP")
    {
        socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    else if (protocol == "UDP")
    {
        socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    else
    {
        LOGE("Unsupported protocol: %s", protocol.c_str());
        return -1;
    }

    if (socket_fd == -1)
    {
        LOGE("Failed to create socket: %d", errno);
        return -1;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags != -1)
    {
        fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
    }

    return socket_fd;
}

bool SocketForwarder::connectToDestination(int socket_fd, const std::string &dest_ip, uint16_t dest_port)
{
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);

    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0)
    {
        LOGE("Invalid destination IP: %s", dest_ip.c_str());
        return false;
    }

    int result = connect(socket_fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (result == -1 && errno != EINPROGRESS)
    {
        LOGE("Failed to connect to %s:%d - %d", dest_ip.c_str(), dest_port, errno);
        return false;
    }

    return true;
}

void SocketForwarder::handleSocketData(int socket_fd, const SessionKey &key)
{
    uint8_t buffer[4096];
    SessionManager &session_mgr = SessionManager::getInstance();

    while (is_running_)
    {
        ssize_t received = recv(socket_fd, buffer, sizeof(buffer), 0);

        if (received > 0)
        {
            session_mgr.updateSession(key, received, false);

            // Here you would inject the response back into the TUN interface
            // This requires additional implementation for packet crafting
        }
        else if (received == 0)
        {
            // Connection closed
            LOGD("Connection closed for %s:%d", key.dest_ip.c_str(), key.dest_port);
            break;
        }
        else if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            // Error occurred
            LOGE("Error receiving data: %d", errno);
            break;
        }

        // Small delay to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    session_mgr.closeSession(key);
}

void SocketForwarder::cleanup()
{
    is_running_ = false;
}
