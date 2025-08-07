#include "packet_parser.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <arpa/inet.h>

PacketInfo PacketParser::parsePacket(const uint8_t *packet, int length)
{
    PacketInfo info;

    if (length < sizeof(IPHeader))
    {
        return info;
    }

    const IPHeader *ip_header = reinterpret_cast<const IPHeader *>(packet);

    // Check if it's IPv4
    if ((ip_header->version_ihl >> 4) != 4)
    {
        return info;
    }

    info.source_ip = ipToString(ip_header->source_ip);
    info.dest_ip = ipToString(ip_header->dest_ip);
    info.size = ntohs_custom(ip_header->total_length);
    info.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    uint8_t ip_header_length = (ip_header->version_ihl & 0x0F) * 4;
    const uint8_t *payload = packet + ip_header_length;
    int payload_length = length - ip_header_length;

    switch (ip_header->protocol)
    {
    case 6: // TCP
        return parseTCP(ip_header, payload, payload_length);
    case 17: // UDP
        return parseUDP(ip_header, payload, payload_length);
    default:
        info.protocol = "OTHER";
        info.source_port = 0;
        info.dest_port = 0;
        break;
    }

    return info;
}

PacketInfo PacketParser::parseTCP(const IPHeader *ip_header, const uint8_t *packet, int length)
{
    PacketInfo info;
    info.source_ip = ipToString(ip_header->source_ip);
    info.dest_ip = ipToString(ip_header->dest_ip);
    info.size = ntohs_custom(ip_header->total_length);
    info.protocol = "TCP";
    info.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    if (length < sizeof(TCPHeader))
    {
        return info;
    }

    const TCPHeader *tcp_header = reinterpret_cast<const TCPHeader *>(packet);
    info.source_port = ntohs_custom(tcp_header->source_port);
    info.dest_port = ntohs_custom(tcp_header->dest_port);

    uint8_t tcp_header_length = (tcp_header->data_offset_reserved >> 4) * 4;
    if (length > tcp_header_length)
    {
        const uint8_t *payload = packet + tcp_header_length;
        int payload_length = length - tcp_header_length;
        info.payload = bytesToHex(payload, payload_length);
    }

    return info;
}

PacketInfo PacketParser::parseUDP(const IPHeader *ip_header, const uint8_t *packet, int length)
{
    PacketInfo info;
    info.source_ip = ipToString(ip_header->source_ip);
    info.dest_ip = ipToString(ip_header->dest_ip);
    info.size = ntohs_custom(ip_header->total_length);
    info.protocol = "UDP";
    info.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    if (length < sizeof(UDPHeader))
    {
        return info;
    }

    const UDPHeader *udp_header = reinterpret_cast<const UDPHeader *>(packet);
    info.source_port = ntohs_custom(udp_header->source_port);
    info.dest_port = ntohs_custom(udp_header->dest_port);

    if (length > sizeof(UDPHeader))
    {
        const uint8_t *payload = packet + sizeof(UDPHeader);
        int payload_length = length - sizeof(UDPHeader);
        info.payload = bytesToHex(payload, payload_length);
    }

    return info;
}

std::string PacketParser::ipToString(uint32_t ip)
{
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, buffer, INET_ADDRSTRLEN);
    return std::string(buffer);
}

uint16_t PacketParser::ntohs_custom(uint16_t value)
{
    return ntohs(value);
}

uint32_t PacketParser::ntohl_custom(uint32_t value)
{
    return ntohl(value);
}

std::string PacketParser::getCurrentTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string PacketParser::bytesToHex(const uint8_t *data, int length, int max_bytes)
{
    std::stringstream ss;
    int bytes_to_show = std::min(length, max_bytes);

    for (int i = 0; i < bytes_to_show; ++i)
    {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
        if (i < bytes_to_show - 1)
            ss << " ";
    }

    if (length > max_bytes)
    {
        ss << "...";
    }

    return ss.str();
}
