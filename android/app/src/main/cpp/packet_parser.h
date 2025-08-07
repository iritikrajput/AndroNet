#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <string>
#include <cstdint>

struct IPHeader
{
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
};

struct TCPHeader
{
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct UDPHeader
{
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct PacketInfo
{
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    std::string protocol;
    uint16_t size;
    std::string payload;
    uint64_t timestamp;
};

class PacketParser
{
public:
    static PacketInfo parsePacket(const uint8_t *packet, int length);
    static std::string ipToString(uint32_t ip);
    static uint16_t ntohs_custom(uint16_t value);
    static uint32_t ntohl_custom(uint32_t value);
    static std::string getCurrentTimestamp();
    static std::string bytesToHex(const uint8_t *data, int length, int max_bytes = 64);

private:
    static PacketInfo parseTCP(const IPHeader *ip_header, const uint8_t *packet, int length);
    static PacketInfo parseUDP(const IPHeader *ip_header, const uint8_t *packet, int length);
};

#endif // PACKET_PARSER_H
