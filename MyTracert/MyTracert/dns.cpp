#include "dns.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <cstring>
#include <cstdint> 

using namespace std;

#pragma comment(lib, "ws2_32.lib")

#pragma pack(push, 1)
struct DNSHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
};
#pragma pack(pop)

string ReverseDNS(const string& ip)
{
    SOCKET dnsSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dnsSocket == INVALID_SOCKET)
        return "";

    sockaddr_in dnsServer{};
    dnsServer.sin_family = AF_INET;
    dnsServer.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dnsServer.sin_addr);

    vector<uint8_t> packet(512);
    DNSHeader* header = (DNSHeader*)packet.data();

    header->id = htons(0x1234);
    header->flags = htons(0x0100); // стандартный запрос
    header->qdCount = htons(1);
    header->anCount = 0;
    header->nsCount = 0;
    header->arCount = 0;

    size_t offset = sizeof(DNSHeader);

    // Формируем PTR запрос
    in_addr addr{};
    inet_pton(AF_INET, ip.c_str(), &addr);
    uint8_t* bytes = (uint8_t*)&addr;

    char reverseIp[64];
    sprintf_s(reverseIp, "%u.%u.%u.%u.in-addr.arpa", bytes[3], bytes[2], bytes[1], bytes[0]);

    char* token = strtok(reverseIp, ".");
    while (token)
    {
        size_t len = strlen(token);
        packet[offset++] = (uint8_t)len;
        memcpy(&packet[offset], token, len);
        offset += len;                  
        token = strtok(nullptr, ".");
    }
    packet[offset++] = 0; // конец имени

    *(uint16_t*)&packet[offset] = htons(12); // PTR
    offset += 2;

    *(uint16_t*)&packet[offset] = htons(1); // IN
    offset += 2;

    sendto(dnsSocket, (char*)packet.data(), static_cast<int>(offset), 0, (sockaddr*)&dnsServer, sizeof(dnsServer));

    sockaddr_in from{};
    int fromLen = sizeof(from);

    int bytesReceived = recvfrom(dnsSocket, (char*)packet.data(), (int)packet.size(), 0,
        (sockaddr*)&from, &fromLen);

    closesocket(dnsSocket);

    if (bytesReceived <= 0)
        return "";

    DNSHeader* respHeader = (DNSHeader*)packet.data();
    if (ntohs(respHeader->anCount) == 0)
        return "";

    offset = sizeof(DNSHeader);

    while (packet[offset] != 0)
        offset += packet[offset] + 1;
    offset += 5;

    offset += 2; 
    uint16_t type = ntohs(*(uint16_t*)&packet[offset]);
    offset += 8; 

    uint16_t dataLen = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;

    if (type != 12)
        return "";

    string result;
    size_t end = offset + dataLen; 

    while (offset < end)
    {
        uint8_t len = packet[offset++];
        if (len == 0)
            break;

        if (!result.empty())
            result += ".";

        result.append((char*)&packet[offset], len);
        offset += len;
    }

    return result;
}

string ResolveHostname(const string& hostname)
{
    SOCKET dnsSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dnsSocket == INVALID_SOCKET)
        return "";

    sockaddr_in dnsServer{};
    dnsServer.sin_family = AF_INET;
    dnsServer.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dnsServer.sin_addr);

    vector<uint8_t> packet(512);
    DNSHeader* header = (DNSHeader*)packet.data();

    header->id = htons(0x4321);
    header->flags = htons(0x0100);
    header->qdCount = htons(1);
    header->anCount = 0;
    header->nsCount = 0;
    header->arCount = 0;

    size_t offset = sizeof(DNSHeader); 

    size_t start = 0;
    while (true)
    {
        size_t dot = hostname.find('.', start);
        string label;

        if (dot == string::npos)
            label = hostname.substr(start);
        else
            label = hostname.substr(start, dot - start);

        packet[offset++] = (uint8_t)label.size();
        memcpy(&packet[offset], label.c_str(), label.size());
        offset += label.size();         

        if (dot == string::npos)
            break;

        start = dot + 1;
    }

    packet[offset++] = 0;

    *(uint16_t*)&packet[offset] = htons(1); // A
    offset += 2;

    *(uint16_t*)&packet[offset] = htons(1); // IN
    offset += 2;

    sendto(dnsSocket, (char*)packet.data(), static_cast<int>(offset), 0,
        (sockaddr*)&dnsServer, sizeof(dnsServer));

    sockaddr_in from{};
    int fromLen = sizeof(from);

    int bytesReceived = recvfrom(dnsSocket, (char*)packet.data(), (int)packet.size(), 0,
        (sockaddr*)&from, &fromLen);

    closesocket(dnsSocket);

    if (bytesReceived <= 0)
        return "";

    DNSHeader* respHeader = (DNSHeader*)packet.data();
    if (ntohs(respHeader->anCount) == 0)
        return "";

    offset = sizeof(DNSHeader);

    while (packet[offset] != 0)
        offset += packet[offset] + 1;
    offset += 5;

    for (int i = 0; i < ntohs(respHeader->anCount); i++)
    {
        offset += 2; // pointer

        uint16_t type = ntohs(*(uint16_t*)&packet[offset]);
        offset += 2;

        offset += 6; // class + ttl

        uint16_t dataLen = ntohs(*(uint16_t*)&packet[offset]);
        offset += 2;

        if (type == 1 && dataLen == 4)
        {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &packet[offset], ip, sizeof(ip));
            return string(ip);
        }

        offset += dataLen;
    }

    return "";
}