#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iomanip>
#include <chrono>
#include <string>
#include "dns.h"
#include "icmp.h"
#include "checksum.h"

using namespace std;

#pragma comment(lib, "ws2_32.lib")

// ------------------------------------------------------------
// ИНИЦИАЛИЗАЦИЯ WINSOCK
// ------------------------------------------------------------
bool InitializeWinsock()
{
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

// ------------------------------------------------------------
// РЕЗОЛВИНГ ЦЕЛИ (IP или DNS)
// ------------------------------------------------------------
bool ResolveTarget(const string& target, string& ipOut)
{
    in_addr addr{};
    if (inet_pton(AF_INET, target.c_str(), &addr) == 1)
    {
        ipOut = target;
        return true;
    }

    ipOut = ResolveHostname(target);
    return !ipOut.empty();
}

// ------------------------------------------------------------
// ПЕЧАТЬ ЗАГОЛОВКА
// ------------------------------------------------------------
void PrintHeader(const string& input, const string& ip, int maxHops, bool disableReverse)
{
    // Определяем, является ли входная строка IP-адресом
    in_addr addr;
    bool inputIsIP = (inet_pton(AF_INET, input.c_str(), &addr) == 1);

    string displayName;
    if (inputIsIP && !disableReverse)
    {
        // Для IP и без -d пытаемся получить обратное имя
        string rev = ReverseDNS(ip);
        if (!rev.empty())
            displayName = rev;
        else
            displayName = ip; // если не удалось, показываем IP
    }
    else
    {
        // Для домена или IP с -d показываем исходную строку
        displayName = input;
    }

    cout << "\nТрассировка маршрута к " << displayName << " [" << ip << "]\n";
    cout << "с максимальным числом прыжков " << maxHops << ":\n\n";
}

// ------------------------------------------------------------
// ПРОВЕРКА, ЧТО ПАКЕТ ОТВЕЧАЕТ НА ЗАПРОС
// ------------------------------------------------------------
bool IsExpectedResponse(const char* buffer, int bytesReceived, uint16_t expectedId, uint16_t expectedSeq)
{
    if (bytesReceived < 28)
        return false;

    int ipHeaderLen = (buffer[0] & 0x0F) * 4;
    if (bytesReceived < ipHeaderLen + 8)
        return false;

    const uint8_t* icmp = reinterpret_cast<const uint8_t*>(buffer) + ipHeaderLen;
    uint8_t type = icmp[0];

    if (type == 0) // Echo Reply
    {
        if (bytesReceived < ipHeaderLen + 8 + 4)
            return false;
        uint16_t id = ntohs(*(uint16_t*)(icmp + 4));
        uint16_t seq = ntohs(*(uint16_t*)(icmp + 6));
        return (id == expectedId && seq == expectedSeq);
    }
    else if (type == 11) // Time Exceeded
    {
        if (bytesReceived < ipHeaderLen + 8 + 20)
            return false;
        const uint8_t* origIp = icmp + 8;
        int origIpHeaderLen = (origIp[0] & 0x0F) * 4;
        if (bytesReceived < ipHeaderLen + 8 + origIpHeaderLen + 8)
            return false;
        const uint8_t* origIcmp = origIp + origIpHeaderLen;
        uint16_t id = ntohs(*(uint16_t*)(origIcmp + 4));
        uint16_t seq = ntohs(*(uint16_t*)(origIcmp + 6));
        return (id == expectedId && seq == expectedSeq);
    }
    return false;
}

// ------------------------------------------------------------
// ОТПРАВКА ICMP ЗАПРОСА
// ------------------------------------------------------------
int SendProbe(SOCKET sock, sockaddr_in& dest, uint16_t id, uint16_t seq, int ttl)
{
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl)) == SOCKET_ERROR)
    {
        cerr << "Warning: Failed to set TTL " << ttl << ": " << WSAGetLastError() << endl;
    }

    char packet[64] = { 0 };

    ICMPHeader* icmp = (ICMPHeader*)packet;
    icmp->type = 8;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->identifier = htons(id);
    icmp->sequence = htons(seq);

    const char* data = "MyTracerouteData";
    size_t dataLen = strlen(data);
    memcpy(packet + sizeof(ICMPHeader), data, dataLen);

    int size = static_cast<int>(sizeof(ICMPHeader) + dataLen);
    icmp->checksum = CalculateChecksum((uint16_t*)packet, size);

    return sendto(sock, packet, size, 0, (sockaddr*)&dest, sizeof(dest));
}

// ------------------------------------------------------------
// ЗАПУСК TRACERT
// ------------------------------------------------------------
void RunTraceroute(const string& ip, int maxHops, int timeoutMs, bool disableReverse)
{
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    DWORD timeout = timeoutMs;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR)
    {
        cerr << "Warning: Failed to set receive timeout: " << WSAGetLastError() << endl;
    }

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);

    uint16_t id = (uint16_t)GetCurrentProcessId();
    uint16_t seq = 1;

    bool reached = false;

    for (int ttl = 1; ttl <= maxHops && !reached; ttl++)
    {
        cout << setw(3) << ttl << "  ";

        double rtts[3] = { -1, -1, -1 };
        sockaddr_in lastAddr{};
        bool gotReply = false;

        for (int i = 0; i < 3; i++)
        {
            uint16_t currentSeq = seq;
            auto start = chrono::high_resolution_clock::now();

            SendProbe(sock, dest, id, currentSeq, ttl);

            char buffer[1024];
            sockaddr_in reply{};
            int len = sizeof(reply);

            int bytes = recvfrom(sock, buffer, static_cast<int>(sizeof(buffer)), 0,
                (sockaddr*)&reply, &len);

            auto end = chrono::high_resolution_clock::now();

            if (bytes != SOCKET_ERROR && IsExpectedResponse(buffer, bytes, id, currentSeq))
            {
                int ipLen = (buffer[0] & 0x0F) * 4;
                ICMPHeader* icmp = (ICMPHeader*)(buffer + ipLen);

                if (icmp->type == 0)
                {
                    reached = true;
                }

                rtts[i] = chrono::duration<double, milli>(end - start).count();
                lastAddr = reply;
                gotReply = true;
            }

            seq++;
            Sleep(100); // задержка между пакетами
        }

        bool allTimeout = true;

        for (int i = 0; i < 3; i++)
        {
            if (rtts[i] < 0)
            {
                cout << setw(7) << "*";
            }
            else
            {
                string rttStr = to_string(static_cast<int>(rtts[i])) + " ms";
                cout << setw(7) << rttStr.c_str();
            }
            allTimeout = allTimeout && (rtts[i] < 0);
        }

        if (allTimeout)
        {
            cout << "  Превышен интервал ожидания для запроса.\n";
            Sleep(100);
            continue;
        }

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &lastAddr.sin_addr, ipStr, sizeof(ipStr));

        cout << "  "; // два пробела перед IP/именем

        if (!disableReverse)
        {
            string name = ReverseDNS(ipStr);
            if (!name.empty())
                cout << name << " [" << ipStr << "]";
            else
                cout << ipStr;
        }
        else
        {
            cout << ipStr;
        }

        cout << "\n";
        Sleep(100);
    }

    cout << "\nТрассировка завершена.\n";

    closesocket(sock);
}

// ------------------------------------------------------------
// ПАРСИНГ АРГУМЕНТОВ
// ------------------------------------------------------------
bool ParseArguments(int argc, char* argv[], string& target, int& maxHops, int& timeout, bool& disableReverse)
{
    if (argc < 2)
        return false;

    if (argc == 2)
    {
        target = argv[1];
        return true;
    }

    for (int i = 1; i < argc; ++i)
    {
        string arg = argv[i];

        if (arg == "-d")
        {
            disableReverse = true;
        }
        else if (arg == "-h")
        {
            if (i + 1 >= argc)
                return false;

            try
            {
                maxHops = stoi(argv[++i]);
            }
            catch (...)
            {
                return false;
            }
        }
        else if (arg == "-w")
        {
            if (i + 1 >= argc)
                return false;

            try
            {
                timeout = stoi(argv[++i]);
            }
            catch (...)
            {
                return false;
            }
        }
        else
        {
            target = arg;
        }
    }

    return !target.empty();
}

// ------------------------------------------------------------
// MAIN
// ------------------------------------------------------------
int main(int argc, char* argv[])
{
    string target;
    int maxHops = 30;
    int timeout = 4000;
    bool disableReverse = false;

    if (!ParseArguments(argc, argv, target, maxHops, timeout, disableReverse))
    {
        cout << "Использование:\n";
        cout << "MyTraceroute [-d] [-h max_hops] [-w timeout_ms] <адрес>\n";
        return 1;
    }

    if (!InitializeWinsock())
        return 1;

    string ip;
    if (!ResolveTarget(target, ip))
    {
        cout << "Не удалось разрешить имя.\n";
        return 1;
    }

    PrintHeader(target, ip, maxHops, disableReverse);

    RunTraceroute(ip, maxHops, timeout, disableReverse);

    WSACleanup();
    return 0;
}