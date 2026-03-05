#pragma once
#include <cstdint>

#pragma pack(push, 1)

struct ICMPHeader
{
    uint8_t  type;        // Тип (8 = Echo Request)
    uint8_t  code;        // Код (0)
    uint16_t checksum;    // Контрольная сумма
    uint16_t identifier;  // ID процесса
    uint16_t sequence;    // Номер последовательности
};

bool IsDestinationReached(uint8_t type);

#pragma pack(pop)