#include "checksum.h"

uint16_t CalculateChecksum(uint16_t* buffer, int size)
{
    uint32_t sum = 0;

    while (size > 1)
    {
        sum += *buffer++;
        size -= 2;
    }

    if (size == 1)
    {
        sum += *(uint8_t*)buffer;
    }

    // добавляем перенос
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}