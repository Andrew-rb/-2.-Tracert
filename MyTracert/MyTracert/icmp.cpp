#include "icmp.h"
#include <winsock2.h>

// Проверка, является ли тип ICMP ответом назначения
bool IsDestinationReached(uint8_t type)
{
    return type == 0; // Echo Reply
}