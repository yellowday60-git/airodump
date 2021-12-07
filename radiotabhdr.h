#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push,1)
struct radioTabHdr
{
    uint8_t reversion;
    uint8_t pad;
    uint16_t len;
    uint32_t present_flags1;
    uint32_t present_flags2;
    uint32_t present_flags3;
    uint8_t flag;
    uint8_t rate;
    uint16_t frequency;
    uint16_t flag2;
    int8_t antenna;
    uint16_t signal_quality;
    uint16_t RX_flag;
};
#pragma pack(pop)