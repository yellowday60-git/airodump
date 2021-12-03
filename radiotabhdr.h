#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push,1)
struct radioTabHdr
{
    uint8_t reversion;
    uint8_t pad;
    uint16_t len;
    uint32_t present_flags;
    uint8_t flag;
    uint8_t rate;
    uint16_t frequency;
    uint16_t channel_type;
    uint8_t SSI_signal;
    uint16_t RX_flag;
    uint8_t antenna;
};
#pragma pack(pop)