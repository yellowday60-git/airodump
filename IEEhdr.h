#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"

#define BEACON_HEADER_SIZE 24
#define BEACON_SUBTYPE 0x80
#define PROBE_SUBTYPE 0x40
#define SSID_SIZE 2

#pragma pack(push,1)
struct ieeHdr{
    uint8_t subtype;
    uint8_t flag;
    uint16_t duration;
    Mac dmac;
    Mac smac;
    Mac bssid;
    uint16_t seq;
};
#pragma pack(pop)

#pragma pack(push,1)
struct ssidHdr{
    uint8_t num;
    uint8_t len;
};
#pragma pack(pop)