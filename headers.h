#pragma once
#include <stdio.h>
#include <pcap.h>
#include "mac.h"
#include <string>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <map>
#include <iostream>
#define BEACON_TYPE 0x80
#define ONE 1
#pragma pack(push, 1)
struct RadiotapHdr {
	uint8_t  ver_;
	uint8_t  pad_;
	uint16_t  len_;
	uint32_t  present_;
    u_int8_t datarate_;
    u_int8_t unknown_;
    u_int16_t txflag_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct BeaconHdr{
uint8_t ver:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;
    uint16_t duration_id;
    Mac dest_addr;
    Mac src_addr;
    Mac bssid;
    uint16_t squence_num;
    uint16_t fixed;
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_info;
    uint8_t tag_num;
    uint8_t len;
    char ssid[100];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct deauth_packet final {
    RadiotapHdr radiotap_hdr;
    BeaconHdr beacon_hdr;
};
#pragma pack(pop)
