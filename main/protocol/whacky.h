#ifndef WHACKY_INC_H
#define WHACKY_INC_H

#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/whacky.pb.h"

typedef struct {
    discovery_Domain domain;
    discovery_Capability cap;
} DeviceCapability;

typedef struct {
    uint8_t bd_addr[6];
    uint8_t *p_adv_data;
    int adv_data_length;
    uint8_t *p_scan_rsp;
    int scan_rsp_length;
} whacky_adv_data_t;

void whacky_init_verbose_message(Message *message, char *psz_message);
void whacky_init_error_message(Message *message, generic_ResultCode error);
void whacky_discovery_info_resp(
    Message *message,
    discovery_DeviceType device_type,
    uint32_t proto_min_ver,
    uint32_t fw_version_major,
    uint32_t fw_version_minor,
    uint32_t fw_version_rev,
    DeviceCapability *capabilities);

void whacky_ble_device_discovered(
    Message *message,
    whacky_adv_data_t *args
);

#endif /* WHACKY_INC_H */