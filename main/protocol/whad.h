#ifndef WHAD_INC_H
#define WHAD_INC_H

#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/whad.pb.h"

typedef struct {
    discovery_Domain domain;
    discovery_Capability cap;
} DeviceCapability;

typedef struct {
    int rssi;
    ble_BleAdvType adv_type;
    uint8_t bd_addr[6];
    uint8_t *p_adv_data;
    int adv_data_length;
    uint8_t *p_scan_rsp;
    int scan_rsp_length;
} whad_adv_data_t;

void whad_init_verbose_message(Message *message, char *psz_message);
void whad_init_error_message(Message *message, generic_ResultCode error);
void whad_discovery_device_info_resp(
    Message *message,
    discovery_DeviceType device_type,
    uint32_t proto_min_ver,
    uint32_t fw_version_major,
    uint32_t fw_version_minor,
    uint32_t fw_version_rev,
    DeviceCapability *capabilities);

void whad_discovery_domain_info_resp(
    Message *message, discovery_Domain domain,
    uint64_t supported_commands);

void whad_ble_adv_pdu(
    Message *message,
    whad_adv_data_t *args
);
void whad_ble_data_pdu(
    Message *message,
    uint8_t *p_pdu,
    int length,
    ble_BleDirection direction
);

void whad_ble_notify_connected(Message *message, uint32_t conn_handle);
void whad_ble_notify_disconnected(Message *message, uint32_t conn_handle, uint32_t reason);

void whad_ble_ll_data_pdu(
    Message *message,
    uint16_t header,
    uint8_t *p_pdu,
    int length,
    ble_BleDirection direction,
    int conn_handle,
    bool processed
);
void whad_generic_cmd_result(
    Message *message,
    generic_ResultCode result
);

#endif /* whad_INC_H */