#ifndef ADAPTER_INC_H
#define ADAPTER_INC_H

#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/generic.pb.h"
#include "protocol/device.pb.h"
#include "protocol/ble/ble.pb.h"
#include "protocol/whad.pb.h"
#include "protocol/whad.h"

#include "inc/comm.h"
#include "inc/helpers.h"
#include "inc/ble_hack.h"

/* Adapter state. */
typedef enum {
    IDLE,
    OBSERVER,
    CENTRAL,
} adapter_state_t;

typedef enum {
    CONNECTING,
    CONNECTED,
    DISCONNECTED
} adapter_conn_state_t;

typedef struct {
    /* Current state. */
    adapter_state_t state;
    bool active_scan;

    /* Target device. */
    uint8_t target_dev_addr[6];
    adapter_conn_state_t conn_state;
    uint16_t conn_handle;

    /* Capabilities. */
    DeviceCapability *capabilities;
} adapter_t;

void adapter_init(void);

/* BLE callbacks. */
static void blecent_host_task(void *param);
static void blecent_on_reset(int reason);
static void blecent_on_sync(void);

/* BLE hooks. */
int ble_rx_ctl_handler(uint8_t *p_pdu, int length);
int ble_rx_data_handler(uint8_t *p_pdu, int length);
int ble_tx_data_handler(uint8_t *p_pdu, int length);
int ble_tx_ctl_handler(llcp_opinfo *p_llcp_pdu);

/* Callbacks. */
void adapter_on_unsupported(Message *message);
void adapter_on_device_info_req(discovery_DeviceInfoQuery *query);
void adapter_on_domain_info_req(discovery_DeviceDomainInfoQuery *query);

void adapter_on_enable_scan(ble_ScanModeCmd *scan_mode);
void adapter_on_enable_central(ble_CentralModeCmd *central_mode);
void adapter_on_connect(ble_ConnectToCmd *connect);
void adapter_on_start(ble_StartCmd *start);
void adapter_on_stop(ble_StartCmd *stop);
void adapter_on_sniff_adv(ble_SniffAdvCmd *sniff_adv);
void adapter_on_notify_adv(
    uint8_t adv_type,
    int rssi,
    uint8_t *bd_addr,
    uint8_t *p_adv_data,
    int adv_data_length,
    uint8_t *p_scan_rsp,
    int scan_rsp_length
);

#endif /* ADAPTER_INC_H */