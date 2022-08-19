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

#define FIRMWARE_AUTHOR "Damien Cauquil"
#define FIRMWARE_URL "https://github.com/virtualabs/esp32-fw.git"

/* Adapter state. */
typedef enum {
    IDLE,
    OBSERVER,
    BROADCASTER,
    CENTRAL,
    PERIPHERAL
} adapter_state_t;

typedef enum {
    CONNECTING,
    CONNECTED,
    DISCONNECTED
} adapter_conn_state_t;

typedef struct {
    /* Device name (esp32_112233). */
    uint8_t dev_name[16];
    
    /* Current state. */
    adapter_state_t state;
    bool active_scan;
    uint8_t my_dev_addr[6];
    bool b_spoof_addr;
    bool b_enabled;

    /* Target device (Master mode). */
    uint8_t target_dev_addr[6];
    adapter_conn_state_t conn_state;
    int16_t conn_handle;

    /* L2CAP monitoring. */
    bool b_l2cap_started;
    int l2cap_pkt_size;
    int l2cap_recv_bytes;

    /* Advertising data (Slave mode). */
    uint8_t adv_data[31];
    int adv_data_length;
    uint8_t adv_rsp_data[31];
    int adv_rsp_data_length;

    /* Capabilities. */
    DeviceCapability *capabilities;
} adapter_t;

void adapter_init(void);

/* BLE callbacks. */
static void blecent_host_task(void *param);
static void blecent_on_reset(int reason);
static void blecent_on_sync(void);
void ble_advertise(void);

/* BLE hooks. */
int ble_rx_ctl_handler(uint16_t header, uint8_t *p_pdu, int length);
int ble_rx_data_handler(uint16_t header,uint8_t *p_pdu, int length);
int ble_tx_data_handler(uint16_t header,uint8_t *p_pdu, int length);
int ble_tx_ctl_handler(llcp_opinfo *p_llcp_pdu);

/* Callbacks. */
void adapter_on_unsupported(Message *message);
void adapter_on_device_info_req(discovery_DeviceInfoQuery *query);
void adapter_on_domain_info_req(discovery_DeviceDomainInfoQuery *query);

void adapter_on_enable_adv(ble_AdvModeCmd *adv_mode);
void adapter_on_enable_peripheral(ble_PeripheralModeCmd *periph_mode);
void adapter_on_enable_scan(ble_ScanModeCmd *scan_mode);
void adapter_on_enable_central(ble_CentralModeCmd *central_mode);
void adapter_on_connect(ble_ConnectToCmd *connect);
void adapter_on_start(ble_StartCmd *start);
void adapter_on_stop(ble_StartCmd *stop);
void adapter_on_disconnect(ble_DisconnectCmd *disconnect);
void adapter_on_send_pdu(ble_SendPDUCmd *send_pdu);
void adapter_on_sniff_adv(ble_SniffAdvCmd *sniff_adv);
void adapter_on_notify_connected(void);
void adapter_on_notify_disconnected(void);
void adapter_on_notify_adv(
    uint8_t adv_type,
    int rssi,
    uint8_t *bd_addr,
    uint8_t *p_adv_data,
    int adv_data_length,
    uint8_t *p_scan_rsp,
    int scan_rsp_length
);
void adapter_on_set_bd_addr(ble_SetBdAddressCmd *bd_addr);
void adapter_on_reset(void);
void adapter_on_set_speed(discovery_SetTransportSpeed *speed);

#endif /* ADAPTER_INC_H */