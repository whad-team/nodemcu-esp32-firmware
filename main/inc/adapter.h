#ifndef ADAPTER_INC_H
#define ADAPTER_INC_H

#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/generic.pb.h"
#include "protocol/device.pb.h"
#include "protocol/ble.pb.h"
#include "protocol/whacky.pb.h"
#include "protocol/whacky.h"

#include "inc/comm.h"

/* Adapter state. */
typedef enum {
    OBSERVER,
    CONNECTING,
    CONNECTED,
    DISCONNECTED
} adapter_state_t;

typedef struct {
    /* Current state. */
    adapter_state_t state;

    /* Capabilities. */
    DeviceCapability *capabilities;
} adapter_t;

void adapter_init(void);

/* Callbacks. */
void adapter_on_unsupported(Message *message);
void adapter_on_discovery_info_req(discovery_DeviceInfoQuery *query);
void adapter_on_notify_adv(uint8_t *bd_addr, uint8_t *p_adv_data, int adv_data_length, uint8_t *p_scan_rsp, int scan_rsp_length);

#endif /* ADAPTER_INC_H */