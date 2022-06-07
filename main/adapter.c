#include "inc/adapter.h"

static adapter_t g_adapter;
static DeviceCapability g_adapter_cap[] = {
    {discovery_Domain_BtLE, discovery_Capability_SlaveRole | discovery_Capability_MasterRole | discovery_Capability_Inject},
    {discovery_Domain_Zigbee, discovery_Capability_SlaveRole | discovery_Capability_MasterRole |
    discovery_Capability_Inject},
    {0, 0}
};

void adapter_init(void)
{
    /* By default, non-connected and act as an observer. */
    g_adapter.state = OBSERVER;
    g_adapter.capabilities = g_adapter_cap;

}

/****************************************************
 * Adapter events callbacks
 ***************************************************/

void adapter_on_unsupported(Message *message)
{
    Message reply;
    whacky_init_error_message(&reply, generic_ResultCode_ERROR);
    send_pb_message(&reply);
}

void adapter_on_discovery_info_req(discovery_DeviceInfoQuery *query)
{
    Message reply;

    memset(&reply, 0, sizeof(Message));
    whacky_discovery_info_resp(
        &reply,
        discovery_DeviceType_Esp32BleFuzzer,
        0x0100,
        1,
        0,
        0,
        g_adapter.capabilities
    );
    send_pb_message(&reply);
}

void adapter_on_notify_adv(uint8_t *bd_addr, uint8_t *p_adv_data, int adv_data_length, uint8_t *p_scan_rsp, int scan_rsp_length)
{
    Message notification;
    whacky_adv_data_t adv_data;

    memset(&notification, 0, sizeof(Message));
    memcpy(adv_data.bd_addr, bd_addr, 6);
    adv_data.p_adv_data = p_adv_data;
    adv_data.adv_data_length = adv_data_length;
    adv_data.p_scan_rsp = p_scan_rsp;
    adv_data.scan_rsp_length = scan_rsp_length;

    /* Build notification and send to host. */
    whacky_ble_device_discovered(&notification, &adv_data);
    send_pb_message(&notification);
}