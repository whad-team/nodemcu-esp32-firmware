#include "hci.h"

uint16_t make_cmd_set_evt_mask (uint8_t *buf, uint8_t *evt_mask)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_SET_EVT_MASK);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_SET_EVENT_MASK);
    ARRAY_TO_STREAM(buf, evt_mask, HCIC_PARAM_SIZE_SET_EVENT_MASK);
    return HCI_H4_CMD_PREAMBLE_SIZE + HCIC_PARAM_SIZE_SET_EVENT_MASK;
}

uint16_t make_cmd_ble_set_scan_enable (uint8_t *buf, uint8_t scan_enable,
                                       uint8_t filter_duplicates)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_BLE_WRITE_SCAN_ENABLE);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_BLE_WRITE_SCAN_ENABLE);
    UINT8_TO_STREAM (buf, scan_enable);
    UINT8_TO_STREAM (buf, filter_duplicates);
    return HCI_H4_CMD_PREAMBLE_SIZE + HCIC_PARAM_SIZE_BLE_WRITE_SCAN_ENABLE;
}

uint16_t make_cmd_ble_set_scan_params (uint8_t *buf, uint8_t scan_type,
                                       uint16_t scan_interval, uint16_t scan_window,
                                       uint8_t own_addr_type, uint8_t filter_policy)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_BLE_WRITE_SCAN_PARAM);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_BLE_WRITE_SCAN_PARAM);
    UINT8_TO_STREAM (buf, scan_type);
    UINT16_TO_STREAM (buf, scan_interval);
    UINT16_TO_STREAM (buf, scan_window);
    UINT8_TO_STREAM (buf, own_addr_type);
    UINT8_TO_STREAM (buf, filter_policy);
    return HCI_H4_CMD_PREAMBLE_SIZE + HCIC_PARAM_SIZE_BLE_WRITE_SCAN_PARAM;
}

uint16_t make_cmd_ble_set_adv_enable (uint8_t *buf, uint8_t adv_enable)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_BLE_WRITE_ADV_ENABLE);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_WRITE_ADV_ENABLE);
    UINT8_TO_STREAM (buf, adv_enable);
    return HCI_H4_CMD_PREAMBLE_SIZE + HCIC_PARAM_SIZE_WRITE_ADV_ENABLE;
}

uint16_t make_cmd_ble_set_adv_param (uint8_t *buf, uint16_t adv_int_min, uint16_t adv_int_max,
                                     uint8_t adv_type, uint8_t addr_type_own,
                                     uint8_t addr_type_dir, bd_addr_t direct_bda,
                                     uint8_t channel_map, uint8_t adv_filter_policy)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_BLE_WRITE_ADV_PARAMS);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_BLE_WRITE_ADV_PARAMS );

    UINT16_TO_STREAM (buf, adv_int_min);
    UINT16_TO_STREAM (buf, adv_int_max);
    UINT8_TO_STREAM (buf, adv_type);
    UINT8_TO_STREAM (buf, addr_type_own);
    UINT8_TO_STREAM (buf, addr_type_dir);
    BDADDR_TO_STREAM (buf, direct_bda);
    UINT8_TO_STREAM (buf, channel_map);
    UINT8_TO_STREAM (buf, adv_filter_policy);
    return HCI_H4_CMD_PREAMBLE_SIZE + HCIC_PARAM_SIZE_BLE_WRITE_ADV_PARAMS;
}

uint16_t make_cmd_reset(uint8_t *buf)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_RESET);
    UINT8_TO_STREAM (buf, 0);
    return HCI_H4_CMD_PREAMBLE_SIZE;
}



uint16_t make_cmd_ble_set_adv_data(uint8_t *buf, uint8_t data_len, uint8_t *p_data)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_BLE_WRITE_ADV_DATA);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA + 1);

    memset(buf, 0, HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA);

    if (p_data != NULL && data_len > 0) {
        if (data_len > HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA) {
            data_len = HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA;
        }

        UINT8_TO_STREAM (buf, data_len);

        ARRAY_TO_STREAM (buf, p_data, data_len);
    }
    return HCI_H4_CMD_PREAMBLE_SIZE + HCIC_PARAM_SIZE_BLE_WRITE_ADV_DATA + 1;
}

uint16_t make_cmd_ble_set_scan_resp_data(uint8_t *buf, uint8_t data_len, uint8_t *p_data)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_BLE_WRITE_SCAN_RESP_DATA);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_BLE_WRITE_SCAN_RESP_DATA + 1);

    memset(buf, 0, HCIC_PARAM_SIZE_BLE_WRITE_SCAN_RESP_DATA);

    if (p_data != NULL && data_len > 0) {
        if (data_len > HCIC_PARAM_SIZE_BLE_WRITE_SCAN_RESP_DATA) {
            data_len = HCIC_PARAM_SIZE_BLE_WRITE_SCAN_RESP_DATA;
        }

        UINT8_TO_STREAM (buf, data_len);

        ARRAY_TO_STREAM (buf, p_data, data_len);
    }
    return HCI_H4_CMD_PREAMBLE_SIZE + HCIC_PARAM_SIZE_BLE_WRITE_SCAN_RESP_DATA + 1;
}

uint16_t make_cmd_ble_create_connection(uint8_t *buf, uint16_t scan_interval, uint16_t scan_window,
                                uint8_t peer_addr_type, uint8_t *peer_address, uint8_t own_addr_type,
                                uint16_t conn_interval_min, uint16_t conn_interval_max,
                                uint16_t max_latency, uint16_t supervision_timeout,
                                uint16_t min_ce_length, uint16_t max_ce_length)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_BLE_CREATE_CONNECTION);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_BLE_CREATE_CONNECTION);

    UINT16_TO_STREAM(buf, scan_interval);
    UINT16_TO_STREAM(buf, scan_window);
    UINT8_TO_STREAM(buf, 0); /* Initiator Filter Policy (disabled) */
    UINT8_TO_STREAM(buf, peer_addr_type);
    ARRAY_TO_STREAM(buf, peer_address, 6);
    UINT8_TO_STREAM(buf, own_addr_type);
    UINT16_TO_STREAM(buf, conn_interval_min);
    UINT16_TO_STREAM(buf, conn_interval_max);
    UINT16_TO_STREAM(buf, max_latency);
    UINT16_TO_STREAM(buf, supervision_timeout);
    UINT16_TO_STREAM(buf, min_ce_length);
    UINT16_TO_STREAM(buf, max_ce_length);

    return HCI_H4_CMD_PREAMBLE_SIZE + HCIC_PARAM_SIZE_BLE_CREATE_CONNECTION;
}

uint16_t make_cmd_ble_set_random_address(uint8_t *buf, uint8_t *p_address)
{
    UINT8_TO_STREAM (buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM (buf, HCI_BLE_SET_RAND_ADDR);
    UINT8_TO_STREAM  (buf, HCIC_PARAM_SIZE_BLE_SET_RAND_ADDR);

    ARRAY_TO_STREAM(buf, p_address, 6);

    return HCI_H4_CMD_PREAMBLE_SIZE +  HCIC_PARAM_SIZE_BLE_SET_RAND_ADDR;   
}