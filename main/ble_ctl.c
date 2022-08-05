#include "inc/ble_ctl.h"

#define NIMBLE_VHCI_TIMEOUT_MS  2000
#define BLE_HCI_EVENT_HDR_LEN               (2)
#define BLE_HCI_CMD_HDR_LEN                 (3)

const static char *TAG = "Lithium";

ble_controller_t g_ble_ctl;

static void ble_ctl_rcv_pkt_ready(void)
{
    if (g_ble_ctl.vhci_send_sem)
        xSemaphoreGive(g_ble_ctl.vhci_send_sem);
}

static int ble_ctl_host_recv(uint8_t *p_data, uint16_t len)
{
    return 0;
}

static const esp_vhci_host_callback_t vhci_host_cb = {
    .notify_host_send_available = ble_ctl_rcv_pkt_ready,
    .notify_host_recv = ble_ctl_host_recv
};

static esp_err_t ble_ctl_init(void)
{
    esp_err_t ret;

    /* Initialize BT controller. */
    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    if ((ret = esp_bt_controller_init(&bt_cfg)) != ESP_OK) {
        return ret;
    }

    /* Enable BT controller. */
    if ((ret = esp_bt_controller_enable(ESP_BT_MODE_BLE)) != ESP_OK) {
        return ret;
    }

    /* Register our VHCI callbacks. */
     if ((ret = esp_vhci_host_register_callback(&vhci_host_cb)) != ESP_OK) {
        return ESP_FAIL;
    }

    /* Initialize our semaphore. */
    g_ble_ctl.vhci_send_sem = xSemaphoreCreateBinary();
    xSemaphoreGive(g_ble_ctl.vhci_send_sem);

    return ESP_OK;
}

int ble_ctl_send(uint8_t *hci_pkt, uint16_t len)
{
    uint8_t rc = 0;

    if (!esp_vhci_host_check_send_available()) {
        ESP_LOGD(TAG, "Controller not ready to receive packets");
    }

    if (xSemaphoreTake(g_ble_ctl.vhci_send_sem, NIMBLE_VHCI_TIMEOUT_MS / portTICK_PERIOD_MS) == pdTRUE) {
        esp_vhci_host_send_packet(hci_pkt, len);
    } else {
        rc = BLE_HS_ETIMEOUT_HCI;
    }

    return rc;
}

int ble_ctl_ll_set_event_mask(uint64_t mask)
{
    
}

