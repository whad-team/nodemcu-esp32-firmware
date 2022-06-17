#include "inc/adapter.h"

#include "nvs_flash.h"

/* BLE */
#include "esp_nimble_hci.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "console/console.h"
#include "services/gap/ble_svc_gap.h"
#include "blecent.h"

static const char *tag = "whd_ble";
static int blecent_gap_event(struct ble_gap_event *event, void *arg);
static uint8_t peer_addr[6];
static uint8_t null_bd_addr[6] = {0};


static adapter_t g_adapter;
static DeviceCapability g_adapter_cap[] = {
    {discovery_Domain_BtLE, discovery_Capability_SlaveRole | discovery_Capability_MasterRole | discovery_Capability_Inject},
    {0, 0}
};
static uint64_t g_ble_supported_commands = (
    (1 << ble_BleCommand_ScanMode) |
    (1 << ble_BleCommand_CentralMode) |
    (1 << ble_BleCommand_ConnectTo) |
    (1 << ble_BleCommand_Disconnect) |
    (1 << ble_BleCommand_SendPDU) |
    (1 << ble_BleCommand_Start) |
    (1 << ble_BleCommand_Stop)
);

static int blecent_gap_event(struct ble_gap_event *event, void *arg);
static uint8_t peer_addr[6];

void ble_store_config_init(void);


void adapter_init(void)
{
    int rc;

    /* By default, non-connected and act as an observer. */
    g_adapter.state = OBSERVER;
    g_adapter.capabilities = g_adapter_cap;
    g_adapter.active_scan = false;

    /* Initialize NVS — it is used to store PHY calibration data */
    esp_err_t ret = nvs_flash_init();
    if  (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_nimble_hci_and_controller_init());

    nimble_port_init();
    
    /* Configure the host. */
    ble_hs_cfg.reset_cb = blecent_on_reset;
    ble_hs_cfg.sync_cb = blecent_on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    /* Initialize data structures to track connected peers. */
    rc = peer_init(MYNEWT_VAL(BLE_MAX_CONNECTIONS), 64, 64, 64);
    assert(rc == 0);

    /* Set the default device name. */
    rc = ble_svc_gap_device_name_set("nimble-blecent");
    assert(rc == 0);

    /* XXX Need to have template for store */
    ble_store_config_init();

    dbg_txt("Start BLE host task");
    nimble_port_freertos_init(blecent_host_task);
    

}

/****************************************************
 * NimBLE callbacks & helpers
 ***************************************************/

/**
 * Application callback.  Called when the attempt to subscribe to notifications
 * for the ANS Unread Alert Status characteristic has completed.
 */
static int
blecent_on_subscribe(uint16_t conn_handle,
                     const struct ble_gatt_error *error,
                     struct ble_gatt_attr *attr,
                     void *arg)
{
    MODLOG_DFLT(INFO, "Subscribe complete; status=%d conn_handle=%d "
                "attr_handle=%d\n",
                error->status, conn_handle, attr->handle);

    return 0;
}

/**
 * Application callback.  Called when the write to the ANS Alert Notification
 * Control Point characteristic has completed.
 */
static int
blecent_on_write(uint16_t conn_handle,
                 const struct ble_gatt_error *error,
                 struct ble_gatt_attr *attr,
                 void *arg)
{
    MODLOG_DFLT(INFO,
                "Write complete; status=%d conn_handle=%d attr_handle=%d\n",
                error->status, conn_handle, attr->handle);

    /* Subscribe to notifications for the Unread Alert Status characteristic.
     * A central enables notifications by writing two bytes (1, 0) to the
     * characteristic's client-characteristic-configuration-descriptor (CCCD).
     */
    const struct peer_dsc *dsc;
    uint8_t value[2];
    int rc;
    const struct peer *peer = peer_find(conn_handle);

    dsc = peer_dsc_find_uuid(peer,
                             BLE_UUID16_DECLARE(BLECENT_SVC_ALERT_UUID),
                             BLE_UUID16_DECLARE(BLECENT_CHR_UNR_ALERT_STAT_UUID),
                             BLE_UUID16_DECLARE(BLE_GATT_DSC_CLT_CFG_UUID16));
    if (dsc == NULL) {
        MODLOG_DFLT(ERROR, "Error: Peer lacks a CCCD for the Unread Alert "
                    "Status characteristic\n");
        goto err;
    }

    value[0] = 1;
    value[1] = 0;
    rc = ble_gattc_write_flat(conn_handle, dsc->dsc.handle,
                              value, sizeof value, blecent_on_subscribe, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to subscribe to characteristic; "
                    "rc=%d\n", rc);
        goto err;
    }

    return 0;
err:
    /* Terminate the connection. */
    return ble_gap_terminate(peer->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
}

/**
 * Application callback.  Called when the read of the ANS Supported New Alert
 * Category characteristic has completed.
 */
static int
blecent_on_read(uint16_t conn_handle,
                const struct ble_gatt_error *error,
                struct ble_gatt_attr *attr,
                void *arg)
{
    MODLOG_DFLT(INFO, "Read complete; status=%d conn_handle=%d", error->status,
                conn_handle);
    if (error->status == 0) {
        MODLOG_DFLT(INFO, " attr_handle=%d value=", attr->handle);
        print_mbuf(attr->om);
    }
    MODLOG_DFLT(INFO, "\n");

    /* Write two bytes (99, 100) to the alert-notification-control-point
     * characteristic.
     */
    const struct peer_chr *chr;
    uint8_t value[2];
    int rc;
    const struct peer *peer = peer_find(conn_handle);

    chr = peer_chr_find_uuid(peer,
                             BLE_UUID16_DECLARE(BLECENT_SVC_ALERT_UUID),
                             BLE_UUID16_DECLARE(BLECENT_CHR_ALERT_NOT_CTRL_PT));
    if (chr == NULL) {
        MODLOG_DFLT(ERROR, "Error: Peer doesn't support the Alert "
                    "Notification Control Point characteristic\n");
        goto err;
    }

    value[0] = 99;
    value[1] = 100;
    rc = ble_gattc_write_flat(conn_handle, chr->chr.val_handle,
                              value, sizeof value, blecent_on_write, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to write characteristic; rc=%d\n",
                    rc);
        goto err;
    }

    return 0;
err:
    /* Terminate the connection. */
    return ble_gap_terminate(peer->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
}

/**
 * Performs three GATT operations against the specified peer:
 * 1. Reads the ANS Supported New Alert Category characteristic.
 * 2. After read is completed, writes the ANS Alert Notification Control Point characteristic.
 * 3. After write is completed, subscribes to notifications for the ANS Unread Alert Status
 *    characteristic.
 *
 * If the peer does not support a required service, characteristic, or
 * descriptor, then the peer lied when it claimed support for the alert
 * notification service!  When this happens, or if a GATT procedure fails,
 * this function immediately terminates the connection.
 */
static void
blecent_read_write_subscribe(const struct peer *peer)
{
    const struct peer_chr *chr;
    int rc;

    /* Read the supported-new-alert-category characteristic. */
    chr = peer_chr_find_uuid(peer,
                             BLE_UUID16_DECLARE(BLECENT_SVC_ALERT_UUID),
                             BLE_UUID16_DECLARE(BLECENT_CHR_SUP_NEW_ALERT_CAT_UUID));
    if (chr == NULL) {
        MODLOG_DFLT(ERROR, "Error: Peer doesn't support the Supported New "
                    "Alert Category characteristic\n");
        goto err;
    }

    rc = ble_gattc_read(peer->conn_handle, chr->chr.val_handle,
                        blecent_on_read, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to read characteristic; rc=%d\n",
                    rc);
        goto err;
    }

    return;
err:
    /* Terminate the connection. */
    ble_gap_terminate(peer->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
}

/**
 * Called when service discovery of the specified peer has completed.
 */
static void
blecent_on_disc_complete(const struct peer *peer, int status, void *arg)
{

    if (status != 0) {
        /* Service discovery failed.  Terminate the connection. */
        MODLOG_DFLT(ERROR, "Error: Service discovery failed; status=%d "
                    "conn_handle=%d\n", status, peer->conn_handle);
        ble_gap_terminate(peer->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }

    /* Service discovery has completed successfully.  Now we have a complete
     * list of services, characteristics, and descriptors that the peer
     * supports.
     */
    MODLOG_DFLT(ERROR, "Service discovery complete; status=%d "
                "conn_handle=%d\n", status, peer->conn_handle);

    /* Now perform three GATT procedures against the peer: read,
     * write, and subscribe to notifications.
     */
    //blecent_read_write_subscribe(peer);
}

/**
 * Initiates the GAP general discovery procedure.
 */
static void
blecent_scan(void)
{
    uint8_t own_addr_type;
    struct ble_gap_disc_params disc_params;
    int rc;

    /* Figure out address to use while advertising (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        dbg_txt("error determining address type; rc=%d\n", rc);
        return;
    }

    /* Tell the controller to filter duplicates; we don't want to process
     * repeated advertisements from the same device.
     */
    //disc_params.filter_duplicates = 1;

    /**
     * Perform a passive scan.  I.e., don't send follow-up scan requests to
     * each advertiser.
     */
    disc_params.passive = (!g_adapter.active_scan);

    /* Use defaults for the rest of the parameters. */
    disc_params.itvl = 0;
    disc_params.window = 0;
    disc_params.filter_policy = 0;
    disc_params.limited = 0;

    rc = ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &disc_params,
                      blecent_gap_event, NULL);
    if (rc != 0) {
        dbg_txt("Error initiating GAP discovery procedure; rc=%d\n",
                    rc);
    }

    dbg_txt("GAP discovery initiated.");
}

/**
 * Indicates whether we should try to connect to the sender of the specified
 * advertisement.  The function returns a positive result if the device
 * advertises connectability and support for the Alert Notification service.
 */
static int
blecent_should_connect(const struct ble_gap_disc_desc *disc)
{
    struct ble_hs_adv_fields fields;
    int rc;
    int i;

    /* The device has to be advertising connectability. */
    if (disc->event_type != BLE_HCI_ADV_RPT_EVTYPE_ADV_IND &&
            disc->event_type != BLE_HCI_ADV_RPT_EVTYPE_DIR_IND) {

        return 0;
    }

    rc = ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data);
    if (rc != 0) {
        return rc;
    }

    if (memcmp(g_adapter.target_dev_addr, disc->addr.val, sizeof(disc->addr.val)) != 0) {
        return 0;
    }

    return 1;
}

/**
 * Connects to the sender of the specified advertisement of it looks
 * interesting.  A device is "interesting" if it advertises connectability and
 * support for the Alert Notification service.
 */
static void
blecent_connect_if_interesting(const struct ble_gap_disc_desc *disc)
{
    uint8_t own_addr_type;
    int rc;

    /* Don't do anything if we don't care about this advertiser. */
    if (!blecent_should_connect(disc)) {
        return;
    }

    /* Scanning must be stopped before a connection can be initiated. */
    rc = ble_gap_disc_cancel();
    if (rc != 0) {
        MODLOG_DFLT(DEBUG, "Failed to cancel scan; rc=%d\n", rc);
        return;
    }

    /* Figure out address to use for connect (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "error determining address type; rc=%d\n", rc);
        return;
    }

    /* Try to connect the the advertiser.  Allow 30 seconds (30000 ms) for
     * timeout.
     */

    rc = ble_gap_connect(own_addr_type, &disc->addr, 30000, NULL,
                         blecent_gap_event, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to connect to device; addr_type=%d "
                    "addr=%s; rc=%d\n",
                    disc->addr.type, addr_str(disc->addr.val), rc);
        return;
    }
}

/**
 * The nimble host executes this callback when a GAP event occurs.  The
 * application associates a GAP event callback with each connection that is
 * established.  blecent uses the same callback for all connections.
 *
 * @param event                 The event being signalled.
 * @param arg                   Application-specified argument; unused by
 *                                  blecent.
 *
 * @return                      0 if the application successfully handled the
 *                                  event; nonzero on failure.  The semantics
 *                                  of the return code is specific to the
 *                                  particular GAP event being signalled.
 */
static int
blecent_gap_event(struct ble_gap_event *event, void *arg)
{
    struct ble_gap_conn_desc desc;
    struct ble_hs_adv_fields fields;
    int rc;

    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        rc = ble_hs_adv_parse_fields(&fields, event->disc.data,
                                     event->disc.length_data);
        if (rc != 0) {
            return 0;
        }
        
        switch (event->disc.event_type)
        {
            case BLE_HCI_ADV_RPT_EVTYPE_NONCONN_IND:
            {
                if (g_adapter.state == OBSERVER)
                {
                    /* An advertisment report was received during GAP discovery. */
                    adapter_on_notify_adv(
                        ble_BleAdvType_ADV_NONCONN_IND,
                        event->disc.rssi,
                        event->disc.addr.val,
                        event->disc.data,
                        event->disc.length_data,
                        NULL,
                        0
                    );
                }
            }
            break;

            case BLE_HCI_ADV_RPT_EVTYPE_ADV_IND:
            {
                if (g_adapter.state == OBSERVER)
                {
                    /* An advertisment report was received during GAP discovery. */
                    adapter_on_notify_adv(
                        ble_BleAdvType_ADV_IND,
                        event->disc.rssi,
                        event->disc.addr.val,
                        event->disc.data,
                        event->disc.length_data,
                        NULL,
                        0
                    );
                }
                else if (g_adapter.state == CENTRAL)
                {
                    //dbg_txt("ADV PDU received");

                    /* Try to connect to the advertiser if it looks interesting. */
                    blecent_connect_if_interesting(&event->disc);
                }

            }
            break;

            case BLE_HCI_ADV_RPT_EVTYPE_SCAN_IND:
            {
                if (g_adapter.state == OBSERVER)
                {
                    /* An advertisment report was received during GAP discovery. */
                    adapter_on_notify_adv(
                        ble_BleAdvType_ADV_SCAN_IND,
                        event->disc.rssi,
                        event->disc.addr.val,
                        event->disc.data,
                        event->disc.length_data,
                        NULL,
                        0
                    );
                }
            }
            break;

            case BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP:
            {
                if (g_adapter.state == OBSERVER)
                {
                    /* An advertisment report was received during GAP discovery. */
                    adapter_on_notify_adv(
                        ble_BleAdvType_ADV_SCAN_RSP,
                        event->disc.rssi,
                        event->disc.addr.val,
                        NULL,
                        0,
                        event->disc.data,
                        event->disc.length_data
                    );
                }
            }
            break;

            default:
            break;
        }
        return 0;

    case BLE_GAP_EVENT_CONNECT:
        /* A new connection was established or a connection attempt failed. */
        if (event->connect.status == 0) {
            dbg_txt("[nimble] connection established\r\n");
            
            g_adapter.conn_handle = event->connect.conn_handle;
            g_adapter.conn_state = CONNECTED;

            adapter_on_notify_connected();

            rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
            assert(rc == 0);
            print_conn_desc(&desc);
            MODLOG_DFLT(INFO, "\n");

            /* Remember peer. */
            rc = peer_add(event->connect.conn_handle);
            if (rc != 0) {
                MODLOG_DFLT(ERROR, "Failed to add peer; rc=%d\n", rc);
                return 0;
            }

        } else {
            /* Connection attempt failed; resume scanning. */
            MODLOG_DFLT(ERROR, "Error: Connection failed; status=%d\n",
                        event->connect.status);
            blecent_scan();
        }

        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        dbg_txt("[nimble] disconnected\r\n");
        /* Connection terminated. */
        MODLOG_DFLT(INFO, "disconnect; reason=%d ", event->disconnect.reason);
        print_conn_desc(&event->disconnect.conn);
        MODLOG_DFLT(INFO, "\n");

        /* Forget about peer. */
        peer_delete(event->disconnect.conn.conn_handle);

        g_adapter.conn_state = DISCONNECTED;

        /* Resume scanning. */
        blecent_scan();
        return 0;

    case BLE_GAP_EVENT_DISC_COMPLETE:
        dbg_txt("discovery complete; reason=%d\n",
                    event->disc_complete.reason);
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        /* Encryption has been enabled or disabled for this connection. */
        MODLOG_DFLT(INFO, "encryption change event; status=%d ",
                    event->enc_change.status);
        rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
        assert(rc == 0);
        print_conn_desc(&desc);
        return 0;

    case BLE_GAP_EVENT_NOTIFY_RX:
        /* Peer sent us a notification or indication. */
        MODLOG_DFLT(INFO, "received %s; conn_handle=%d attr_handle=%d "
                    "attr_len=%d\n",
                    event->notify_rx.indication ?
                    "indication" :
                    "notification",
                    event->notify_rx.conn_handle,
                    event->notify_rx.attr_handle,
                    OS_MBUF_PKTLEN(event->notify_rx.om));

        /* Attribute data is contained in event->notify_rx.om. Use
         * `os_mbuf_copydata` to copy the data received in notification mbuf */
        return 0;

    case BLE_GAP_EVENT_MTU:
        MODLOG_DFLT(INFO, "mtu update event; conn_handle=%d cid=%d mtu=%d\n",
                    event->mtu.conn_handle,
                    event->mtu.channel_id,
                    event->mtu.value);
        return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING:
        /* We already have a bond with the peer, but it is attempting to
         * establish a new secure link.  This app sacrifices security for
         * convenience: just throw away the old bond and accept the new link.
         */

        /* Delete the old bond. */
        rc = ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc);
        assert(rc == 0);
        ble_store_util_delete_peer(&desc.peer_id_addr);

        /* Return BLE_GAP_REPEAT_PAIRING_RETRY to indicate that the host should
         * continue with the pairing operation.
         */
        return BLE_GAP_REPEAT_PAIRING_RETRY;

    default:
        return 0;
    }
}

static void blecent_on_reset(int reason)
{
    dbg_txt("Resetting state; reason=%d\n", reason);
}

static void blecent_on_sync(void)
{
    int rc;

    dbg_txt("blecent_on_sync");

    /* Make sure we have proper identity address set (public preferred) */
    rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);

    /* Begin scanning for a peripheral to connect to. */
    blecent_scan();
}

static void blecent_host_task(void *param)
{   
    dbg_txt("blecent_host_task");

    /* This function will return only when nimble_port_stop() is executed */
    nimble_port_run();
    nimble_port_freertos_deinit();
}

int ble_rx_ctl_handler(uint16_t header, uint8_t *p_pdu, int length)
{
  dbg_txt_rom("[ble:rx:ctl] got %d bytes", length);
  
  return HOOK_FORWARD;
}

int ble_rx_data_handler(uint16_t header, uint8_t *p_pdu, int length)
{
  /* Rebuild a data PDU and send it to the host. We don't need to forward this
  to the underlying BLE stack as it is not used in our case. */
  Message pdu;

  whad_ble_ll_data_pdu(&pdu, header, p_pdu, length, ble_BleDirection_SLAVE_TO_MASTER);
  pending_pb_message(&pdu);

  return HOOK_FORWARD;
}

/* This handler SHALL NOT be called, as the underlying BLE stack is not supposed
to send data. */
int ble_tx_data_handler(uint16_t header, uint8_t *p_pdu, int length)
{
  /* Rebuild a data PDU and send it to the host. We don't need to forward this
  to the underlying BLE stack as it is not used in our case. */
  Message pdu;

  whad_ble_ll_data_pdu(&pdu, header, p_pdu, length, ble_BleDirection_MASTER_TO_SLAVE);
  pending_pb_message(&pdu);

  return HOOK_FORWARD;
}

int ble_tx_ctl_handler(llcp_opinfo *p_llcp_pdu)
{
  dbg_txt_rom("[ble:tx:ctl] sent 0x%02x opcode", p_llcp_pdu->opcode);
  return HOOK_FORWARD;
}

void adapter_quit_state(adapter_state_t state)
{
    switch (state)
    {
        case OBSERVER:
            {
                dbg_txt("GAP disc canceled");

                /* Cancel device discovery. */
                ble_gap_disc_cancel();
            }
            break;

        case CENTRAL:
            {
                /* Stop advertising if required. */
                if (ble_gap_adv_active())
                {
                    /* Stop advertising. */
                    ble_gap_adv_stop();
                }
                else if (ble_gap_conn_active())
                {
                    /* Terminate connection. */
                    ble_gap_terminate(g_adapter.conn_handle, 3);
                }

                /* Reset target address. */
                memset(g_adapter.target_dev_addr, 0, 6);
                g_adapter.conn_state = DISCONNECTED;
                g_adapter.conn_handle = 0;
            }

        default:
            break;
    }
}

adapter_state_t adapter_enter_state(adapter_state_t state)
{
    switch (state)
    {
        case OBSERVER:
            {
                /* Start passive scanner. */
                //blecent_scan();
            }
            break;

        case CENTRAL:
            {
                /* Reset target address. */
                memset(g_adapter.target_dev_addr, 0, 6);
            }
            break;

        default:
            break;
    }

    return state;
}

bool adapter_set_state(adapter_state_t state)
{
    dbg_txt("adapter set state");
    adapter_quit_state(g_adapter.state);
    g_adapter.state = adapter_enter_state(state);
    return (g_adapter.state == state);
}

/****************************************************
 * Adapter events callbacks
 ***************************************************/

void adapter_on_unsupported(Message *message)
{
    Message reply;
    whad_init_error_message(&reply, generic_ResultCode_ERROR);
    send_pb_message(&reply);
}

void adapter_on_device_info_req(discovery_DeviceInfoQuery *query)
{
    Message reply;

    memset(&reply, 0, sizeof(Message));
    whad_discovery_device_info_resp(
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

void adapter_on_domain_info_req(discovery_DeviceDomainInfoQuery *query)
{
    Message reply;

    switch (query->domain)
    {
        case discovery_Domain_BtLE:
        {
            memset(&reply, 0, sizeof(Message));
            whad_discovery_domain_info_resp(
                &reply,
                discovery_Domain_BtLE,
                g_ble_supported_commands
            );
            send_pb_message(&reply);
        }
        break;

        default:
        {
            whad_generic_cmd_result(
                &reply,
                generic_ResultCode_UNSUPPORTED_DOMAIN
            );
            send_pb_message(&reply);
        }
        break;

    }
}

void adapter_on_notify_adv(uint8_t adv_type, int rssi, uint8_t *bd_addr, uint8_t *p_adv_data, int adv_data_length, uint8_t *p_scan_rsp, int scan_rsp_length)
{
    Message notification;
    whad_adv_data_t adv_data;

    memset(&notification, 0, sizeof(Message));
    memcpy(adv_data.bd_addr, bd_addr, 6);
    adv_data.p_adv_data = p_adv_data;
    adv_data.adv_data_length = adv_data_length;
    adv_data.p_scan_rsp = p_scan_rsp;
    adv_data.scan_rsp_length = scan_rsp_length;
    adv_data.rssi = rssi;
    adv_data.adv_type = adv_type;

    /* Build notification and send to host. */
    whad_ble_adv_pdu(&notification, &adv_data);
    send_pb_message(&notification);
}

void adapter_on_notify_connected(void)
{
    Message notification;

    whad_ble_notify_connected(&notification);
    send_pb_message(&notification);
}

void adapter_on_sniff_adv(ble_SniffAdvCmd *sniff_adv)
{
    Message cmd_result;

    /* Switch to observer mode. */
    if (adapter_set_state(OBSERVER))
    {
        /* Start scanner. */
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
        send_pb_message(&cmd_result);
    }
    else
    {
        whad_init_error_message(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);
    }
}

void adapter_on_enable_scan(ble_ScanModeCmd *scan_mode)
{
    Message cmd_result;

    /* Switch to observer mode. */
    if (adapter_set_state(OBSERVER))
    {
        dbg_txt("observer mode set");

        /* Store scan mode. */
        g_adapter.active_scan = scan_mode->active_scan;

        /* Start scanner. */
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
        send_pb_message(&cmd_result);
    }
    else
    {
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);
    }
}

void adapter_on_enable_central(ble_CentralModeCmd *central_mode)
{
    Message cmd_result;

    /* Switch to central mode. */
    if (adapter_set_state(CENTRAL))
    {
        dbg_txt("central mode set");

        whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
        send_pb_message(&cmd_result);
    }
    else
    {
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);        
    }
}

void adapter_on_connect(ble_ConnectToCmd *connect)
{
    Message cmd_result;

    if ((g_adapter.state == CENTRAL))
    {
        /* Copy target address. */
        memcpy(g_adapter.target_dev_addr, connect->bd_address, 6);

        /* Success ! */
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
        send_pb_message(&cmd_result);
    }
    else
    {
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);   
    }
}

void adapter_on_start(ble_StartCmd *start)
{
    Message cmd_result;

    switch (g_adapter.state)
    {
        case OBSERVER:
        {
            dbg_txt("Start scanning ...");

            /* Enable scanner. */
            blecent_scan();

            /* Success. */
            whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
            send_pb_message(&cmd_result);

            return;
        }
        break;

        case CENTRAL:
        {
            if (memcmp(g_adapter.target_dev_addr, null_bd_addr, 6))
            {
                /* Start scanning. */
                blecent_scan();

                /* Success. */
                whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
                send_pb_message(&cmd_result);                

                return;
            }
            else
            {
                /* Send an error (wrong parameter). */
                whad_generic_cmd_result(&cmd_result, generic_ResultCode_PARAMETER_ERROR);
                send_pb_message(&cmd_result);   
            }
        }
        break;

        default:
            break;
    }

    /* Error. */
    whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
    send_pb_message(&cmd_result);
}

void adapter_on_stop(ble_StartCmd *stop)
{
    Message cmd_result;

    switch (g_adapter.state)
    {
        case OBSERVER:
        {
            dbg_txt("Stop GAP disc");

            /* Cancel device discovery. */
            ble_gap_disc_cancel();

            /* Success. */
            whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
            send_pb_message(&cmd_result);

            return;
        }
        break;

        case CENTRAL:
        {
            /* Stop advertising if required. */
            if (ble_gap_adv_active())
            {
                /* Stop advertising. */
                ble_gap_adv_stop();
            }
            else if (ble_gap_conn_active())
            {
                /* Terminate connection. */
                ble_gap_terminate(g_adapter.conn_handle, 3);
            }
        }
        break;

        default:
            break;
    }

    /* Error. */
    whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
    send_pb_message(&cmd_result);
}

void adapter_on_send_pdu(ble_SendPDUCmd *send_pdu)
{
    Message cmd_result;

    if ((g_adapter.state == CENTRAL) && (g_adapter.conn_state == CONNECTED))
    {
        /* Send PDU. */
        send_raw_data_pdu(
            g_adapter.conn_handle,
            send_pdu->pdu.bytes[0],
            &send_pdu->pdu.bytes[2],
            send_pdu->pdu.bytes[1],
            false
        );

        /* Success ! */
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
        send_pb_message(&cmd_result);
    }
    else
    {
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);   
    }
}