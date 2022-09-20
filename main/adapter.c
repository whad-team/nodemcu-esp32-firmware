#include "inc/adapter.h"

#include "nvs_flash.h"

/* BLE */
#include "esp_nimble_hci.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "nimble/ble.h"
#include "host/util/util.h"
#include "console/console.h"
#include "services/gap/ble_svc_gap.h"
#include "blecent.h"

static const char *tag = "whd_ble";
static int blecent_gap_event(struct ble_gap_event *event, void *arg);
static uint8_t peer_addr[6];
static uint8_t null_bd_addr[6] = {0};

extern struct ble_hs_conn;
extern struct ble_hs_conn *ble_hs_conn_find(uint16_t handle);
extern int r_lld_util_set_bd_address(uint8_t *p_bd_addr, uint32_t addr_type);
extern uint8_t g_dev_address[6];

adapter_t g_adapter;
static DeviceCapability g_adapter_cap[] = {
    {discovery_Domain_BtLE, discovery_Capability_SlaveRole | discovery_Capability_MasterRole | discovery_Capability_Inject | discovery_Capability_NoRawData},
    {0, 0}
};
static uint64_t g_ble_supported_commands = (
    (1 << ble_BleCommand_AdvMode) |
    (1 << ble_BleCommand_PeripheralMode) |
    (1 << ble_BleCommand_ScanMode) |
    (1 << ble_BleCommand_CentralMode) |
    (1 << ble_BleCommand_ConnectTo) |
    (1 << ble_BleCommand_Disconnect) |
    (1 << ble_BleCommand_SendPDU) |
    (1 << ble_BleCommand_Start) |
    (1 << ble_BleCommand_Stop) |
    (1 << ble_BleCommand_SetBdAddress)
);

static int blecent_gap_event(struct ble_gap_event *event, void *arg);
static uint8_t peer_addr[6];
void ble_store_config_init(void);
char dbg[256];
uint8_t _pdu[256];
Message pdu_msg;

bool IRAM_ATTR send_pdu(uint8_t *p_pdu, int length, bool b_encrypt)
{
    bool b_sent = false;
    uint8_t *p_pkt = NULL;
    uint16_t *pkt_count;
    struct ble_hs_conn *conn;
    int res,i;

    /* Handle encryption. */
    if (b_encrypt)
    {
        /* Allocate a new buffer for pdu. */
        p_pkt = (uint8_t *)malloc(p_pdu[1] + 4);
        if (p_pkt != NULL)
        {
            /* Encrypt PDU. */
            res = encrypt_pdu(
                p_pdu[0],     /* LLID */
                &p_pdu[2],    /* plaintext PDU payload */
                p_pdu[1],     /* Length */
                p_pkt,    /* Output buffer (enc payload + MIC) */    
                (g_adapter.state == CENTRAL)
            );

            if (!res)
            {
                /* Send packet. */
                send_raw_data_pdu(
                    g_adapter.conn_handle,
                    p_pdu[0],   // original LLID
                    p_pkt,        // encrypted PDU
                    p_pdu[1]+4, // length + size of MIC
                    true
                );

                /* Packet has been sent. */
                b_sent = true;             
            }
            else
            {
                esp_rom_printf("Error while encrypting: %d", res);
            }

            /* Free encrypted packet. */
            free(p_pkt);
        }
    }
    else
    {
        /* Send PDU. */
        send_raw_data_pdu(
            g_adapter.conn_handle,
            p_pdu[0],
            &p_pdu[2],
            p_pdu[1],
            true
        );

        /* Packet has been sent. */
        b_sent = true;
    }

    if (b_sent)
    {
        /* Update connection packets. */
        conn = ble_hs_conn_find(g_adapter.conn_handle);
        if (conn != NULL)
        {
            pkt_count = (uint16_t *)(((uint8_t *)conn) + 56);
            (*pkt_count)++;
        }
    }

    /* Return operation status. */
    return b_sent;
}

void send_terminate_ind(void)
{
    /* Send LL_TERMINATE_IND. */
    send_pdu((uint8_t *)"\x03\x02\x02\x13", 4, g_adapter.b_encrypted);
}

void adapter_init(void)
{
    uint8_t mac_addr[6];
    Message msg;
    int rc;

    /* Generate device name based on MAC */
    esp_read_mac(mac_addr, ESP_MAC_BT);
    snprintf(
        (char *)g_adapter.dev_name,
        16,
        "esp32_%02x%02x%02x",
        mac_addr[3],
        mac_addr[4],
        mac_addr[5]
    );


    /* By default, non-connected and act as an observer. */
    g_adapter.state = OBSERVER;
    g_adapter.capabilities = g_adapter_cap;
    g_adapter.active_scan = false;
    g_adapter.b_enabled = false;

    /* Initialize encryption material. */
    g_adapter.b_encrypted = false;
    memset(g_adapter.enc_key, 0, 16);
    memset(g_adapter.enc_iv, 0, 16);
    g_adapter.enc_master_counter = 0;
    g_adapter.enc_slave_counter = 0;

    /* Initialize L2CAP filtering mechanism. */
    g_adapter.b_l2cap_started = false;
    g_adapter.l2cap_pkt_size = 0;
    g_adapter.l2cap_recv_bytes = 0;

    /* Initialize RX/TX queues. */
    packet_queue_init(&g_adapter.tx_queue);
    packet_queue_init(&g_adapter.rx_queue);

    /* Initialize NVS — it is used to store PHY calibration data */
    esp_err_t ret = nvs_flash_init();
    if  (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_nimble_hci_and_controller_init());

    nimble_port_init();
    
    /* Initialize advertising data. */
    memset(g_adapter.adv_data, 0, 31);
    g_adapter.adv_data_length = 0;
    memset(g_adapter.adv_rsp_data, 0, 31);
    g_adapter.adv_rsp_data_length = 0;

    /* Initialize BD address spoofing. */
    memset(g_adapter.my_dev_addr, 0, 6);
    g_adapter.b_spoof_addr = false;
    
    /* Configure the host. */
    ble_hs_cfg.reset_cb = blecent_on_reset;
    ble_hs_cfg.sync_cb = blecent_on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    ble_hs_cfg.sm_io_cap =  BLE_SM_IO_CAP_NO_IO;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 0;
    ble_hs_cfg.sm_our_key_dist = 1;
    ble_hs_cfg.sm_their_key_dist = 1;

    /* Initialize data structures to track connected peers. */
    rc = peer_init(MYNEWT_VAL(BLE_MAX_CONNECTIONS), 64, 64, 64);
    assert(rc == 0);

    /* Set the default device name. */
    rc = ble_svc_gap_device_name_set("nimble-blecent");
    assert(rc == 0);

    /* XXX Need to have template for store */
    ble_store_config_init();

    //dbg_txt("Start BLE host task");
    nimble_port_freertos_init(blecent_host_task);

    /* Disable RWBLE crypto. */
    ble_disable_crypto();

    /* Adapter is ready now ! */
    whad_discovery_ready_resp(&msg);
    send_pb_message(&msg);

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
    struct ble_gap_disc_params disc_params;
    int rc;

    /* Figure out address to use while advertising (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &g_adapter.my_addr_type);
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

    rc = ble_gap_disc(g_adapter.my_addr_type, BLE_HS_FOREVER, &disc_params,
                      blecent_gap_event, NULL);
    if (rc != 0) {
        dbg_txt("Error initiating GAP discovery procedure; rc=%d\n",
                    rc);
    }

    dbg_txt("GAP discovery initiated (mode: %d).", g_adapter.state);
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

    /* Make sure target address and address type match. */
    if (
        (memcmp(g_adapter.target_dev_addr, disc->addr.val, sizeof(disc->addr.val)) != 0) ||
        (g_adapter.target_dev_addr_type != (disc->addr.type & 0x01))
    ) {
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
    rc = ble_hs_id_infer_auto(0, &g_adapter.my_addr_type);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "error determining address type; rc=%d\n", rc);
        return;
    }
    

    /* Try to connect the the advertiser.  Allow 30 seconds (30000 ms) for
     * timeout.
     */

    rc = ble_gap_connect(g_adapter.my_addr_type, &disc->addr, 30000, NULL,
                         blecent_gap_event, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to connect to device; addr_type=%d "
                    "addr=%s; rc=%d\n",
                    disc->addr.type, addr_str(disc->addr.val), rc);
        return;
    }

    /*
     * Update BD address right after having initiated a GAP connection.
     */

    if (g_adapter.b_spoof_addr)
    {
        r_lld_util_set_bd_address(g_adapter.my_dev_addr, 0);
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

    printf("GAP event: %d\n", event->type);

    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        rc = ble_hs_adv_parse_fields(&fields, event->disc.data,
                                     event->disc.length_data);
        if (rc != 0) {
            return 0;
        }
        
        switch (event->disc.event_type)
        {
            case BLE_HCI_ADV_RPT_EVTYPE_DIR_IND:
            {
                if (g_adapter.state == OBSERVER)
                {
                    /* An advertisment report was received during GAP discovery. */
                    adapter_on_notify_adv(
                        ble_BleAdvType_ADV_DIRECT_IND,
                        event->disc.rssi,
                        event->disc.addr.type & 0x01,
                        event->disc.addr.val,
                        event->disc.data,
                        event->disc.length_data
                    );
                }
            }
            break;

            case BLE_HCI_ADV_RPT_EVTYPE_NONCONN_IND:
            {
                if (g_adapter.state == OBSERVER)
                {
                    /* An advertisment report was received during GAP discovery. */
                    adapter_on_notify_adv(
                        ble_BleAdvType_ADV_NONCONN_IND,
                        event->disc.rssi,
                        event->disc.addr.type & 0x01,
                        event->disc.addr.val,
                        event->disc.data,
                        event->disc.length_data
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
                        event->disc.addr.type & 0x01,
                        event->disc.addr.val,
                        event->disc.data,
                        event->disc.length_data
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
                        event->disc.addr.type & 0x01,
                        event->disc.addr.val,
                        event->disc.data,
                        event->disc.length_data
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
                        event->disc.addr.type & 0x01,
                        event->disc.addr.val,
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
        /* Connection is only allowed when in peripheral or central mode. */
        if ((g_adapter.state == PERIPHERAL) || (g_adapter.state == CENTRAL) )
        {
            /* A new connection was established or a connection attempt failed. */
            if (event->connect.status == 0) {
                dbg_txt("[nimble] connection established\r\n");
                
                g_adapter.conn_handle = event->connect.conn_handle;
                g_adapter.conn_state = CONNECTED;

                rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
                assert(rc == 0);
                
                /* In Peripheral mode, WE are advertising. */
                if (g_adapter.state == PERIPHERAL)
                {
                    /* Notify peer connection. */
                    adapter_on_notify_connected(
                        desc.our_ota_addr.type & 0x01,
                        desc.our_ota_addr.val,
                        desc.peer_ota_addr.type & 0x01,
                        desc.peer_ota_addr.val
                    );
                }
                else
                {
                    /* Notify peer connection. */
                    adapter_on_notify_connected(
                        desc.peer_ota_addr.type & 0x01,
                        desc.peer_ota_addr.val,
                        desc.our_ota_addr.type & 0x01,
                        desc.our_ota_addr.val
                    );
                }

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

        adapter_on_notify_disconnected();
        g_adapter.conn_handle = -1;
        g_adapter.conn_state = DISCONNECTED;
        g_adapter.b_encrypted = false; /* Do not encrypt anymore. */

        if (g_adapter.state == CENTRAL)
        {
            if (g_adapter.b_enabled)
            {
                /* Resume scanning. */
                blecent_scan();
            }
        }
        else if (g_adapter.state == PERIPHERAL)
        {
            ble_advertise();
        }
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

    case BLE_GAP_EVENT_ADV_COMPLETE:
        if ( (g_adapter.state == PERIPHERAL) || (g_adapter.state == BROADCASTER) )
        {
            /* Restart advertising. */
            ble_advertise();
        }
        return 0;

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
    //blecent_scan();
}

static void blecent_host_task(void *param)
{   
    dbg_txt("blecent_host_task");

    /* This function will return only when nimble_port_stop() is executed */
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void IRAM_ATTR ble_tx_prog_handler(void)
{
    uint8_t direction, flags, llid, length;
    uint16_t conn_handle;
    int ret;
    bool res;

    if (g_adapter.conn_handle >= 0)
    {
        /* Check queue size. */
        if (g_adapter.tx_queue.size > 0)
        {
            //esp_rom_printf("[tx_prog hook] txqueue: %d\n", g_adapter.tx_queue.size);

            /* We still have some data to send. */
            _pdu[1] = 254;
            ret = packet_queue_pop(
                &g_adapter.tx_queue,
                &direction,
                &flags, 
                &conn_handle,
                &_pdu[0],    /* First byte is LLID */
                &_pdu[1],    /* Second byte is length */
                &_pdu[2]     /* Next is BLE PDU */
            );

            /* PDU successfully extracted from queue. */
            if (ret == RX_QUEUE_SUCCESS)
            {
                /* Include LLID and length in data to send. */
                length = _pdu[1] + 2;

                switch (g_adapter.state)
                {
                    case CENTRAL:
                    {
                        //if (direction == ble_BleDirection_MASTER_TO_SLAVE)
                        if (1)
                        {
                            /* Send PDU. */
                            res = send_pdu(
                                _pdu,
                                length,
                                ((flags & RX_QUEUE_FLAG_ENCRYPTED) != 0) /* If encrypted flag set, enable encryption. */
                            );
                            //esp_rom_printf("[txprog] sent pdu (%d)\n", res);
                        }
                    }
                    break;

                    case PERIPHERAL:
                    {
                        //if (direction == ble_BleDirection_SLAVE_TO_MASTER)
                        if (1)
                        {
                            /* Send PDU. */
                            res = send_pdu(
                                _pdu,
                                length,
                                ((flags & RX_QUEUE_FLAG_ENCRYPTED) != 0) /* If encrypted flag set, enable encryption. */
                            );
                            //esp_rom_printf("[txprog] sent pdu (%d)\n", res);
                        }
                    }
                    break;

                    case IDLE:
                    case OBSERVER:
                    case BROADCASTER:
                    break;

                }
            }
            else
            {
                esp_rom_printf("[main::process pdus] cannot extract message from queue: %d\n", ret);
                //break;
            }
        }
    }
}

int IRAM_ATTR ble_rx_ctl_handler(int packet_num, uint16_t header, uint8_t *p_pdu, int length)
{
    uint8_t flags = 0;
    bool b_decrypted = false;
    uint8_t *p_payload = NULL;
    int ret;

    switch (g_adapter.state)
    {
        case PERIPHERAL:
        {
            /* If encryption is enabled, decrypt incoming PDU. */
            if (g_adapter.b_encrypted)
            {
                /* Decrypt PDU. */
                ret = decrypt_pdu(
                    header,
                    p_pdu,
                    length,
                    (g_adapter.state == PERIPHERAL)
                );

                /* Check if decryption was successful */
                if (ret == 0)
                {
                    esp_rom_printf(".");
                    //esp_rom_printf("[rx ctl] decryption OK\n");

                    /* Decryption in-place OK, push decrypted packet. */
                    flags |= RX_QUEUE_FLAG_DECRYPTED;

                    length -= 4;                    
                    set_packet_length(packet_num, length);
                }
                else
                {
                    esp_rom_printf("header: 0x%04x\n", header);
                    esp_rom_printf("[crypto] packet decryption failed\n");
                    //debug_fifos();
                    return HOOK_BLOCK;
                }
            }

            #if 0
            /* Convert pdu to hex. */
            for (int i=0; i<length; i++)
                snprintf(&dbg[2*i], 3, "%02x", p_pdu[i]);

            esp_rom_printf("Header: 0x%02x 0x%02x\n", header&0xff, (header&0xff00)>>8);
            esp_rom_printf("Clear. PDU: %s\n", dbg);
            #endif

            /* Only hook control PDUs that are not required by NimBLE. */
            if (
                (p_pdu[0] == 0x03) || // ENC_REQ
                (p_pdu[0] == 0x04) || // ENC_RSP
                (p_pdu[0] == 0x05) || // START_ENC_REQ
                (p_pdu[0] == 0x06) || // START_ENC_RSP
                (p_pdu[0] == 0x07) || // UNKNOWN_RSP
                (p_pdu[0] == 0x0A) || // LL_PAUSE_ENC_REQ
                (p_pdu[0] == 0x0B) || // LL_PAUSE_ENC_RSP
                (p_pdu[0] == 0x0C) || // LL_VERSION_IND
                (p_pdu[0] == 0x0D) || // LL_REJECT_IND
                //(p_pdu[0] == 0x0F) || // LL_CONNECTION_UPDATE_REQ
                (p_pdu[0] == 0x12) || // LL_PING_REQ
                (p_pdu[0] == 0x13) || // LL_PING_RSP
                (p_pdu[0] == 0x14) || // LENGTH_REQ
                (p_pdu[0] == 0x15)    // LENGTH_RSP
            )
            {
                if (b_decrypted)
                    flags |= RX_QUEUE_FLAG_DECRYPTED;

                /* Save PDU into RX queue. */
                ret = packet_queue_append(
                    &g_adapter.rx_queue,
                    (g_adapter.state == CENTRAL)?ble_BleDirection_SLAVE_TO_MASTER:ble_BleDirection_MASTER_TO_SLAVE,
                    flags,
                    g_adapter.conn_handle,
                    header & 0xff,  /* LLID */
                    (header & 0xff00) >> 8, /* length */
                    p_pdu
                );


                if (ret != RX_QUEUE_SUCCESS)
                {
                    esp_rom_printf("[rx queue] cannot append pdu to queue: %d\n", ret);
                }

                /* Block message. */
                return HOOK_BLOCK;
            }
        }
        break;

        case CENTRAL:
        {

            /* If encryption is enabled, decrypt incoming PDU. */
            if (g_adapter.b_encrypted)
            {
                //dbg_txt("Encrypted CTL PDU received");

                /* Decrypt PDU in place. PDU comes from slave, not master. */
                if (decrypt_pdu(header, p_pdu, length, false) != 0)
                {
                    /* Error while decrypting, drop PDU. */
                    //dbg_txt("Error during PDU decryption, dropping PDU.");
                    return HOOK_BLOCK;
                }
                else
                {
                    /* Packet successfully decrypted. */
                    b_decrypted = true;

                    /* Remove MIC. */
                    length -= 4;

                    /* Update packet header. */
                    set_packet_length(packet_num, length);
                }
            }

            /* Only hook control PDUs that are not required by NimBLE. */
            if (
                (p_pdu[0] == 0x03) || // ENC_REQ
                (p_pdu[0] == 0x04) || // ENC_RSP
                (p_pdu[0] == 0x05) || // START_ENC_REQ
                (p_pdu[0] == 0x06) || // START_ENC_RSP
                (p_pdu[0] == 0x07) || // UNKNOWN_RSP
                (p_pdu[0] == 0x0A) || // LL_PAUSE_ENC_REQ
                (p_pdu[0] == 0x0B) || // LL_PAUSE_ENC_RSP
                (p_pdu[0] == 0x0C) || // LL_VERSION_IND
                (p_pdu[0] == 0x0D) || // LL_REJECT_IND
                (p_pdu[0] == 0x12) || // LL_PING_REQ
                (p_pdu[0] == 0x13) || // LL_PING_RSP
                (p_pdu[0] == 0x14) || // LENGTH_REQ
                (p_pdu[0] == 0x15)    // LENGTH_RSP
            )
            {
                if (b_decrypted)
                    flags |= RX_QUEUE_FLAG_DECRYPTED;

                /* Save PDU into RX queue. */
                ret = packet_queue_append(
                    &g_adapter.rx_queue,
                    (g_adapter.state == CENTRAL)?ble_BleDirection_SLAVE_TO_MASTER:ble_BleDirection_MASTER_TO_SLAVE,
                    flags,
                    g_adapter.conn_handle,
                    header & 0xff,  /* LLID */
                    (header & 0xff00) >> 8, /* length */
                    p_pdu
                );

                if (ret != RX_QUEUE_SUCCESS)
                {
                    esp_rom_printf("[rx queue] cannot append pdu to queue: %d\n", ret);
                }


                /* Block message. */
                return HOOK_BLOCK;
            }
        }
        break;

        default:
        break;
    }

    flags = RX_QUEUE_FLAG_PROCESSED;
    if (b_decrypted)
        flags |= RX_QUEUE_FLAG_DECRYPTED;

    /* Save PDU into RX queue. */
    ret = packet_queue_append(
        &g_adapter.rx_queue,
        (g_adapter.state == CENTRAL)?ble_BleDirection_SLAVE_TO_MASTER:ble_BleDirection_MASTER_TO_SLAVE,
        flags,
        g_adapter.conn_handle,
        header & 0xff,  /* LLID */
        (header & 0xff00) >> 8, /* length */
        p_pdu
    );

    if (ret != RX_QUEUE_SUCCESS)
    {
        esp_rom_printf("[rx queue] cannot append pdu to queue: %d", ret);
    }
    
    /* Forward by default. */
    return HOOK_FORWARD;
}

int IRAM_ATTR ble_rx_data_handler(int packet_num, uint16_t header, uint8_t *p_pdu, int length)
{
  /* Rebuild a data PDU and send it to the host. We don't need to forward this
  to the underlying BLE stack as it is not used in our case. */
  uint16_t *p_l2cap_channel, *p_l2cap_pkt_size;
  bool b_valid_pkt = false;
  bool b_decrypted = false;
  uint8_t flags = 0;
  int ret;


  if (
    (g_adapter.conn_state == CONNECTED) && 
    ( (g_adapter.state == CENTRAL) || (g_adapter.state == PERIPHERAL) )
  )
  {

    /* If encryption is enabled, decrypt incoming PDU. */
    if (g_adapter.b_encrypted)
    {
        //esp_rom_printf("Encrypted Data PDU received\n");

        /* Decrypt PDU in place. PDU comes from master. */
        if (decrypt_pdu(header, p_pdu, length, (g_adapter.state == PERIPHERAL)) != 0)
        {
            /* Error while decrypting, drop PDU. */
            esp_rom_printf("Packet decryption error\n");
            return HOOK_BLOCK;               
        }
        else
        {
            esp_rom_printf(".");

            /* Packet successfully decrypted. */
            b_decrypted = true;

            /* Remove MIC. */
            length -= 4;

            /* Update packet header. */
            set_packet_length(packet_num, length);
        }        
    }

    /** 
    * L2CAP layer tracking.
    * 
    * This feature has been implemented to avoid some noise packets
    * reported by r_lld_rx_pdu_handler().
    **/

    /* Valid BLE L2CAP packet is at least 6 bytes (2-byte BLE DATA header + 4-byte L2CAP header) */
    if (length >= 4)
    {
        p_l2cap_channel = &p_pdu[2];
        p_l2cap_pkt_size = &p_pdu[0];

        //dbg_txt_rom("[l2cap] pdu size %d, l2cap size: %d, channel: %d", length, *p_l2cap_pkt_size,*p_l2cap_channel);

        /* Do we have a DATA start fragment ? */
        if ((header & 0x03) == 0x02)
        {
            //dbg_txt_rom("[l2cap] start fragment received (state=%d)", g_adapter.b_l2cap_started);
            if (!g_adapter.b_l2cap_started)
            {
                /* Make sure L2CAP header has the correct channel (attribute or SMP). */
                if ((*p_l2cap_channel == 0x04) || (*p_l2cap_channel == 0x06))
                {
                    /* L2CAP start fragment received, save expected size. */
                    g_adapter.b_l2cap_started = true;
                    g_adapter.l2cap_pkt_size = *p_l2cap_pkt_size;
                    g_adapter.l2cap_recv_bytes = length - 4; /* information payload size */

                    if (g_adapter.l2cap_recv_bytes == g_adapter.l2cap_pkt_size)
                    {
                        /* Packet is complete. */
                        g_adapter.b_l2cap_started = false;
                        //dbg_txt_rom("[l2cap] received complete fragment");
                    }
                    else
                    {
                        //dbg_txt_rom("[l2cap] received start fragment");
                    }
                }

                /* Packet is valid. */
                b_valid_pkt = true;
            }
        }
        /* Do we have a DATA continue fragment ? */
        else if ((header & 0x03) == 0x01)
        {
            //dbg_txt_rom("[l2cap] continue fragment received (state=%d)", g_adapter.b_l2cap_started);
            /* Only accept this fragment after a start fragment has been received. */
            if (g_adapter.b_l2cap_started)
            {
                //dbg_txt_rom("[l2cap] received continue fragment");

                /* Do we have received a complete L2CAP packet ? */
                g_adapter.l2cap_recv_bytes += (length - 4); /* information payload size. */
                if (g_adapter.l2cap_recv_bytes >= g_adapter.l2cap_pkt_size)
                {
                    //dbg_txt_rom("[l2cap] packet is complete");

                    /* Yes, next packet shall be a start fragment. */
                    g_adapter.b_l2cap_started = false;
                    g_adapter.l2cap_pkt_size = 0;
                    g_adapter.l2cap_recv_bytes = 0;
                }
                else
                {
                    //dbg_txt_rom("[l2cap] packet continuation %d/%d", g_adapter.l2cap_recv_bytes, g_adapter.l2cap_pkt_size);
                }

                /* Packet is valid. */
                b_valid_pkt = true;
            }
        }

        if (b_valid_pkt)
        {
            if (b_decrypted)
                flags |= RX_QUEUE_FLAG_DECRYPTED;

            /* Save PDU into RX queue. */
            ret = packet_queue_append(
                &g_adapter.rx_queue,
                (g_adapter.state == CENTRAL)?ble_BleDirection_SLAVE_TO_MASTER:ble_BleDirection_MASTER_TO_SLAVE,
                flags,
                g_adapter.conn_handle,
                header & 0xff,  /* LLID */
                (header & 0xff00) >> 8, /* length */
                p_pdu
            );
            if (ret != RX_QUEUE_SUCCESS)
            {
                esp_rom_printf("[rx queue] cannot append pdu to queue: %d", ret);
            }

        }
    }
    return HOOK_BLOCK;
  }
  else
    return HOOK_FORWARD;
}

/* This handler SHALL NOT be called, as the underlying BLE stack is not supposed
to send data. */
int IRAM_ATTR ble_tx_data_handler(int packet_num, uint16_t header, uint8_t *p_pdu, int length)
{
  /* Rebuild a data PDU and send it to the host. We don't need to forward this
  to the underlying BLE stack as it is not used in our case. */
  if (g_adapter.conn_state == CONNECTED)
  {
    whad_ble_ll_data_pdu(
        &pdu_msg,
        header,
        p_pdu,
        length,
        (g_adapter.state == CENTRAL)?ble_BleDirection_MASTER_TO_SLAVE:ble_BleDirection_SLAVE_TO_MASTER,
        g_adapter.conn_handle,
        true,
        false
    );
    pending_pb_message(&pdu_msg); 
  }

  return HOOK_FORWARD;  
}

int IRAM_ATTR ble_tx_ctl_handler(llcp_opinfo *p_llcp_pdu)
{
  //dbg_txt_rom("[ble:tx:ctl] sent 0x%02x opcode", p_llcp_pdu->opcode);
  /* Rebuild a data PDU and send it to the host. We don't need to forward this
  to the underlying BLE stack as it is not used in our case. */
  
  /* 
   * Only let LL_FEATURE_RSP, LL_FEATURE_REQ, LL_CONNECTION_PARAM_REQ, 
   * LL_CONNECTION_PARAM_RSP, LL_PING_REQ, LL_PING_RSP, LL_LENGTH_REQ,
   * LL_LENGTH_RSP.
   */
  if ((p_llcp_pdu->opcode == 0x00) ||
      (p_llcp_pdu->opcode == 0x01) ||
      (p_llcp_pdu->opcode == 0x08) ||
      (p_llcp_pdu->opcode == 0x09) ||
      (p_llcp_pdu->opcode == 0x0C) ||
      (p_llcp_pdu->opcode == 0x0F) ||
      (p_llcp_pdu->opcode == 0x10) ||
      (p_llcp_pdu->opcode == 0x11) ||
      (p_llcp_pdu->opcode == 0x12) ||
      (p_llcp_pdu->opcode == 0x13) ||
      (p_llcp_pdu->opcode == 0x14) ||
      (p_llcp_pdu->opcode == 0x15)
  )
  {
    //dbg_txt_rom("(tx ctl) forward pdu %02x", p_llcp_pdu->opcode);
    //esp_rom_printf("esp sent ctl pdu: 0x%02x\n", p_llcp_pdu->opcode);
    return HOOK_FORWARD;
  }
  else
  {
    //dbg_txt_rom("(tx ctl) block pdu %02x", p_llcp_pdu->opcode);
    //esp_rom_printf("blocked ctl pdu: 0x%02x\n", p_llcp_pdu->opcode);
    return HOOK_BLOCK;
  }
}

void ble_advertise(void)
{
    int rc;
    struct ble_gap_adv_params adv_params;

    /* Figure out address to use for connect (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &g_adapter.my_addr_type);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "error determining address type; rc=%d\n", rc);
        return;
    }

    /* Update advertising and scan response data. */
    if (g_adapter.adv_data_length > 0)
    {
        ble_gap_adv_set_data(g_adapter.adv_data, g_adapter.adv_data_length);
    }

    if (g_adapter.adv_rsp_data_length > 0)
    {
        ble_gap_adv_rsp_set_data(g_adapter.adv_rsp_data, g_adapter.adv_rsp_data_length);
    }

    /* Set advertising parameters. */
    memset(&adv_params, 0, sizeof adv_params);
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND; /* Undirected */
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN; /* General discovery mode */
    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                           &adv_params, blecent_gap_event, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "error enabling advertisement; rc=%d\n", rc);
        return;
    }

    if (g_adapter.b_spoof_addr)
    {
        r_lld_util_set_bd_address(g_adapter.my_dev_addr, 0);
    }
}

void adapter_quit_state(adapter_state_t state)
{
    int res;
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
                    dbg_txt("adv stop");
                    /* Stop advertising. */
                    ble_gap_adv_stop();
                }
                else
                {
                    /* Terminate connection. */
                    //res = ble_gap_terminate(g_adapter.conn_handle, 0x13);
                    //dbg_txt("terminate connection: %d (%d)", res, g_adapter.conn_handle);
                    
                    /* Force disconnect. */
                    /*
                    send_raw_data_pdu(
                        g_adapter.conn_handle,
                        0x03,
                        "\x02\x13",
                        2,
                        true
                    );
                    */
                   send_terminate_ind();
                }

                /* Wait for the BLE stack to be disconnected. */
                memset(g_adapter.target_dev_addr, 0, 6);
                g_adapter.conn_state = DISCONNECTED;
                g_adapter.conn_handle = -1;
                g_adapter.b_encrypted = false; /* Do not encrypt anymore. */
            }
            break;

        case PERIPHERAL:
        case BROADCASTER:
            {
                /* Stop advertising. */
                ble_gap_adv_stop();
            }
            break;

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

        case PERIPHERAL:
        case BROADCASTER:
            {
                /* Start advertising. */
                ble_advertise();
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
        g_adapter.dev_name,
        0x0100,
        460800, /* Max speed on UART */
        FIRMWARE_AUTHOR,
        FIRMWARE_URL,
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

void adapter_on_notify_adv(uint8_t adv_type, int rssi, uint8_t addr_type, uint8_t *bd_addr, uint8_t *p_adv_data, int adv_data_length)
{
    Message notification;
    whad_adv_data_t adv_data;

    memset(&notification, 0, sizeof(Message));
    memcpy(adv_data.bd_addr, bd_addr, 6);
    adv_data.addr_type = addr_type;
    adv_data.p_adv_data = p_adv_data;
    adv_data.adv_data_length = adv_data_length;
    adv_data.rssi = rssi;
    adv_data.adv_type = adv_type;

    /* Build notification and send to host. */
    whad_ble_adv_pdu(&notification, &adv_data);
    send_pb_message(&notification);
}

void adapter_on_notify_connected(uint8_t our_addr_type, uint8_t *p_our_addr, uint8_t peer_addr_type, uint8_t *p_peer_addr)
{
    Message notification;

    whad_ble_notify_connected(
        &notification,
        our_addr_type,
        p_our_addr,
        peer_addr_type,
        p_peer_addr,
        g_adapter.conn_handle
    );
    send_pb_message(&notification);
}

void adapter_on_notify_disconnected(void)
{
    Message notification;

    whad_ble_notify_disconnected(&notification, g_adapter.conn_handle, 0);
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

void adapter_on_enable_adv(ble_AdvModeCmd *adv_mode)
{
    Message cmd_result;

    /* Update advertising data and scan response data if provided. */
    if ( (adv_mode->scan_data.size > 0) && (adv_mode->scan_data.size <= 31) )
    {
        g_adapter.adv_data_length = adv_mode->scan_data.size;
        memcpy(g_adapter.adv_data, adv_mode->scan_data.bytes, adv_mode->scan_data.size);
    }
    if ( (adv_mode->scanrsp_data.size > 0) && (adv_mode->scanrsp_data.size <= 31) )
    {
        g_adapter.adv_rsp_data_length = adv_mode->scanrsp_data.size;
        memcpy(g_adapter.adv_rsp_data, adv_mode->scanrsp_data.bytes, adv_mode->scanrsp_data.size);
    }

    /* Switch to advertising mode. */
    if (adapter_set_state(BROADCASTER))
    {
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
        send_pb_message(&cmd_result);
    }
    else
    {
        whad_init_error_message(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);        
    }
}

void adapter_on_enable_peripheral(ble_PeripheralModeCmd *periph_mode)
{
    Message cmd_result;

    /* Update advertising data and scan response data if provided. */
    if ( (periph_mode->scan_data.size > 0) && (periph_mode->scan_data.size <= 31) )
    {
        g_adapter.adv_data_length = periph_mode->scan_data.size;
        memcpy(g_adapter.adv_data, periph_mode->scan_data.bytes, periph_mode->scan_data.size);
    }
    if ( (periph_mode->scanrsp_data.size > 0) && (periph_mode->scanrsp_data.size <= 31) )
    {
        g_adapter.adv_rsp_data_length = periph_mode->scanrsp_data.size;
        memcpy(g_adapter.adv_rsp_data, periph_mode->scanrsp_data.bytes, periph_mode->scanrsp_data.size);
    }

    /* Switch to advertising mode. */
    if (adapter_set_state(PERIPHERAL))
    {
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

        /* Copy target address type. */
        g_adapter.target_dev_addr_type = connect->addr_type;

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

                /* Enabled. */
                g_adapter.b_enabled = true;

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
            /* Enabled. */
            g_adapter.b_enabled = false;

            /* Stop advertising if required. */
            if (ble_gap_adv_active())
            {
                /* Stop advertising. */
                ble_gap_adv_stop();

            }
            else if ((g_adapter.conn_handle >= 0) && (g_adapter.conn_state == CONNECTED))
            {
                /* Force disconnect. */
                /*
                send_raw_data_pdu(
                    g_adapter.conn_handle,
                    0x03,
                    "\x02\x13",
                    2,
                    true
                );*/
                send_terminate_ind();
            }

            /* Success. */
            whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
            send_pb_message(&cmd_result);
        }
        break;

        default:
            break;
    }

    /* Error. */
    whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
    send_pb_message(&cmd_result);
}

void adapter_on_disconnect(ble_DisconnectCmd *disconnect)
{
    Message cmd_result;

    switch (g_adapter.state)
    {
        case PERIPHERAL:
        case CENTRAL:
        {
            if (g_adapter.conn_state == CONNECTED)
            {
                /* Force disconnect. */
                /*
                send_raw_data_pdu(
                    g_adapter.conn_handle,
                    0x03,
                    "\x02\x13",
                    2,
                    true
                );*/
                send_terminate_ind();
                
                /* Success. */
                whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
                send_pb_message(&cmd_result);
            }
            else
            {
                whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
                send_pb_message(&cmd_result);                
            }
        }
        break;

        /* Cannot disconnect if not connected and in CENTRAL or PERIPHERAL mode. */
        default:
        {
            whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
            send_pb_message(&cmd_result);  
        }
        break;
    }
}

void adapter_on_send_pdu(ble_SendPDUCmd *send_pdu_cmd)
{
    Message cmd_result;
    struct ble_hs_conn *conn;
    uint16_t *pkt_count;
    uint8_t *p_pkt = NULL;
    int res,ret;
    int length;

    if (
        ((g_adapter.state == CENTRAL) || (g_adapter.state == PERIPHERAL)) &&
        (g_adapter.conn_state == CONNECTED)
    )
    {

        #if 0
        if (send_pdu(
            send_pdu_cmd->pdu.bytes,
            send_pdu_cmd->pdu.size,
            send_pdu_cmd->encrypt
        )) {
            //printf("send_pdu: success\n");
            /* Success ! */
            whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
            send_pb_message(&cmd_result);
        }
        else
        {
            //printf("send_pdu: error\n");
            /* Error. */
            whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
            send_pb_message(&cmd_result);   
        }
        #endif
        portDISABLE_INTERRUPTS();
        ret = packet_queue_append(
            &g_adapter.tx_queue,
            send_pdu_cmd->direction,
            send_pdu_cmd->encrypt?RX_QUEUE_FLAG_ENCRYPTED:0,
            send_pdu_cmd->conn_handle,
            send_pdu_cmd->pdu.bytes[0],
            send_pdu_cmd->pdu.size - 2,
            &send_pdu_cmd->pdu.bytes[2]
        );
        portENABLE_INTERRUPTS();

        //printf("[adapter] enqueue %d bytes into tx queue (%d bytes now)\n", send_pdu_cmd->pdu.size, g_adapter.tx_queue.size);

        if (ret == RX_QUEUE_SUCCESS)
        {
            /* Success ! */
            whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
            send_pb_message(&cmd_result);
        }
        else
        {
            /* Error. */
            whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
            send_pb_message(&cmd_result);   
        }
    }
    else
    {
        //dbg_txt_rom("[pdu] cannot send pdu (state:%d, conn_state:%d)",g_adapter.state,g_adapter.conn_state );
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);   
    }
}


void adapter_on_set_bd_addr(ble_SetBdAddressCmd *bd_addr)
{
    Message cmd_result;

    /* Ask for a random address from NimBLE, if we need a random one. */
    if (bd_addr->addr_type == ble_BleAddrType_RANDOM)
    {
        ble_hs_id_set_rnd(bd_addr->bd_address);
    }

    /* Save our spoofed address. */
    memcpy(g_adapter.my_dev_addr, bd_addr->bd_address, 6);
    g_adapter.b_spoof_addr = true;

    /* Success ! */
    whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
    send_pb_message(&cmd_result);
}

void adapter_on_reset(void)
{
    Message cmd_result;

    /* Soft reset ! */
    esp_restart();
}

void adapter_on_set_speed(discovery_SetTransportSpeed *speed)
{
    Message cmd_result;
    
    if (speed->speed <= 460800)
    {
        /* Send success message. */
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
        send_pb_message(&cmd_result);

        vTaskDelay(200 / portTICK_PERIOD_MS);

        /* Reconfigure UART0 */
        reconfigure_uart(speed->speed, false);
    }
    else
    {
        /* Send error message. */
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);   
    }
}

void adapter_on_encryption_changed(ble_SetEncryptionCmd *encryption)
{
    Message cmd_result;
    int res=0,ret;
    
    /* Initialize crypto. */
    if (encryption->enabled)
    {
        /* Copy  128-bit Key and IV. */
        memcpy(g_adapter.enc_key, encryption->key, 16);
        memcpy(g_adapter.enc_iv, encryption->iv, 16);

        /* Reset master and slave counters. */
        g_adapter.enc_master_counter = 0;
        g_adapter.enc_slave_counter = 0;

        /* Initialize context. */
        mbedtls_ccm_init(&g_adapter.enc_context);

        /* Set AES key */
        mbedtls_ccm_setkey(&g_adapter.enc_context, MBEDTLS_CIPHER_ID_AES, g_adapter.enc_key, 128);

        /* Set encryption status accordingly. */
        g_adapter.b_encrypted = encryption->enabled;
    }
    else
    {
        /* Disable encryption. */
        g_adapter.b_encrypted = false;
    }

    /* Return message based on initialization result. */
    if (!res)
    {
        dbg_txt("Link-layer crypto OK: %d", g_adapter.b_encrypted);

        /* Send success message. */
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_SUCCESS);
        send_pb_message(&cmd_result);
    }
    else
    {
        dbg_txt("Error: cannot enable encryption");

        /* Send error message. */
        whad_generic_cmd_result(&cmd_result, generic_ResultCode_ERROR);
        send_pb_message(&cmd_result);           
    }

    /* Disable encryption in BLE controller. */
    //printf("[adapter] RWBLECNTL=0x%08x\n", ble_read_rwblecntl());
    ble_disable_crypto();
    //printf("[adapter] RWBLECNTL=0x%08x\n", ble_read_rwblecntl());
}

int adapter_rxqueue_size(void)
{
    return g_adapter.rx_queue.size;
}

int adapter_rxqueue_get(
    uint8_t *p_direction,
    uint8_t *p_flags,
    uint16_t *p_conn_handle,
    uint8_t *p_llid,
    uint8_t *p_length,
    uint8_t *p_pdu
)
{
    return packet_queue_pop(
        &g_adapter.rx_queue,
        p_direction,
        p_flags,
        p_conn_handle,
        p_llid,
        p_length,
        p_pdu
    );
}

int adapter_txqueue_size(void)
{
    return g_adapter.tx_queue.size;
}

int adapter_txqueue_append(
    packet_queue_t *queue,
    uint8_t direction,
    uint8_t flags,
    uint16_t conn_handle,
    uint8_t llid,
    uint8_t length,
    uint8_t *p_pdu
)
{
    return packet_queue_append(
        &g_adapter.tx_queue,
        direction,
        flags,
        conn_handle,
        llid,
        length,
        p_pdu

    );
}