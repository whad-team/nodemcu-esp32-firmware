/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.7-dev */

#ifndef PB_BLE_PROTOCOL_BLE_BLE_PB_H_INCLUDED
#define PB_BLE_PROTOCOL_BLE_BLE_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Enum definitions */
typedef enum _ble_BleCommand { /* *
 Low-level commands */
    /* Set BD address. */
    ble_BleCommand_SetBdAddress = 0, 
    /* Sniff advertisements. */
    ble_BleCommand_SniffAdv = 1, 
    /* Jam advertisements. */
    ble_BleCommand_JamAdv = 2, 
    /* Jam advertisements on a single channel. */
    ble_BleCommand_JamAdvOnChannel = 3, 
    /* Sniff CONN_REQ PDUs and sync with connection. */
    ble_BleCommand_SniffConnReq = 4, 
    /* Sniff active connection. */
    ble_BleCommand_SniffAccessAddress = 5, 
    ble_BleCommand_SniffActiveConn = 6, 
    /* Connection jamming. */
    ble_BleCommand_JamConn = 7, 
    /* Scanner mode. */
    ble_BleCommand_ScanMode = 8, 
    /* Advertiser mode. */
    ble_BleCommand_AdvMode = 9, 
    ble_BleCommand_SetAdvData = 10, /* SetAdvData shared with Peripheral mode. */
    /* Central mode. */
    ble_BleCommand_CentralMode = 11, 
    ble_BleCommand_ConnectTo = 12, 
    ble_BleCommand_SendRawPDU = 13, 
    ble_BleCommand_SendPDU = 14, 
    ble_BleCommand_Disconnect = 15, 
    /* Peripheral mode. */
    ble_BleCommand_PeripheralMode = 16, /* SetAdvData and SetScanRspData are shared accross
 Peripheral and Advertiser modes
 SendPDU is shared with Central mode
 Disconnect is shared with Central mode */
    /* Common to multiple modes. */
    ble_BleCommand_Start = 17, 
    ble_BleCommand_Stop = 18, 
    /* Hijack mode. */
    ble_BleCommand_HijackMaster = 19, 
    ble_BleCommand_HijackSlave = 20, 
    ble_BleCommand_HijackBoth = 21 
} ble_BleCommand;

typedef enum _ble_BleAdvType { 
    ble_BleAdvType_ADV_UNKNOWN = 0, 
    ble_BleAdvType_ADV_IND = 1, 
    ble_BleAdvType_ADV_DIRECT_IND = 2, 
    ble_BleAdvType_ADV_NONCONN_IND = 3, 
    ble_BleAdvType_ADV_SCAN_IND = 4, 
    ble_BleAdvType_ADV_SCAN_RSP = 5 
} ble_BleAdvType;

typedef enum _ble_BleDirection { 
    ble_BleDirection_UNKNOWN = 0, 
    ble_BleDirection_MASTER_TO_SLAVE = 1, 
    ble_BleDirection_SLAVE_TO_MASTER = 2, 
    ble_BleDirection_INJECTION_TO_SLAVE = 3, 
    ble_BleDirection_INJECTION_TO_MASTER = 4 
} ble_BleDirection;

/* Struct definitions */
/* *
 CentralModeCmd

 Enable central mode. */
typedef struct _ble_CentralModeCmd { 
    char dummy_field;
} ble_CentralModeCmd;

typedef struct _ble_JamAdvCmd { 
    char dummy_field;
} ble_JamAdvCmd;

typedef struct _ble_SetAdvDataCmd { 
    pb_callback_t scan_data;
    pb_callback_t scanrsp_data;
} ble_SetAdvDataCmd;

/* *
 SniffAccessAddressCmd

 Sniff Access Addresses sent over BLE.

 Will send AccessAddressDiscovered notifications each
 time an AccessAddress has been found. */
typedef struct _ble_SniffAccessAddressCmd { 
    char dummy_field;
} ble_SniffAccessAddressCmd;

/* *
 StartCmd

 Enable peripheral advertising and accept connections. */
typedef struct _ble_StartCmd { 
    char dummy_field;
} ble_StartCmd;

/* *
 StopCmd

 Terminate active connection and stop peripheral. */
typedef struct _ble_StopCmd { 
    char dummy_field;
} ble_StopCmd;

typedef struct _ble_AccessAddressDiscovered { 
    uint32_t access_address;
    bool has_rssi;
    int32_t rssi;
    bool has_timestamp;
    uint32_t timestamp;
} ble_AccessAddressDiscovered;

typedef PB_BYTES_ARRAY_T(31) ble_AdvModeCmd_scan_data_t;
typedef PB_BYTES_ARRAY_T(31) ble_AdvModeCmd_scanrsp_data_t;
typedef struct _ble_AdvModeCmd { 
    ble_AdvModeCmd_scan_data_t scan_data;
    ble_AdvModeCmd_scanrsp_data_t scanrsp_data;
} ble_AdvModeCmd;

typedef PB_BYTES_ARRAY_T(31) ble_AdvPduReceived_adv_data_t;
typedef struct _ble_AdvPduReceived { 
    ble_BleAdvType adv_type;
    int32_t rssi;
    pb_byte_t bd_address[6];
    ble_AdvPduReceived_adv_data_t adv_data;
} ble_AdvPduReceived;

/* *
 ConnectToCmd

 Connect to a specific target device. */
typedef struct _ble_ConnectToCmd { 
    pb_byte_t bd_address[6];
} ble_ConnectToCmd;

typedef struct _ble_Connected { 
    pb_byte_t initiator[6];
    pb_byte_t advertiser[6];
    uint32_t access_address;
    /* uint32 crc_init = 4;
uint32 hop_interval = 5;
uint32 hop_increment = 6;
bytes channel_map = 7; */
    uint32_t conn_handle;
} ble_Connected;

/* *
 Desynchronized */
typedef struct _ble_Desynchronized { 
    uint32_t access_address;
} ble_Desynchronized;

typedef struct _ble_DisconnectCmd { 
    int32_t conn_handle;
} ble_DisconnectCmd;

/* *
 Disconnected */
typedef struct _ble_Disconnected { 
    uint32_t reason;
    uint32_t conn_handle;
} ble_Disconnected;

/* *
 HijackBothCmd

 Initiate an existing connection hijacking, targeting
 both devices (establish a Man-in-the-Middle in an existing connection).

 `access_address` specifies the target Access Address
    of the connection to hijack. */
typedef struct _ble_HijackBothCmd { 
    uint32_t access_address;
} ble_HijackBothCmd;

typedef struct _ble_HijackMasterCmd { 
    uint32_t access_address;
} ble_HijackMasterCmd;

/* *
 HijackSlaveCmd

 Initiate an existing connection hijacking, targeting
 its slave device.

 `access_address` specifies the target Access Address
    of the connection to hijack. */
typedef struct _ble_HijackSlaveCmd { 
    uint32_t access_address;
} ble_HijackSlaveCmd;

typedef struct _ble_Hijacked { 
    bool success;
    uint32_t access_address;
} ble_Hijacked;

/* *
 Injected */
typedef struct _ble_Injected { 
    bool success;
    uint32_t access_address;
    uint32_t injection_attempts;
} ble_Injected;

typedef struct _ble_JamAdvOnChannelCmd { 
    uint32_t channel;
} ble_JamAdvOnChannelCmd;

typedef struct _ble_JamConnCmd { 
    uint32_t access_address;
} ble_JamConnCmd;

typedef PB_BYTES_ARRAY_T(300) ble_PduReceived_pdu_t;
typedef struct _ble_PduReceived { 
    ble_BleDirection direction;
    ble_PduReceived_pdu_t pdu;
    uint32_t conn_handle;
    bool processed;
} ble_PduReceived;

typedef PB_BYTES_ARRAY_T(31) ble_PeripheralModeCmd_scan_data_t;
typedef PB_BYTES_ARRAY_T(31) ble_PeripheralModeCmd_scanrsp_data_t;
/* *
 PeripheralModeCmd

 Enable peripheral mode. */
typedef struct _ble_PeripheralModeCmd { 
    ble_PeripheralModeCmd_scan_data_t scan_data;
    ble_PeripheralModeCmd_scanrsp_data_t scanrsp_data;
} ble_PeripheralModeCmd;

typedef PB_BYTES_ARRAY_T(255) ble_RawPduReceived_pdu_t;
typedef struct _ble_RawPduReceived { 
    ble_BleDirection direction;
    uint32_t channel;
    bool has_rssi;
    int32_t rssi;
    bool has_timestamp;
    uint32_t timestamp;
    bool has_relative_timestamp;
    uint32_t relative_timestamp;
    bool has_crc_validity;
    bool crc_validity;
    uint32_t access_address;
    ble_RawPduReceived_pdu_t pdu;
    uint32_t crc;
    uint32_t conn_handle;
    bool processed;
} ble_RawPduReceived;

typedef struct _ble_ScanModeCmd { 
    bool active_scan;
} ble_ScanModeCmd;

typedef PB_BYTES_ARRAY_T(300) ble_SendPDUCmd_pdu_t;
/* *
 SendPDUCmd

 Sends a raw PDU
 If no direction is provided, the following rules are applied:
 - send to peripheral if in central mode
 - send to central if in peripheral mode
 - inject into the synchronized connection if in sniffer mode
 If a direction is provided, use the direction.

 If device is able to send raw packets, `access_address` and
 `crc` can be provided. */
typedef struct _ble_SendPDUCmd { 
    ble_BleDirection direction;
    uint32_t conn_handle;
    ble_SendPDUCmd_pdu_t pdu;
} ble_SendPDUCmd;

typedef PB_BYTES_ARRAY_T(300) ble_SendRawPDUCmd_pdu_t;
/* *
 SendRawPDUCmd

 Sends a raw PDU (to peripheral if in central mode, to central
 if in peripheral mode).

 If device is able to send raw packets, `access_address` and
 `crc` can be provided. */
typedef struct _ble_SendRawPDUCmd { 
    ble_BleDirection direction;
    uint32_t conn_handle;
    uint32_t access_address;
    ble_SendRawPDUCmd_pdu_t pdu;
    uint32_t crc;
} ble_SendRawPDUCmd;

typedef struct _ble_SetBdAddressCmd { 
    pb_byte_t bd_address[6];
} ble_SetBdAddressCmd;

typedef struct _ble_SniffActiveConnCmd { 
    uint32_t access_address;
} ble_SniffActiveConnCmd;

typedef struct _ble_SniffAdvCmd { 
    /* Extended advertisements (BLE 5). */
    bool use_extended_adv;
    /* Channel can be specified, the device will only
listen on this specific channel. */
    uint32_t channel;
    pb_byte_t bd_address[6];
} ble_SniffAdvCmd;

typedef struct _ble_SniffConnReqCmd { 
    bool show_empty_packets;
    bool show_advertisements;
    uint32_t channel;
    pb_byte_t bd_address[6];
} ble_SniffConnReqCmd;

typedef struct _ble_Synchronized { 
    uint32_t access_address;
    uint32_t crc_init;
    uint32_t hop_interval;
    uint32_t hop_increment;
    pb_byte_t channel_map[5];
} ble_Synchronized;

typedef struct _ble_Message { 
    pb_size_t which_msg;
    union {
        /* Messages */
        ble_SetBdAddressCmd set_bd_addr;
        ble_SniffAdvCmd sniff_adv;
        ble_JamAdvCmd jam_adv;
        ble_JamAdvOnChannelCmd jam_adv_chan;
        ble_SniffConnReqCmd sniff_connreq;
        ble_SniffAccessAddressCmd sniff_aa;
        ble_SniffActiveConnCmd sniff_conn;
        ble_JamConnCmd jam_conn;
        ble_ScanModeCmd scan_mode;
        ble_AdvModeCmd adv_mode;
        ble_SetAdvDataCmd set_adv_data;
        ble_CentralModeCmd central_mode;
        ble_ConnectToCmd connect;
        ble_SendRawPDUCmd send_raw_pdu;
        ble_SendPDUCmd send_pdu;
        ble_DisconnectCmd disconnect;
        ble_PeripheralModeCmd periph_mode;
        ble_StartCmd start;
        ble_StopCmd stop;
        ble_HijackMasterCmd hijack_master;
        ble_HijackSlaveCmd hijack_slave;
        ble_HijackBothCmd hijack_both;
        /* Notifications */
        ble_AccessAddressDiscovered aa_disc;
        ble_AdvPduReceived adv_pdu;
        ble_Connected connected;
        ble_Disconnected disconnected;
        ble_Synchronized synchronized;
        ble_Hijacked hijacked;
        ble_PduReceived pdu;
        ble_RawPduReceived raw_pdu;
        ble_Injected injected;
        ble_Desynchronized desynchronized;
    } msg;
} ble_Message;


/* Helper constants for enums */
#define _ble_BleCommand_MIN ble_BleCommand_SetBdAddress
#define _ble_BleCommand_MAX ble_BleCommand_HijackBoth
#define _ble_BleCommand_ARRAYSIZE ((ble_BleCommand)(ble_BleCommand_HijackBoth+1))

#define _ble_BleAdvType_MIN ble_BleAdvType_ADV_UNKNOWN
#define _ble_BleAdvType_MAX ble_BleAdvType_ADV_SCAN_RSP
#define _ble_BleAdvType_ARRAYSIZE ((ble_BleAdvType)(ble_BleAdvType_ADV_SCAN_RSP+1))

#define _ble_BleDirection_MIN ble_BleDirection_UNKNOWN
#define _ble_BleDirection_MAX ble_BleDirection_INJECTION_TO_MASTER
#define _ble_BleDirection_ARRAYSIZE ((ble_BleDirection)(ble_BleDirection_INJECTION_TO_MASTER+1))


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define ble_SetBdAddressCmd_init_default         {{0}}
#define ble_SniffAdvCmd_init_default             {0, 0, {0}}
#define ble_JamAdvCmd_init_default               {0}
#define ble_JamAdvOnChannelCmd_init_default      {0}
#define ble_SniffConnReqCmd_init_default         {0, 0, 0, {0}}
#define ble_SniffAccessAddressCmd_init_default   {0}
#define ble_SniffActiveConnCmd_init_default      {0}
#define ble_JamConnCmd_init_default              {0}
#define ble_ScanModeCmd_init_default             {0}
#define ble_AdvModeCmd_init_default              {{0, {0}}, {0, {0}}}
#define ble_SetAdvDataCmd_init_default           {{{NULL}, NULL}, {{NULL}, NULL}}
#define ble_CentralModeCmd_init_default          {0}
#define ble_ConnectToCmd_init_default            {{0}}
#define ble_SendRawPDUCmd_init_default           {_ble_BleDirection_MIN, 0, 0, {0, {0}}, 0}
#define ble_SendPDUCmd_init_default              {_ble_BleDirection_MIN, 0, {0, {0}}}
#define ble_DisconnectCmd_init_default           {0}
#define ble_PeripheralModeCmd_init_default       {{0, {0}}, {0, {0}}}
#define ble_StartCmd_init_default                {0}
#define ble_StopCmd_init_default                 {0}
#define ble_HijackMasterCmd_init_default         {0}
#define ble_HijackSlaveCmd_init_default          {0}
#define ble_HijackBothCmd_init_default           {0}
#define ble_AccessAddressDiscovered_init_default {0, false, 0, false, 0}
#define ble_AdvPduReceived_init_default          {_ble_BleAdvType_MIN, 0, {0}, {0, {0}}}
#define ble_Connected_init_default               {{0}, {0}, 0, 0}
#define ble_Disconnected_init_default            {0, 0}
#define ble_Synchronized_init_default            {0, 0, 0, 0, {0}}
#define ble_Desynchronized_init_default          {0}
#define ble_Hijacked_init_default                {0, 0}
#define ble_Injected_init_default                {0, 0, 0}
#define ble_RawPduReceived_init_default          {_ble_BleDirection_MIN, 0, false, 0, false, 0, false, 0, false, 0, 0, {0, {0}}, 0, 0, 0}
#define ble_PduReceived_init_default             {_ble_BleDirection_MIN, {0, {0}}, 0, 0}
#define ble_Message_init_default                 {0, {ble_SetBdAddressCmd_init_default}}
#define ble_SetBdAddressCmd_init_zero            {{0}}
#define ble_SniffAdvCmd_init_zero                {0, 0, {0}}
#define ble_JamAdvCmd_init_zero                  {0}
#define ble_JamAdvOnChannelCmd_init_zero         {0}
#define ble_SniffConnReqCmd_init_zero            {0, 0, 0, {0}}
#define ble_SniffAccessAddressCmd_init_zero      {0}
#define ble_SniffActiveConnCmd_init_zero         {0}
#define ble_JamConnCmd_init_zero                 {0}
#define ble_ScanModeCmd_init_zero                {0}
#define ble_AdvModeCmd_init_zero                 {{0, {0}}, {0, {0}}}
#define ble_SetAdvDataCmd_init_zero              {{{NULL}, NULL}, {{NULL}, NULL}}
#define ble_CentralModeCmd_init_zero             {0}
#define ble_ConnectToCmd_init_zero               {{0}}
#define ble_SendRawPDUCmd_init_zero              {_ble_BleDirection_MIN, 0, 0, {0, {0}}, 0}
#define ble_SendPDUCmd_init_zero                 {_ble_BleDirection_MIN, 0, {0, {0}}}
#define ble_DisconnectCmd_init_zero              {0}
#define ble_PeripheralModeCmd_init_zero          {{0, {0}}, {0, {0}}}
#define ble_StartCmd_init_zero                   {0}
#define ble_StopCmd_init_zero                    {0}
#define ble_HijackMasterCmd_init_zero            {0}
#define ble_HijackSlaveCmd_init_zero             {0}
#define ble_HijackBothCmd_init_zero              {0}
#define ble_AccessAddressDiscovered_init_zero    {0, false, 0, false, 0}
#define ble_AdvPduReceived_init_zero             {_ble_BleAdvType_MIN, 0, {0}, {0, {0}}}
#define ble_Connected_init_zero                  {{0}, {0}, 0, 0}
#define ble_Disconnected_init_zero               {0, 0}
#define ble_Synchronized_init_zero               {0, 0, 0, 0, {0}}
#define ble_Desynchronized_init_zero             {0}
#define ble_Hijacked_init_zero                   {0, 0}
#define ble_Injected_init_zero                   {0, 0, 0}
#define ble_RawPduReceived_init_zero             {_ble_BleDirection_MIN, 0, false, 0, false, 0, false, 0, false, 0, 0, {0, {0}}, 0, 0, 0}
#define ble_PduReceived_init_zero                {_ble_BleDirection_MIN, {0, {0}}, 0, 0}
#define ble_Message_init_zero                    {0, {ble_SetBdAddressCmd_init_zero}}

/* Field tags (for use in manual encoding/decoding) */
#define ble_SetAdvDataCmd_scan_data_tag          1
#define ble_SetAdvDataCmd_scanrsp_data_tag       2
#define ble_AccessAddressDiscovered_access_address_tag 1
#define ble_AccessAddressDiscovered_rssi_tag     2
#define ble_AccessAddressDiscovered_timestamp_tag 3
#define ble_AdvModeCmd_scan_data_tag             1
#define ble_AdvModeCmd_scanrsp_data_tag          2
#define ble_AdvPduReceived_adv_type_tag          1
#define ble_AdvPduReceived_rssi_tag              2
#define ble_AdvPduReceived_bd_address_tag        3
#define ble_AdvPduReceived_adv_data_tag          4
#define ble_ConnectToCmd_bd_address_tag          1
#define ble_Connected_initiator_tag              1
#define ble_Connected_advertiser_tag             2
#define ble_Connected_access_address_tag         3
#define ble_Connected_conn_handle_tag            8
#define ble_Desynchronized_access_address_tag    1
#define ble_DisconnectCmd_conn_handle_tag        1
#define ble_Disconnected_reason_tag              1
#define ble_Disconnected_conn_handle_tag         2
#define ble_HijackBothCmd_access_address_tag     1
#define ble_HijackMasterCmd_access_address_tag   1
#define ble_HijackSlaveCmd_access_address_tag    1
#define ble_Hijacked_success_tag                 1
#define ble_Hijacked_access_address_tag          2
#define ble_Injected_success_tag                 1
#define ble_Injected_access_address_tag          2
#define ble_Injected_injection_attempts_tag      3
#define ble_JamAdvOnChannelCmd_channel_tag       1
#define ble_JamConnCmd_access_address_tag        1
#define ble_PduReceived_direction_tag            1
#define ble_PduReceived_pdu_tag                  2
#define ble_PduReceived_conn_handle_tag          3
#define ble_PduReceived_processed_tag            4
#define ble_PeripheralModeCmd_scan_data_tag      1
#define ble_PeripheralModeCmd_scanrsp_data_tag   2
#define ble_RawPduReceived_direction_tag         1
#define ble_RawPduReceived_channel_tag           2
#define ble_RawPduReceived_rssi_tag              3
#define ble_RawPduReceived_timestamp_tag         4
#define ble_RawPduReceived_relative_timestamp_tag 5
#define ble_RawPduReceived_crc_validity_tag      6
#define ble_RawPduReceived_access_address_tag    7
#define ble_RawPduReceived_pdu_tag               8
#define ble_RawPduReceived_crc_tag               9
#define ble_RawPduReceived_conn_handle_tag       10
#define ble_RawPduReceived_processed_tag         11
#define ble_ScanModeCmd_active_scan_tag          1
#define ble_SendPDUCmd_direction_tag             1
#define ble_SendPDUCmd_conn_handle_tag           2
#define ble_SendPDUCmd_pdu_tag                   3
#define ble_SendRawPDUCmd_direction_tag          1
#define ble_SendRawPDUCmd_conn_handle_tag        2
#define ble_SendRawPDUCmd_access_address_tag     3
#define ble_SendRawPDUCmd_pdu_tag                4
#define ble_SendRawPDUCmd_crc_tag                5
#define ble_SetBdAddressCmd_bd_address_tag       1
#define ble_SniffActiveConnCmd_access_address_tag 1
#define ble_SniffAdvCmd_use_extended_adv_tag     1
#define ble_SniffAdvCmd_channel_tag              2
#define ble_SniffAdvCmd_bd_address_tag           3
#define ble_SniffConnReqCmd_show_empty_packets_tag 1
#define ble_SniffConnReqCmd_show_advertisements_tag 2
#define ble_SniffConnReqCmd_channel_tag          3
#define ble_SniffConnReqCmd_bd_address_tag       4
#define ble_Synchronized_access_address_tag      1
#define ble_Synchronized_crc_init_tag            2
#define ble_Synchronized_hop_interval_tag        3
#define ble_Synchronized_hop_increment_tag       4
#define ble_Synchronized_channel_map_tag         5
#define ble_Message_set_bd_addr_tag              1
#define ble_Message_sniff_adv_tag                2
#define ble_Message_jam_adv_tag                  3
#define ble_Message_jam_adv_chan_tag             4
#define ble_Message_sniff_connreq_tag            5
#define ble_Message_sniff_aa_tag                 6
#define ble_Message_sniff_conn_tag               7
#define ble_Message_jam_conn_tag                 8
#define ble_Message_scan_mode_tag                9
#define ble_Message_adv_mode_tag                 10
#define ble_Message_set_adv_data_tag             11
#define ble_Message_central_mode_tag             12
#define ble_Message_connect_tag                  13
#define ble_Message_send_raw_pdu_tag             14
#define ble_Message_send_pdu_tag                 15
#define ble_Message_disconnect_tag               16
#define ble_Message_periph_mode_tag              17
#define ble_Message_start_tag                    18
#define ble_Message_stop_tag                     19
#define ble_Message_hijack_master_tag            20
#define ble_Message_hijack_slave_tag             21
#define ble_Message_hijack_both_tag              22
#define ble_Message_aa_disc_tag                  23
#define ble_Message_adv_pdu_tag                  24
#define ble_Message_connected_tag                25
#define ble_Message_disconnected_tag             26
#define ble_Message_synchronized_tag             27
#define ble_Message_hijacked_tag                 28
#define ble_Message_pdu_tag                      29
#define ble_Message_raw_pdu_tag                  30
#define ble_Message_injected_tag                 31
#define ble_Message_desynchronized_tag           32

/* Struct field encoding specification for nanopb */
#define ble_SetBdAddressCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, bd_address,        1)
#define ble_SetBdAddressCmd_CALLBACK NULL
#define ble_SetBdAddressCmd_DEFAULT NULL

#define ble_SniffAdvCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BOOL,     use_extended_adv,   1) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           2) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, bd_address,        3)
#define ble_SniffAdvCmd_CALLBACK NULL
#define ble_SniffAdvCmd_DEFAULT NULL

#define ble_JamAdvCmd_FIELDLIST(X, a) \

#define ble_JamAdvCmd_CALLBACK NULL
#define ble_JamAdvCmd_DEFAULT NULL

#define ble_JamAdvOnChannelCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1)
#define ble_JamAdvOnChannelCmd_CALLBACK NULL
#define ble_JamAdvOnChannelCmd_DEFAULT NULL

#define ble_SniffConnReqCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BOOL,     show_empty_packets,   1) \
X(a, STATIC,   SINGULAR, BOOL,     show_advertisements,   2) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           3) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, bd_address,        4)
#define ble_SniffConnReqCmd_CALLBACK NULL
#define ble_SniffConnReqCmd_DEFAULT NULL

#define ble_SniffAccessAddressCmd_FIELDLIST(X, a) \

#define ble_SniffAccessAddressCmd_CALLBACK NULL
#define ble_SniffAccessAddressCmd_DEFAULT NULL

#define ble_SniffActiveConnCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    1)
#define ble_SniffActiveConnCmd_CALLBACK NULL
#define ble_SniffActiveConnCmd_DEFAULT NULL

#define ble_JamConnCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    1)
#define ble_JamConnCmd_CALLBACK NULL
#define ble_JamConnCmd_DEFAULT NULL

#define ble_ScanModeCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BOOL,     active_scan,       1)
#define ble_ScanModeCmd_CALLBACK NULL
#define ble_ScanModeCmd_DEFAULT NULL

#define ble_AdvModeCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BYTES,    scan_data,         1) \
X(a, STATIC,   SINGULAR, BYTES,    scanrsp_data,      2)
#define ble_AdvModeCmd_CALLBACK NULL
#define ble_AdvModeCmd_DEFAULT NULL

#define ble_SetAdvDataCmd_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, BYTES,    scan_data,         1) \
X(a, CALLBACK, SINGULAR, BYTES,    scanrsp_data,      2)
#define ble_SetAdvDataCmd_CALLBACK pb_default_field_callback
#define ble_SetAdvDataCmd_DEFAULT NULL

#define ble_CentralModeCmd_FIELDLIST(X, a) \

#define ble_CentralModeCmd_CALLBACK NULL
#define ble_CentralModeCmd_DEFAULT NULL

#define ble_ConnectToCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, bd_address,        1)
#define ble_ConnectToCmd_CALLBACK NULL
#define ble_ConnectToCmd_DEFAULT NULL

#define ble_SendRawPDUCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    direction,         1) \
X(a, STATIC,   SINGULAR, UINT32,   conn_handle,       2) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    3) \
X(a, STATIC,   SINGULAR, BYTES,    pdu,               4) \
X(a, STATIC,   SINGULAR, UINT32,   crc,               5)
#define ble_SendRawPDUCmd_CALLBACK NULL
#define ble_SendRawPDUCmd_DEFAULT NULL

#define ble_SendPDUCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    direction,         1) \
X(a, STATIC,   SINGULAR, UINT32,   conn_handle,       2) \
X(a, STATIC,   SINGULAR, BYTES,    pdu,               3)
#define ble_SendPDUCmd_CALLBACK NULL
#define ble_SendPDUCmd_DEFAULT NULL

#define ble_DisconnectCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, INT32,    conn_handle,       1)
#define ble_DisconnectCmd_CALLBACK NULL
#define ble_DisconnectCmd_DEFAULT NULL

#define ble_PeripheralModeCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BYTES,    scan_data,         1) \
X(a, STATIC,   SINGULAR, BYTES,    scanrsp_data,      2)
#define ble_PeripheralModeCmd_CALLBACK NULL
#define ble_PeripheralModeCmd_DEFAULT NULL

#define ble_StartCmd_FIELDLIST(X, a) \

#define ble_StartCmd_CALLBACK NULL
#define ble_StartCmd_DEFAULT NULL

#define ble_StopCmd_FIELDLIST(X, a) \

#define ble_StopCmd_CALLBACK NULL
#define ble_StopCmd_DEFAULT NULL

#define ble_HijackMasterCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    1)
#define ble_HijackMasterCmd_CALLBACK NULL
#define ble_HijackMasterCmd_DEFAULT NULL

#define ble_HijackSlaveCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    1)
#define ble_HijackSlaveCmd_CALLBACK NULL
#define ble_HijackSlaveCmd_DEFAULT NULL

#define ble_HijackBothCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    1)
#define ble_HijackBothCmd_CALLBACK NULL
#define ble_HijackBothCmd_DEFAULT NULL

#define ble_AccessAddressDiscovered_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    1) \
X(a, STATIC,   OPTIONAL, INT32,    rssi,              2) \
X(a, STATIC,   OPTIONAL, UINT32,   timestamp,         3)
#define ble_AccessAddressDiscovered_CALLBACK NULL
#define ble_AccessAddressDiscovered_DEFAULT NULL

#define ble_AdvPduReceived_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    adv_type,          1) \
X(a, STATIC,   SINGULAR, INT32,    rssi,              2) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, bd_address,        3) \
X(a, STATIC,   SINGULAR, BYTES,    adv_data,          4)
#define ble_AdvPduReceived_CALLBACK NULL
#define ble_AdvPduReceived_DEFAULT NULL

#define ble_Connected_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, initiator,         1) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, advertiser,        2) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    3) \
X(a, STATIC,   SINGULAR, UINT32,   conn_handle,       8)
#define ble_Connected_CALLBACK NULL
#define ble_Connected_DEFAULT NULL

#define ble_Disconnected_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   reason,            1) \
X(a, STATIC,   SINGULAR, UINT32,   conn_handle,       2)
#define ble_Disconnected_CALLBACK NULL
#define ble_Disconnected_DEFAULT NULL

#define ble_Synchronized_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    1) \
X(a, STATIC,   SINGULAR, UINT32,   crc_init,          2) \
X(a, STATIC,   SINGULAR, UINT32,   hop_interval,      3) \
X(a, STATIC,   SINGULAR, UINT32,   hop_increment,     4) \
X(a, STATIC,   SINGULAR, FIXED_LENGTH_BYTES, channel_map,       5)
#define ble_Synchronized_CALLBACK NULL
#define ble_Synchronized_DEFAULT NULL

#define ble_Desynchronized_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    1)
#define ble_Desynchronized_CALLBACK NULL
#define ble_Desynchronized_DEFAULT NULL

#define ble_Hijacked_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BOOL,     success,           1) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    2)
#define ble_Hijacked_CALLBACK NULL
#define ble_Hijacked_DEFAULT NULL

#define ble_Injected_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BOOL,     success,           1) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    2) \
X(a, STATIC,   SINGULAR, UINT32,   injection_attempts,   3)
#define ble_Injected_CALLBACK NULL
#define ble_Injected_DEFAULT NULL

#define ble_RawPduReceived_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    direction,         1) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           2) \
X(a, STATIC,   OPTIONAL, INT32,    rssi,              3) \
X(a, STATIC,   OPTIONAL, UINT32,   timestamp,         4) \
X(a, STATIC,   OPTIONAL, UINT32,   relative_timestamp,   5) \
X(a, STATIC,   OPTIONAL, BOOL,     crc_validity,      6) \
X(a, STATIC,   SINGULAR, UINT32,   access_address,    7) \
X(a, STATIC,   SINGULAR, BYTES,    pdu,               8) \
X(a, STATIC,   SINGULAR, UINT32,   crc,               9) \
X(a, STATIC,   SINGULAR, UINT32,   conn_handle,      10) \
X(a, STATIC,   SINGULAR, BOOL,     processed,        11)
#define ble_RawPduReceived_CALLBACK NULL
#define ble_RawPduReceived_DEFAULT NULL

#define ble_PduReceived_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UENUM,    direction,         1) \
X(a, STATIC,   SINGULAR, BYTES,    pdu,               2) \
X(a, STATIC,   SINGULAR, UINT32,   conn_handle,       3) \
X(a, STATIC,   SINGULAR, BOOL,     processed,         4)
#define ble_PduReceived_CALLBACK NULL
#define ble_PduReceived_DEFAULT NULL

#define ble_Message_FIELDLIST(X, a) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,set_bd_addr,msg.set_bd_addr),   1) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,sniff_adv,msg.sniff_adv),   2) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,jam_adv,msg.jam_adv),   3) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,jam_adv_chan,msg.jam_adv_chan),   4) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,sniff_connreq,msg.sniff_connreq),   5) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,sniff_aa,msg.sniff_aa),   6) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,sniff_conn,msg.sniff_conn),   7) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,jam_conn,msg.jam_conn),   8) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,scan_mode,msg.scan_mode),   9) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,adv_mode,msg.adv_mode),  10) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,set_adv_data,msg.set_adv_data),  11) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,central_mode,msg.central_mode),  12) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,connect,msg.connect),  13) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,send_raw_pdu,msg.send_raw_pdu),  14) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,send_pdu,msg.send_pdu),  15) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,disconnect,msg.disconnect),  16) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,periph_mode,msg.periph_mode),  17) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,start,msg.start),  18) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,stop,msg.stop),  19) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,hijack_master,msg.hijack_master),  20) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,hijack_slave,msg.hijack_slave),  21) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,hijack_both,msg.hijack_both),  22) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,aa_disc,msg.aa_disc),  23) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,adv_pdu,msg.adv_pdu),  24) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,connected,msg.connected),  25) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,disconnected,msg.disconnected),  26) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,synchronized,msg.synchronized),  27) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,hijacked,msg.hijacked),  28) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,pdu,msg.pdu),  29) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,raw_pdu,msg.raw_pdu),  30) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,injected,msg.injected),  31) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,desynchronized,msg.desynchronized),  32)
#define ble_Message_CALLBACK NULL
#define ble_Message_DEFAULT NULL
#define ble_Message_msg_set_bd_addr_MSGTYPE ble_SetBdAddressCmd
#define ble_Message_msg_sniff_adv_MSGTYPE ble_SniffAdvCmd
#define ble_Message_msg_jam_adv_MSGTYPE ble_JamAdvCmd
#define ble_Message_msg_jam_adv_chan_MSGTYPE ble_JamAdvOnChannelCmd
#define ble_Message_msg_sniff_connreq_MSGTYPE ble_SniffConnReqCmd
#define ble_Message_msg_sniff_aa_MSGTYPE ble_SniffAccessAddressCmd
#define ble_Message_msg_sniff_conn_MSGTYPE ble_SniffActiveConnCmd
#define ble_Message_msg_jam_conn_MSGTYPE ble_JamConnCmd
#define ble_Message_msg_scan_mode_MSGTYPE ble_ScanModeCmd
#define ble_Message_msg_adv_mode_MSGTYPE ble_AdvModeCmd
#define ble_Message_msg_set_adv_data_MSGTYPE ble_SetAdvDataCmd
#define ble_Message_msg_central_mode_MSGTYPE ble_CentralModeCmd
#define ble_Message_msg_connect_MSGTYPE ble_ConnectToCmd
#define ble_Message_msg_send_raw_pdu_MSGTYPE ble_SendRawPDUCmd
#define ble_Message_msg_send_pdu_MSGTYPE ble_SendPDUCmd
#define ble_Message_msg_disconnect_MSGTYPE ble_DisconnectCmd
#define ble_Message_msg_periph_mode_MSGTYPE ble_PeripheralModeCmd
#define ble_Message_msg_start_MSGTYPE ble_StartCmd
#define ble_Message_msg_stop_MSGTYPE ble_StopCmd
#define ble_Message_msg_hijack_master_MSGTYPE ble_HijackMasterCmd
#define ble_Message_msg_hijack_slave_MSGTYPE ble_HijackSlaveCmd
#define ble_Message_msg_hijack_both_MSGTYPE ble_HijackBothCmd
#define ble_Message_msg_aa_disc_MSGTYPE ble_AccessAddressDiscovered
#define ble_Message_msg_adv_pdu_MSGTYPE ble_AdvPduReceived
#define ble_Message_msg_connected_MSGTYPE ble_Connected
#define ble_Message_msg_disconnected_MSGTYPE ble_Disconnected
#define ble_Message_msg_synchronized_MSGTYPE ble_Synchronized
#define ble_Message_msg_hijacked_MSGTYPE ble_Hijacked
#define ble_Message_msg_pdu_MSGTYPE ble_PduReceived
#define ble_Message_msg_raw_pdu_MSGTYPE ble_RawPduReceived
#define ble_Message_msg_injected_MSGTYPE ble_Injected
#define ble_Message_msg_desynchronized_MSGTYPE ble_Desynchronized

extern const pb_msgdesc_t ble_SetBdAddressCmd_msg;
extern const pb_msgdesc_t ble_SniffAdvCmd_msg;
extern const pb_msgdesc_t ble_JamAdvCmd_msg;
extern const pb_msgdesc_t ble_JamAdvOnChannelCmd_msg;
extern const pb_msgdesc_t ble_SniffConnReqCmd_msg;
extern const pb_msgdesc_t ble_SniffAccessAddressCmd_msg;
extern const pb_msgdesc_t ble_SniffActiveConnCmd_msg;
extern const pb_msgdesc_t ble_JamConnCmd_msg;
extern const pb_msgdesc_t ble_ScanModeCmd_msg;
extern const pb_msgdesc_t ble_AdvModeCmd_msg;
extern const pb_msgdesc_t ble_SetAdvDataCmd_msg;
extern const pb_msgdesc_t ble_CentralModeCmd_msg;
extern const pb_msgdesc_t ble_ConnectToCmd_msg;
extern const pb_msgdesc_t ble_SendRawPDUCmd_msg;
extern const pb_msgdesc_t ble_SendPDUCmd_msg;
extern const pb_msgdesc_t ble_DisconnectCmd_msg;
extern const pb_msgdesc_t ble_PeripheralModeCmd_msg;
extern const pb_msgdesc_t ble_StartCmd_msg;
extern const pb_msgdesc_t ble_StopCmd_msg;
extern const pb_msgdesc_t ble_HijackMasterCmd_msg;
extern const pb_msgdesc_t ble_HijackSlaveCmd_msg;
extern const pb_msgdesc_t ble_HijackBothCmd_msg;
extern const pb_msgdesc_t ble_AccessAddressDiscovered_msg;
extern const pb_msgdesc_t ble_AdvPduReceived_msg;
extern const pb_msgdesc_t ble_Connected_msg;
extern const pb_msgdesc_t ble_Disconnected_msg;
extern const pb_msgdesc_t ble_Synchronized_msg;
extern const pb_msgdesc_t ble_Desynchronized_msg;
extern const pb_msgdesc_t ble_Hijacked_msg;
extern const pb_msgdesc_t ble_Injected_msg;
extern const pb_msgdesc_t ble_RawPduReceived_msg;
extern const pb_msgdesc_t ble_PduReceived_msg;
extern const pb_msgdesc_t ble_Message_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define ble_SetBdAddressCmd_fields &ble_SetBdAddressCmd_msg
#define ble_SniffAdvCmd_fields &ble_SniffAdvCmd_msg
#define ble_JamAdvCmd_fields &ble_JamAdvCmd_msg
#define ble_JamAdvOnChannelCmd_fields &ble_JamAdvOnChannelCmd_msg
#define ble_SniffConnReqCmd_fields &ble_SniffConnReqCmd_msg
#define ble_SniffAccessAddressCmd_fields &ble_SniffAccessAddressCmd_msg
#define ble_SniffActiveConnCmd_fields &ble_SniffActiveConnCmd_msg
#define ble_JamConnCmd_fields &ble_JamConnCmd_msg
#define ble_ScanModeCmd_fields &ble_ScanModeCmd_msg
#define ble_AdvModeCmd_fields &ble_AdvModeCmd_msg
#define ble_SetAdvDataCmd_fields &ble_SetAdvDataCmd_msg
#define ble_CentralModeCmd_fields &ble_CentralModeCmd_msg
#define ble_ConnectToCmd_fields &ble_ConnectToCmd_msg
#define ble_SendRawPDUCmd_fields &ble_SendRawPDUCmd_msg
#define ble_SendPDUCmd_fields &ble_SendPDUCmd_msg
#define ble_DisconnectCmd_fields &ble_DisconnectCmd_msg
#define ble_PeripheralModeCmd_fields &ble_PeripheralModeCmd_msg
#define ble_StartCmd_fields &ble_StartCmd_msg
#define ble_StopCmd_fields &ble_StopCmd_msg
#define ble_HijackMasterCmd_fields &ble_HijackMasterCmd_msg
#define ble_HijackSlaveCmd_fields &ble_HijackSlaveCmd_msg
#define ble_HijackBothCmd_fields &ble_HijackBothCmd_msg
#define ble_AccessAddressDiscovered_fields &ble_AccessAddressDiscovered_msg
#define ble_AdvPduReceived_fields &ble_AdvPduReceived_msg
#define ble_Connected_fields &ble_Connected_msg
#define ble_Disconnected_fields &ble_Disconnected_msg
#define ble_Synchronized_fields &ble_Synchronized_msg
#define ble_Desynchronized_fields &ble_Desynchronized_msg
#define ble_Hijacked_fields &ble_Hijacked_msg
#define ble_Injected_fields &ble_Injected_msg
#define ble_RawPduReceived_fields &ble_RawPduReceived_msg
#define ble_PduReceived_fields &ble_PduReceived_msg
#define ble_Message_fields &ble_Message_msg

/* Maximum encoded size of messages (where known) */
/* ble_SetAdvDataCmd_size depends on runtime parameters */
/* ble_Message_size depends on runtime parameters */
#define ble_AccessAddressDiscovered_size         23
#define ble_AdvModeCmd_size                      66
#define ble_AdvPduReceived_size                  54
#define ble_CentralModeCmd_size                  0
#define ble_ConnectToCmd_size                    8
#define ble_Connected_size                       28
#define ble_Desynchronized_size                  6
#define ble_DisconnectCmd_size                   11
#define ble_Disconnected_size                    12
#define ble_HijackBothCmd_size                   6
#define ble_HijackMasterCmd_size                 6
#define ble_HijackSlaveCmd_size                  6
#define ble_Hijacked_size                        8
#define ble_Injected_size                        14
#define ble_JamAdvCmd_size                       0
#define ble_JamAdvOnChannelCmd_size              6
#define ble_JamConnCmd_size                      6
#define ble_PduReceived_size                     313
#define ble_PeripheralModeCmd_size               66
#define ble_RawPduReceived_size                  311
#define ble_ScanModeCmd_size                     2
#define ble_SendPDUCmd_size                      311
#define ble_SendRawPDUCmd_size                   323
#define ble_SetBdAddressCmd_size                 8
#define ble_SniffAccessAddressCmd_size           0
#define ble_SniffActiveConnCmd_size              6
#define ble_SniffAdvCmd_size                     16
#define ble_SniffConnReqCmd_size                 18
#define ble_StartCmd_size                        0
#define ble_StopCmd_size                         0
#define ble_Synchronized_size                    31

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
