/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.7-dev */

#ifndef PB_ESB_PROTOCOL_ESB_ESB_PB_H_INCLUDED
#define PB_ESB_PROTOCOL_ESB_ESB_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Enum definitions */
typedef enum _esb_ESBCommand { /* *
 Low-level commands */
    /* Set Node address. */
    esb_ESBCommand_SetNodeAddress = 0, 
    /* Sniff packets. */
    esb_ESBCommand_Sniff = 1, 
    /* Jam packets. */
    esb_ESBCommand_Jam = 2, 
    /* Send packets. */
    esb_ESBCommand_Send = 3, 
    esb_ESBCommand_SendRaw = 4, 
    /* Primary Receiver (PRX) mode. */
    esb_ESBCommand_PrimaryReceiverMode = 5, 
    /* Primary Transmitter (PTX) mode. */
    esb_ESBCommand_PrimaryTransmitterMode = 6, 
    /* Start and Stop commands shared with node-related mode. */
    esb_ESBCommand_Start = 7, 
    esb_ESBCommand_Stop = 8 
} esb_ESBCommand;

/* Struct definitions */
/* *
 StartCmd

 Enable node-related modes. */
typedef struct _esb_StartCmd { 
    char dummy_field;
} esb_StartCmd;

/* *
 StopCmd

 Disable node-related modes. */
typedef struct _esb_StopCmd { 
    char dummy_field;
} esb_StopCmd;

typedef struct _esb_JamCmd { 
    uint32_t channel;
} esb_JamCmd;

typedef struct _esb_Jammed { 
    uint32_t timestamp;
} esb_Jammed;

typedef PB_BYTES_ARRAY_T(5) esb_PduReceived_address_t;
typedef PB_BYTES_ARRAY_T(255) esb_PduReceived_pdu_t;
typedef struct _esb_PduReceived { 
    uint32_t channel;
    bool has_rssi;
    int32_t rssi;
    bool has_timestamp;
    uint32_t timestamp;
    bool has_crc_validity;
    bool crc_validity;
    bool has_address;
    esb_PduReceived_address_t address;
    esb_PduReceived_pdu_t pdu;
} esb_PduReceived;

/* *
 PrimaryReceiverMode

 Enable Primary Receiver (PRX) mode. */
typedef struct _esb_PrimaryReceiverModeCmd { 
    uint32_t channel;
} esb_PrimaryReceiverModeCmd;

/* *
 PrimaryTransmitterMode

 Enable Primary Transmitter (PTX) mode. */
typedef struct _esb_PrimaryTransmitterModeCmd { 
    uint32_t channel;
} esb_PrimaryTransmitterModeCmd;

typedef PB_BYTES_ARRAY_T(5) esb_RawPduReceived_address_t;
typedef PB_BYTES_ARRAY_T(255) esb_RawPduReceived_pdu_t;
typedef struct _esb_RawPduReceived { 
    uint32_t channel;
    bool has_rssi;
    int32_t rssi;
    bool has_timestamp;
    uint32_t timestamp;
    bool has_crc_validity;
    bool crc_validity;
    bool has_address;
    esb_RawPduReceived_address_t address;
    esb_RawPduReceived_pdu_t pdu;
} esb_RawPduReceived;

typedef PB_BYTES_ARRAY_T(255) esb_SendCmd_pdu_t;
/* *
 SendCmd

 Transmit Enhanced ShockBurst packets on a single channel. */
typedef struct _esb_SendCmd { 
    uint32_t channel;
    uint32_t retransmission_count;
    esb_SendCmd_pdu_t pdu;
} esb_SendCmd;

typedef PB_BYTES_ARRAY_T(255) esb_SendRawCmd_pdu_t;
typedef struct _esb_SendRawCmd { 
    uint32_t channel;
    uint32_t retransmission_count;
    esb_SendRawCmd_pdu_t pdu;
} esb_SendRawCmd;

typedef PB_BYTES_ARRAY_T(5) esb_SetNodeAddressCmd_address_t;
typedef struct _esb_SetNodeAddressCmd { 
    esb_SetNodeAddressCmd_address_t address;
} esb_SetNodeAddressCmd;

typedef PB_BYTES_ARRAY_T(5) esb_SniffCmd_address_t;
typedef struct _esb_SniffCmd { 
    /* Channel can be specified, the device will only
listen on this specific channel. */
    uint32_t channel; /* special value: 0xFF (autofind) */
    esb_SniffCmd_address_t address;
    bool show_acknowledgements;
} esb_SniffCmd;

typedef struct _esb_Message { 
    pb_size_t which_msg;
    union {
        /* Messages */
        esb_SetNodeAddressCmd set_node_addr;
        esb_SniffCmd sniff;
        esb_JamCmd jam;
        esb_SendCmd send;
        esb_SendRawCmd send_raw;
        esb_PrimaryReceiverModeCmd prx;
        esb_PrimaryTransmitterModeCmd ptx;
        esb_StartCmd start;
        esb_StopCmd stop;
        /* Notifications */
        esb_Jammed jammed;
        esb_RawPduReceived raw_pdu;
        esb_PduReceived pdu;
    } msg;
} esb_Message;


/* Helper constants for enums */
#define _esb_ESBCommand_MIN esb_ESBCommand_SetNodeAddress
#define _esb_ESBCommand_MAX esb_ESBCommand_Stop
#define _esb_ESBCommand_ARRAYSIZE ((esb_ESBCommand)(esb_ESBCommand_Stop+1))


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define esb_SetNodeAddressCmd_init_default       {{0, {0}}}
#define esb_SniffCmd_init_default                {0, {0, {0}}, 0}
#define esb_JamCmd_init_default                  {0}
#define esb_SendCmd_init_default                 {0, 0, {0, {0}}}
#define esb_SendRawCmd_init_default              {0, 0, {0, {0}}}
#define esb_PrimaryReceiverModeCmd_init_default  {0}
#define esb_PrimaryTransmitterModeCmd_init_default {0}
#define esb_StartCmd_init_default                {0}
#define esb_StopCmd_init_default                 {0}
#define esb_Jammed_init_default                  {0}
#define esb_RawPduReceived_init_default          {0, false, 0, false, 0, false, 0, false, {0, {0}}, {0, {0}}}
#define esb_PduReceived_init_default             {0, false, 0, false, 0, false, 0, false, {0, {0}}, {0, {0}}}
#define esb_Message_init_default                 {0, {esb_SetNodeAddressCmd_init_default}}
#define esb_SetNodeAddressCmd_init_zero          {{0, {0}}}
#define esb_SniffCmd_init_zero                   {0, {0, {0}}, 0}
#define esb_JamCmd_init_zero                     {0}
#define esb_SendCmd_init_zero                    {0, 0, {0, {0}}}
#define esb_SendRawCmd_init_zero                 {0, 0, {0, {0}}}
#define esb_PrimaryReceiverModeCmd_init_zero     {0}
#define esb_PrimaryTransmitterModeCmd_init_zero  {0}
#define esb_StartCmd_init_zero                   {0}
#define esb_StopCmd_init_zero                    {0}
#define esb_Jammed_init_zero                     {0}
#define esb_RawPduReceived_init_zero             {0, false, 0, false, 0, false, 0, false, {0, {0}}, {0, {0}}}
#define esb_PduReceived_init_zero                {0, false, 0, false, 0, false, 0, false, {0, {0}}, {0, {0}}}
#define esb_Message_init_zero                    {0, {esb_SetNodeAddressCmd_init_zero}}

/* Field tags (for use in manual encoding/decoding) */
#define esb_JamCmd_channel_tag                   1
#define esb_Jammed_timestamp_tag                 1
#define esb_PduReceived_channel_tag              1
#define esb_PduReceived_rssi_tag                 2
#define esb_PduReceived_timestamp_tag            3
#define esb_PduReceived_crc_validity_tag         4
#define esb_PduReceived_address_tag              5
#define esb_PduReceived_pdu_tag                  6
#define esb_PrimaryReceiverModeCmd_channel_tag   1
#define esb_PrimaryTransmitterModeCmd_channel_tag 1
#define esb_RawPduReceived_channel_tag           1
#define esb_RawPduReceived_rssi_tag              2
#define esb_RawPduReceived_timestamp_tag         3
#define esb_RawPduReceived_crc_validity_tag      4
#define esb_RawPduReceived_address_tag           5
#define esb_RawPduReceived_pdu_tag               6
#define esb_SendCmd_channel_tag                  1
#define esb_SendCmd_retransmission_count_tag     2
#define esb_SendCmd_pdu_tag                      3
#define esb_SendRawCmd_channel_tag               1
#define esb_SendRawCmd_retransmission_count_tag  2
#define esb_SendRawCmd_pdu_tag                   3
#define esb_SetNodeAddressCmd_address_tag        1
#define esb_SniffCmd_channel_tag                 1
#define esb_SniffCmd_address_tag                 2
#define esb_SniffCmd_show_acknowledgements_tag   3
#define esb_Message_set_node_addr_tag            1
#define esb_Message_sniff_tag                    2
#define esb_Message_jam_tag                      3
#define esb_Message_send_tag                     4
#define esb_Message_send_raw_tag                 5
#define esb_Message_prx_tag                      6
#define esb_Message_ptx_tag                      7
#define esb_Message_start_tag                    8
#define esb_Message_stop_tag                     9
#define esb_Message_jammed_tag                   10
#define esb_Message_raw_pdu_tag                  11
#define esb_Message_pdu_tag                      12

/* Struct field encoding specification for nanopb */
#define esb_SetNodeAddressCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BYTES,    address,           1)
#define esb_SetNodeAddressCmd_CALLBACK NULL
#define esb_SetNodeAddressCmd_DEFAULT NULL

#define esb_SniffCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1) \
X(a, STATIC,   SINGULAR, BYTES,    address,           2) \
X(a, STATIC,   SINGULAR, BOOL,     show_acknowledgements,   3)
#define esb_SniffCmd_CALLBACK NULL
#define esb_SniffCmd_DEFAULT NULL

#define esb_JamCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1)
#define esb_JamCmd_CALLBACK NULL
#define esb_JamCmd_DEFAULT NULL

#define esb_SendCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1) \
X(a, STATIC,   SINGULAR, UINT32,   retransmission_count,   2) \
X(a, STATIC,   SINGULAR, BYTES,    pdu,               3)
#define esb_SendCmd_CALLBACK NULL
#define esb_SendCmd_DEFAULT NULL

#define esb_SendRawCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1) \
X(a, STATIC,   SINGULAR, UINT32,   retransmission_count,   2) \
X(a, STATIC,   SINGULAR, BYTES,    pdu,               3)
#define esb_SendRawCmd_CALLBACK NULL
#define esb_SendRawCmd_DEFAULT NULL

#define esb_PrimaryReceiverModeCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1)
#define esb_PrimaryReceiverModeCmd_CALLBACK NULL
#define esb_PrimaryReceiverModeCmd_DEFAULT NULL

#define esb_PrimaryTransmitterModeCmd_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1)
#define esb_PrimaryTransmitterModeCmd_CALLBACK NULL
#define esb_PrimaryTransmitterModeCmd_DEFAULT NULL

#define esb_StartCmd_FIELDLIST(X, a) \

#define esb_StartCmd_CALLBACK NULL
#define esb_StartCmd_DEFAULT NULL

#define esb_StopCmd_FIELDLIST(X, a) \

#define esb_StopCmd_CALLBACK NULL
#define esb_StopCmd_DEFAULT NULL

#define esb_Jammed_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   timestamp,         1)
#define esb_Jammed_CALLBACK NULL
#define esb_Jammed_DEFAULT NULL

#define esb_RawPduReceived_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1) \
X(a, STATIC,   OPTIONAL, INT32,    rssi,              2) \
X(a, STATIC,   OPTIONAL, UINT32,   timestamp,         3) \
X(a, STATIC,   OPTIONAL, BOOL,     crc_validity,      4) \
X(a, STATIC,   OPTIONAL, BYTES,    address,           5) \
X(a, STATIC,   SINGULAR, BYTES,    pdu,               6)
#define esb_RawPduReceived_CALLBACK NULL
#define esb_RawPduReceived_DEFAULT NULL

#define esb_PduReceived_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           1) \
X(a, STATIC,   OPTIONAL, INT32,    rssi,              2) \
X(a, STATIC,   OPTIONAL, UINT32,   timestamp,         3) \
X(a, STATIC,   OPTIONAL, BOOL,     crc_validity,      4) \
X(a, STATIC,   OPTIONAL, BYTES,    address,           5) \
X(a, STATIC,   SINGULAR, BYTES,    pdu,               6)
#define esb_PduReceived_CALLBACK NULL
#define esb_PduReceived_DEFAULT NULL

#define esb_Message_FIELDLIST(X, a) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,set_node_addr,msg.set_node_addr),   1) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,sniff,msg.sniff),   2) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,jam,msg.jam),   3) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,send,msg.send),   4) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,send_raw,msg.send_raw),   5) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,prx,msg.prx),   6) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,ptx,msg.ptx),   7) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,start,msg.start),   8) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,stop,msg.stop),   9) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,jammed,msg.jammed),  10) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,raw_pdu,msg.raw_pdu),  11) \
X(a, STATIC,   ONEOF,    MESSAGE,  (msg,pdu,msg.pdu),  12)
#define esb_Message_CALLBACK NULL
#define esb_Message_DEFAULT NULL
#define esb_Message_msg_set_node_addr_MSGTYPE esb_SetNodeAddressCmd
#define esb_Message_msg_sniff_MSGTYPE esb_SniffCmd
#define esb_Message_msg_jam_MSGTYPE esb_JamCmd
#define esb_Message_msg_send_MSGTYPE esb_SendCmd
#define esb_Message_msg_send_raw_MSGTYPE esb_SendRawCmd
#define esb_Message_msg_prx_MSGTYPE esb_PrimaryReceiverModeCmd
#define esb_Message_msg_ptx_MSGTYPE esb_PrimaryTransmitterModeCmd
#define esb_Message_msg_start_MSGTYPE esb_StartCmd
#define esb_Message_msg_stop_MSGTYPE esb_StopCmd
#define esb_Message_msg_jammed_MSGTYPE esb_Jammed
#define esb_Message_msg_raw_pdu_MSGTYPE esb_RawPduReceived
#define esb_Message_msg_pdu_MSGTYPE esb_PduReceived

extern const pb_msgdesc_t esb_SetNodeAddressCmd_msg;
extern const pb_msgdesc_t esb_SniffCmd_msg;
extern const pb_msgdesc_t esb_JamCmd_msg;
extern const pb_msgdesc_t esb_SendCmd_msg;
extern const pb_msgdesc_t esb_SendRawCmd_msg;
extern const pb_msgdesc_t esb_PrimaryReceiverModeCmd_msg;
extern const pb_msgdesc_t esb_PrimaryTransmitterModeCmd_msg;
extern const pb_msgdesc_t esb_StartCmd_msg;
extern const pb_msgdesc_t esb_StopCmd_msg;
extern const pb_msgdesc_t esb_Jammed_msg;
extern const pb_msgdesc_t esb_RawPduReceived_msg;
extern const pb_msgdesc_t esb_PduReceived_msg;
extern const pb_msgdesc_t esb_Message_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define esb_SetNodeAddressCmd_fields &esb_SetNodeAddressCmd_msg
#define esb_SniffCmd_fields &esb_SniffCmd_msg
#define esb_JamCmd_fields &esb_JamCmd_msg
#define esb_SendCmd_fields &esb_SendCmd_msg
#define esb_SendRawCmd_fields &esb_SendRawCmd_msg
#define esb_PrimaryReceiverModeCmd_fields &esb_PrimaryReceiverModeCmd_msg
#define esb_PrimaryTransmitterModeCmd_fields &esb_PrimaryTransmitterModeCmd_msg
#define esb_StartCmd_fields &esb_StartCmd_msg
#define esb_StopCmd_fields &esb_StopCmd_msg
#define esb_Jammed_fields &esb_Jammed_msg
#define esb_RawPduReceived_fields &esb_RawPduReceived_msg
#define esb_PduReceived_fields &esb_PduReceived_msg
#define esb_Message_fields &esb_Message_msg

/* Maximum encoded size of messages (where known) */
#define esb_JamCmd_size                          6
#define esb_Jammed_size                          6
#define esb_Message_size                         293
#define esb_PduReceived_size                     290
#define esb_PrimaryReceiverModeCmd_size          6
#define esb_PrimaryTransmitterModeCmd_size       6
#define esb_RawPduReceived_size                  290
#define esb_SendCmd_size                         270
#define esb_SendRawCmd_size                      270
#define esb_SetNodeAddressCmd_size               7
#define esb_SniffCmd_size                        15
#define esb_StartCmd_size                        0
#define esb_StopCmd_size                         0

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
