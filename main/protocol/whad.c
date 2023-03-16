#include "whad.h"

void whad_generic_cmd_result(
    Message *message,
    generic_ResultCode result
)
{
    message->which_msg = Message_generic_tag;
    message->msg.generic.which_msg = generic_Message_cmd_result_tag;
    message->msg.generic.msg.cmd_result.result = result;
}

/**
 * @brief Generic verbose message encoding callback.
 * 
 * @param ostream Output stream
 * @param field Pointer to a field descriptor.
 * @param arg Pointer to a custom argument storing a pointer onto the text message to encode.
 * @return true if everything went ok.
 * @return false if an error is encountered during encoding.
 */
bool whad_verbose_msg_encode_cb(pb_ostream_t *ostream, const pb_field_t *field, void * const *arg)
{
    char dbg[1024];

    /* Take arg and encode it. */
    char *psz_message = *(char **)arg;
    int message_length = strlen(psz_message);

    if (ostream != NULL && field->tag == generic_VerboseMsg_data_tag)
    {
        /* This encodes the header for the field, based on the constant info
        * from pb_field_t. */
        if (!pb_encode_tag_for_field(ostream, field))
            return false;

        pb_encode_string(ostream, (pb_byte_t *)psz_message, message_length);
    }

    return true;
}


/**
 * @brief Initialize a generic verbose message.
 * 
 * @param message pointer to a `Message` structure representing a message.
 */
void whad_init_verbose_message(Message *message, char *psz_message)
{
    /* Specify payload type. */
    message->which_msg = Message_generic_tag;

    /* Fills verbose message data. */
    message->msg.generic.which_msg = generic_Message_verbose_tag;
    message->msg.generic.msg.verbose.data.arg = psz_message;
    message->msg.generic.msg.verbose.data.funcs.encode = whad_verbose_msg_encode_cb;
}

/**
 * @brief Initialize a generic error message.
 * 
 * @param message Pointer to a message structure to initialize.
 * @param error Error code.
 */
void whad_init_error_message(Message *message, generic_ResultCode error)
{
    message->which_msg = Message_generic_tag;
    message->msg.generic.which_msg = generic_Message_cmd_result_tag;
    message->msg.generic.msg.cmd_result.result = error;
}


bool whad_disc_enum_capabilities_cb(pb_ostream_t *ostream, const pb_field_t *field, void * const *arg)
{
    DeviceCapability *capabilities = *(DeviceCapability **)arg;
    if (ostream != NULL && field->tag == discovery_DeviceInfoResp_capabilities_tag)
    {
        while ((capabilities->cap != 0) && (capabilities->domain != 0))
        {
            if (!pb_encode_tag_for_field(ostream, field))
                return false;

            if (!pb_encode_varint(ostream, capabilities->domain | capabilities->cap))
                return false;

            /* Go to next capability. */
            capabilities++;
        }
    }

    return true;
}


void whad_discovery_device_info_resp(
    Message *message,
    discovery_DeviceType device_type,
    uint8_t *devid,
    uint32_t proto_min_ver,
    uint32_t max_speed,
    char *fw_author,
    char *fw_url,
    uint32_t fw_version_major,
    uint32_t fw_version_minor,
    uint32_t fw_version_rev,
    DeviceCapability *capabilities)
{
    message->which_msg = Message_discovery_tag;
    message->msg.discovery.which_msg = discovery_Message_info_resp_tag;
    message->msg.discovery.msg.info_resp.proto_min_ver = proto_min_ver;
    message->msg.discovery.msg.info_resp.max_speed = max_speed;
    if (fw_author != NULL)
    {
        strncpy((char *)message->msg.discovery.msg.info_resp.fw_author.bytes, (char *)fw_author, 63);
        message->msg.discovery.msg.info_resp.fw_author.size = strlen(fw_author);
    }
    else
    {
        message->msg.discovery.msg.info_resp.fw_author.size = 0;
    }

    if(fw_url != NULL)
    {
        strncpy((char *)message->msg.discovery.msg.info_resp.fw_url.bytes, (char *)fw_url, 255);
        message->msg.discovery.msg.info_resp.fw_url.size = strlen(fw_url);
    }
    else
    {
        message->msg.discovery.msg.info_resp.fw_url.size = 0;
    }
    
    message->msg.discovery.msg.info_resp.fw_version_major = fw_version_major;
    message->msg.discovery.msg.info_resp.fw_version_minor = fw_version_minor;
    message->msg.discovery.msg.info_resp.fw_version_rev = fw_version_rev;
    message->msg.discovery.msg.info_resp.type = device_type;
    strncpy((char *)message->msg.discovery.msg.info_resp.devid, (char *)devid, 15);
    message->msg.discovery.msg.info_resp.capabilities.arg = capabilities;
    message->msg.discovery.msg.info_resp.capabilities.funcs.encode = whad_disc_enum_capabilities_cb;
}

void whad_discovery_domain_info_resp(
    Message *message, discovery_Domain domain,
    uint64_t supported_commands)
{
    message->which_msg = Message_discovery_tag;
    message->msg.discovery.which_msg = discovery_Message_domain_resp_tag;
    message->msg.discovery.msg.domain_resp.domain = domain;
    message->msg.discovery.msg.domain_resp.supported_commands = supported_commands;
}

void whad_discovery_ready_resp(Message *message)
{
    message->which_msg = Message_discovery_tag;
    message->msg.discovery.which_msg = discovery_Message_ready_resp_tag;
}

void whad_ble_adv_pdu(
    Message *message,
    whad_adv_data_t *args
)
{
    message->which_msg = Message_ble_tag;
    message->msg.ble.which_msg = ble_Message_adv_pdu_tag;
    memcpy(message->msg.ble.msg.adv_pdu.bd_address, args->bd_addr, 6);
    message->msg.ble.msg.adv_pdu.addr_type = args->addr_type;
    memcpy(message->msg.ble.msg.adv_pdu.adv_data.bytes, args->p_adv_data, args->adv_data_length);
    message->msg.ble.msg.adv_pdu.adv_data.size = args->adv_data_length;
    message->msg.ble.msg.adv_pdu.rssi = args->rssi;
    message->msg.ble.msg.adv_pdu.adv_type = args->adv_type;
}

void whad_ble_data_pdu(
    Message *message,
    uint8_t *p_pdu,
    int length,
    ble_BleDirection direction
)
{
    message->which_msg = Message_ble_tag;
    message->msg.ble.which_msg = ble_Message_pdu_tag;
    message->msg.ble.msg.pdu.direction = direction;
    message->msg.ble.msg.pdu.pdu.size = length;
    memcpy(message->msg.ble.msg.pdu.pdu.bytes, p_pdu, length);
}

void whad_ble_ll_data_pdu(
    Message *message,
    uint16_t header,
    uint8_t *p_pdu,
    int length,
    ble_BleDirection direction,
    int conn_handle,
    bool processed,
    bool decrypted
)
{
    message->which_msg = Message_ble_tag;
    message->msg.ble.which_msg = ble_Message_pdu_tag;
    message->msg.ble.msg.pdu.processed = processed?1:0;
    message->msg.ble.msg.pdu.decrypted = decrypted?1:0;
    message->msg.ble.msg.pdu.direction = direction;
    message->msg.ble.msg.pdu.conn_handle = conn_handle;
    message->msg.ble.msg.pdu.pdu.size = length + 2;
    message->msg.ble.msg.pdu.pdu.bytes[0] = (header & 0xff);
    message->msg.ble.msg.pdu.pdu.bytes[1] = (header >> 8) & 0xff;
    memcpy(&message->msg.ble.msg.pdu.pdu.bytes[2], p_pdu, length);
}

void whad_ble_notify_connected(Message *message, uint8_t adv_addr_type, uint8_t *p_adv_addr, uint8_t init_addr_type, uint8_t *p_init_addr, uint32_t conn_handle)
{
    message->which_msg = Message_ble_tag;
    message->msg.ble.which_msg = ble_Message_connected_tag;

    /* Save Access Address (unknown, set to 0). */
    message->msg.ble.msg.connected.access_address = 0;

    /* Save connection handle. */
    message->msg.ble.msg.connected.conn_handle = conn_handle;

    /* Save advertiser address and address type. */
    memcpy(message->msg.ble.msg.connected.advertiser, p_adv_addr, 6);
    message->msg.ble.msg.connected.adv_addr_type = adv_addr_type;

    /* Save initiator address and address type. */
    memcpy(message->msg.ble.msg.connected.initiator, p_init_addr, 6);
    message->msg.ble.msg.connected.init_addr_type = init_addr_type;
}


void whad_ble_notify_disconnected(Message *message, uint32_t conn_handle, uint32_t reason)
{
    message->which_msg = Message_ble_tag;
    message->msg.ble.which_msg = ble_Message_disconnected_tag;
    message->msg.ble.msg.disconnected.conn_handle = conn_handle;
    message->msg.ble.msg.disconnected.reason = reason;
}
