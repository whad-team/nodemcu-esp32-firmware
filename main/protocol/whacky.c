#include "whacky.h"


/**
 * @brief Generic verbose message encoding callback.
 * 
 * @param ostream Output stream
 * @param field Pointer to a field descriptor.
 * @param arg Pointer to a custom argument storing a pointer onto the text message to encode.
 * @return true if everything went ok.
 * @return false if an error is encountered during encoding.
 */
bool whacky_verbose_msg_encode_cb(pb_ostream_t *ostream, const pb_field_t *field, void * const *arg)
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
void whacky_init_verbose_message(Message *message, char *psz_message)
{
    /* Specify payload type. */
    message->which_msg = Message_generic_tag;

    /* Fills verbose message data. */
    message->msg.generic.which_msg = generic_Message_verbose_tag;
    message->msg.generic.msg.verbose.data.arg = psz_message;
    message->msg.generic.msg.verbose.data.funcs.encode = whacky_verbose_msg_encode_cb;
}

/**
 * @brief Initialize a generic error message.
 * 
 * @param message Pointer to a message structure to initialize.
 * @param error Error code.
 */
void whacky_init_error_message(Message *message, generic_ResultCode error)
{
    message->which_msg = Message_generic_tag;
    message->msg.generic.which_msg = generic_CmdResult_result_tag;
    message->msg.generic.msg.cmd_result.result = error;
}


bool whacky_disc_enum_capabilities_cb(pb_ostream_t *ostream, const pb_field_t *field, void * const *arg)
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


void whacky_discovery_info_resp(
    Message *message, discovery_DeviceType device_type,
    uint32_t proto_min_ver, uint32_t fw_version_major,
    uint32_t fw_version_minor, uint32_t fw_version_rev,
    DeviceCapability *capabilities)
{
    message->which_msg = Message_discovery_tag;
    message->msg.discovery.which_msg = discovery_Message_info_resp_tag;
    message->msg.discovery.msg.info_resp.proto_min_ver = proto_min_ver;
    message->msg.discovery.msg.info_resp.fw_version_major = fw_version_major;
    message->msg.discovery.msg.info_resp.fw_version_minor = fw_version_minor;
    message->msg.discovery.msg.info_resp.fw_version_rev = fw_version_rev;
    message->msg.discovery.msg.info_resp.type = device_type;
    message->msg.discovery.msg.info_resp.capabilities.arg = capabilities;
    message->msg.discovery.msg.info_resp.capabilities.funcs.encode = whacky_disc_enum_capabilities_cb;
}

bool whacky_ble_encode_device_discovered_cb(pb_ostream_t *ostream, const pb_field_t *field, void * const *arg)
{
    /* Take arg and encode it. */
    whacky_adv_data_t *p_adv_args = *(whacky_adv_data_t **)arg;

    if (ostream != NULL)
    {
        /* Encode field tag. */
        if (!pb_encode_tag_for_field(ostream, field))
            return false;

        /* Encode field data. */
        switch(field->tag)
        {
            case ble_DeviceDiscovered_adv_data_tag:
            {
                pb_encode_string(ostream, (pb_byte_t *)p_adv_args->p_adv_data, p_adv_args->adv_data_length);
            }
            break;

            case ble_DeviceDiscovered_scanrsp_data_tag:
            {
                pb_encode_string(ostream, (pb_byte_t *)p_adv_args->p_scan_rsp, p_adv_args->scan_rsp_length);
            }
            break;

            case ble_DeviceDiscovered_bd_address_tag:
            {
                pb_encode_string(ostream, (pb_byte_t *)p_adv_args->bd_addr, 6);
            }
            break;
        }
    }

    return true;
}

bool whacky_ble_encode_scan_rsp_cb(pb_ostream_t *ostream, const pb_field_t *field, void * const *arg)
{
    /* Take arg and encode it. */
    whacky_adv_data_t *p_adv_args = *(whacky_adv_data_t **)arg;

    if (ostream != NULL && field->tag == ble_DeviceDiscovered_scanrsp_data_tag)
    {
        /* This encodes the header for the field, based on the constant info
        * from pb_field_t. */
        if (!pb_encode_tag_for_field(ostream, field))
            return false;

        pb_encode_string(ostream, (pb_byte_t *)p_adv_args->p_scan_rsp, p_adv_args->scan_rsp_length);
    }

    return true;
}

void whacky_ble_device_discovered(
    Message *message,
    whacky_adv_data_t *args
)
{
    message->which_msg = Message_ble_tag;
    message->msg.ble.which_msg = ble_Message_device_disc_tag;
    message->msg.ble.msg.device_disc.bd_address.arg = args;
    message->msg.ble.msg.device_disc.bd_address.funcs.encode = whacky_ble_encode_device_discovered_cb;
    message->msg.ble.msg.device_disc.adv_data.arg = args;
    message->msg.ble.msg.device_disc.adv_data.funcs.encode = whacky_ble_encode_device_discovered_cb;
    message->msg.ble.msg.device_disc.scanrsp_data.arg = args;
    message->msg.ble.msg.device_disc.scanrsp_data.funcs.encode = whacky_ble_encode_device_discovered_cb;
}