#include "inc/dispatch.h"
#include "inc/adapter.h"

void dispatch_message(Message *message)
{
    switch (message->which_msg)
    {
        case Message_generic_tag:
            {
                /* Not supported for now. */
                adapter_on_unsupported(message);
            }
            break;
        
        case Message_ble_tag:
            {
                switch (message->msg.ble.which_msg)
                {
                    case ble_Message_scan_mode_tag:
                    {
                        /* Forward to adapter. */
                        //adapter_on_sniff_adv(&message->msg.ble.msg.sniff_adv);
                        adapter_on_enable_scan(&message->msg.ble.msg.scan_mode);
                    }
                    break;

                    case ble_Message_start_tag:
                    {
                        adapter_on_start(&message->msg.ble.msg.start);
                    }
                    break;

                    case ble_Message_stop_tag:
                    {
                        adapter_on_stop(&message->msg.ble.msg.stop);
                    }
                    break;

                    default:
                    {
                        /* Unsupported message. */
                        adapter_on_unsupported(message);
                    }
                    break;
                }
            }
            break;

        case Message_discovery_tag:
            {
                /* Dispatch discovery message. */
                switch (message->msg.discovery.which_msg)
                {
                    case discovery_Message_info_query_tag:
                    {
                        /* Forward DeviceInfo query to adapter. */
                        adapter_on_device_info_req(
                            &message->msg.discovery.msg.info_query
                        );
                    }
                    break;

                    case discovery_Message_domain_query_tag:
                    {
                        adapter_on_domain_info_req(
                            &message->msg.discovery.msg.domain_query
                        );
                    }
                    break;

                    default:
                        adapter_on_unsupported(message);
                }
            }
            break;

        default:
            break;
    }
}