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
                /* Not supported for now. */
                adapter_on_unsupported(message);
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
                        adapter_on_discovery_info_req(
                            &message->msg.discovery.msg.info_query
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