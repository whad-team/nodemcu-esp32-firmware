/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "esp_log.h"

#include "driver/uart.h"

#include "inc/ble_hack.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/whad.pb.h"
#include "protocol/whad.h"

#include "inc/adapter.h"
#include "inc/comm.h"
#include "inc/dispatch.h"
#include "inc/helpers.h"

#define BUF_SIZE (1024)

void
app_main(void)
{
    int nb_bytes_recvd, msg_size, i, j;
    uint8_t buffer[128];
    Message message_in = Message_init_default;

    reconfigure_uart(115200, true);
    dbg_txt("[system] UART0 reconfigured\r\n");

    adapter_init();
    dbg_txt("adapter ok");

    /* Hack BLE stack. */
    dbg_txt("[system] Hooking BLE ROM functions ... ");
    ble_hack_install_hooks();
    /* Install a RX handler. */
    
    ble_hack_rx_control_pdu_handler(ble_rx_ctl_handler);
    ble_hack_rx_data_pdu_handler(ble_rx_data_handler);
    ble_hack_tx_control_pdu_handler(ble_tx_ctl_handler);
    ble_hack_tx_data_pdu_handler(ble_tx_data_handler);

    /* Handle UART messages. */
    while (1)
    {
        /* Process input messages. */
        if (receive_pb_message(&message_in) > 0)
            dispatch_message(&message_in);
        
        /* Flush pending messages. */
        flush_pending_pb_messages();

        /* Allow other tasks to run. */
        vTaskDelay(10);
    }
}
