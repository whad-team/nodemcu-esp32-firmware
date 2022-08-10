#include "inc/comm.h"
#include "inc/helpers.h"

static uint8_t pb_tx_buffer[1024];
static uint8_t pb_rx_buffer[1024];
volatile int nb_rx_bytes = 0;

static uint8_t pb_pending_tx_buffer[10*1024];
volatile int nb_pending_bytes = 0;

esp_err_t reconfigure_uart(int speed, bool reinstall_driver)
{
    /**
     * Reconfigure UART0 in order to use it to communicate with our
     * computer through our custom protocol.
     */
    const uart_port_t uart_num = UART_NUM_0;
    uart_config_t uart_config = {
      .baud_rate = speed,
      .data_bits = UART_DATA_8_BITS,
      .parity = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };

    // Configure UART parameters
    uart_driver_delete(UART_NUM_0);
    uart_driver_install(UART_NUM_0, BUF_SIZE * 2, 0, 0, NULL, 0);
    return uart_param_config(uart_num, &uart_config);
}

void pending_pb_message(const void *src_struct)
{
    int size;
    uint8_t header[4];
    
    /* Encode message into our buffer. */
    pb_ostream_t stream = pb_ostream_from_buffer(pb_tx_buffer, 1024);
    if (pb_encode(&stream, Message_fields, src_struct))
    {
        /* Write header. */
        header[0] = '\xAC';
        header[1] = '\xBE';
        header[2] = (stream.bytes_written & 0xff);
        header[3] = (stream.bytes_written >> 8) & 0xff;
        //uart_write_bytes(UART_NUM_0, header, 4);
        memcpy(&pb_pending_tx_buffer[nb_pending_bytes], header, 4);
        nb_pending_bytes += 4;

        /* Write serialized data. */
        //uart_write_bytes(UART_NUM_0, pb_tx_buffer, stream.bytes_written);
        memcpy(&pb_pending_tx_buffer[nb_pending_bytes], pb_tx_buffer, stream.bytes_written);
        nb_pending_bytes += stream.bytes_written;
    }
}

void flush_pending_pb_messages(void)
{
    if (nb_pending_bytes > 0)
    {
        dbg_txt("pending bytes: %d", nb_pending_bytes);
        uart_write_bytes(UART_NUM_0, pb_pending_tx_buffer, nb_pending_bytes);
        nb_pending_bytes = 0;
    }
}


void send_pb_message(const void *src_struct)
{
    int size;
    uint8_t header[4];
    
    /* Encode message into our buffer. */
    pb_ostream_t stream = pb_ostream_from_buffer(pb_tx_buffer, 1024);
    if (pb_encode(&stream, Message_fields, src_struct))
    {
        /* Write header. */
        header[0] = '\xAC';
        header[1] = '\xBE';
        header[2] = (stream.bytes_written & 0xff);
        header[3] = (stream.bytes_written >> 8) & 0xff;
        uart_write_bytes(UART_NUM_0, header, 4);

        /* Write serialized data. */
        uart_write_bytes(UART_NUM_0, pb_tx_buffer, stream.bytes_written);
    }
}

int receive_pb_message(Message *message)
{
    int nb_bytes_recvd, msg_size, i, j, result;

    /* Is our buffer full ? */
    if (nb_rx_bytes >= BUF_SIZE)
    {
        /* Flush buffer (no valid message found in it). */
        nb_rx_bytes = 0;
    }

    /* Check if we have something to read. */
    nb_rx_bytes += /*nb_bytes_recvd =*/ uart_read_bytes(UART_NUM_0, &pb_rx_buffer[nb_rx_bytes], BUF_SIZE - nb_rx_bytes, 10 / portTICK_PERIOD_MS);

    if (nb_rx_bytes >= 2)
    {
        /* Update number of bytes in RX buffer. */
        //nb_rx_bytes += nb_bytes_recvd;

        /* Message is supposed to start with [0xAC, 0xBE]. */
        for (j=0; j<(nb_rx_bytes-1); j++)
        {
            if ((pb_rx_buffer[j] == 0xAC) && (pb_rx_buffer[j+1] == 0xBE))
            {
                if (j > 0)
                {
                    for (i=0; i < (nb_rx_bytes - j); i++)
                        pb_rx_buffer[i] = pb_rx_buffer[j+i];
                    
                    nb_rx_bytes -= j;
                }

                /* Exit for loop and process message. */
                break;
            }
        }

        /* Check if we have a message. */
        if ((pb_rx_buffer[0] == 0xAC) && (pb_rx_buffer[1] == 0xBE))
        {
            /* Check if we have received the full message. */
            if (nb_rx_bytes > 4)
            {
                msg_size = pb_rx_buffer[2] | (pb_rx_buffer[3]<<8);
                if (nb_rx_bytes >= (msg_size + 4))
                {
                    /* Message is complete, parse and dispatch. */
                    pb_istream_t stream = pb_istream_from_buffer(&pb_rx_buffer[4], msg_size);

                    /* Now we are ready to decode the message. */
                    if (pb_decode(&stream, Message_fields, message))
                    {
                        /* Success, we got a message. */
                        result = 1;
                    }
                    else
                        result = 0;

                    /* Remove message from buffer. */
                    j=0;
                    for (i=(msg_size+4); i < nb_rx_bytes; i++)
                    {
                        pb_rx_buffer[j++] = pb_rx_buffer[i];
                    }

                    /* Clear rx buffer. */
                    nb_rx_bytes = j;
                    
                    return result;
                }
            }
        }
        else
        {
        }
    }
    //else
    //    nb_rx_bytes += nb_bytes_recvd;

    return 0;
}