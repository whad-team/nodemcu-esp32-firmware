#include "inc/rxqueue.h"

/* Our RX queue buffer. */
uint8_t g_rx_queue[RX_QUEUE_SIZE];

/* Our RX queue size. */
int g_queue_size = 0;
bool g_queue_busy = false;

/* Add a PDU into our RX queue. */
int rxqueue_append_pdu(uint8_t direction, uint8_t flags, uint16_t conn_handle, uint8_t llid, uint8_t length, uint8_t *p_pdu)
{
    /* Queue is busy, drop PDU (we cannot handle it). */
    if (g_queue_busy)
        return RX_QUEUE_BUSY;

    /* First, make sure we have enough room. */
    if ((g_queue_size + length + 6) <= RX_QUEUE_SIZE)
    {
        /* Mark queue as busy to avoid IRQ concurrency. */
        g_queue_busy = true;

        /* We save direction, flags, conn_handle, llid, length first */
        g_rx_queue[g_queue_size + 0x0] = direction;
        g_rx_queue[g_queue_size + 0x1] = flags;
        g_rx_queue[g_queue_size + 0x2] = (conn_handle & 0xff);
        g_rx_queue[g_queue_size + 0x3] = (conn_handle & 0xff00) >> 8;
        g_rx_queue[g_queue_size + 0x4] = llid;
        g_rx_queue[g_queue_size + 0x5] = length & 0xff;
        memcpy(&g_rx_queue[g_queue_size + 0x6], p_pdu, length);

        /* Update size. */
        g_queue_size += length + 6;

        /* Queue is not busy anymore. */
        g_queue_busy = false;


        /* Success. */
        return RX_QUEUE_SUCCESS;
    }
    else
    {
        return RX_QUEUE_FULL;
    }
}

/* Extract a PDU from our RX queue. */
int rxqueue_poke_pdu(uint8_t *p_direction, uint8_t *p_flags, uint16_t *p_conn_handle,uint8_t *p_llid, uint8_t *p_length, uint8_t *p_pdu)
{
    uint8_t length;
    int i;

    /* If busy, returns RX_QUEUE_BUSY. */
    if (g_queue_busy)
        return RX_QUEUE_BUSY;

    /* We are now busy, plz dont interrupt. */
    g_queue_busy = true;

    /* Extract the first PDU we have. */
    if (g_queue_size > 0)
    {
        /* Make sure p_pdu buffer is big enough. */
        length = g_rx_queue[5]; /* Size is stored at offset 5. */
        if (length <= *p_length)
        {
            /* Read llid & length */
            *p_direction = g_rx_queue[0];
            *p_flags = g_rx_queue[1];
            *p_conn_handle = g_rx_queue[2] | (g_rx_queue[3] << 8);
            *p_llid = g_rx_queue[4];
            *p_length = length;

            /* Copy PDU to p_pdu. */
            memcpy(p_pdu, &g_rx_queue[6],length);

            /* Left-shift bytes. */
            length += 6;
            for (i=length; i<RX_QUEUE_SIZE; i++)
                g_rx_queue[i-length] = g_rx_queue[i];

            /* Update queue size. */
            g_queue_size -= length;
        }
        else
        {
            /* Destination buffer is not big enough. */
            g_queue_busy = false;
            return RX_QUEUE_INVALID_LENGTH;
        }
    }
    else
    {
        /* Nothing to extract, queue is empty. */
        g_queue_busy = false;
        return RX_QUEUE_EMPTY;
    }

    /* No more busy ! */
    g_queue_busy = false;
    return RX_QUEUE_SUCCESS;
}

int rxqueue_get_size(void)
{
    return g_queue_size;
}