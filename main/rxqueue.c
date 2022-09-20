#include "inc/rxqueue.h"

/* Our RX/TX queue buffers. */
uint8_t g_rx_queue[RX_QUEUE_SIZE];
uint8_t g_tx_queue[RX_QUEUE_SIZE];

/* Our RX queue size. */
int g_rx_queue_size = 0;
bool g_queue_busy = false;


void packet_queue_init(packet_queue_t *queue)
{
    /* Queue is empty and not used. */
    queue->size = 0;
    queue->busy = false;
}

/* Add a PDU into our RX queue. */
int rxqueue_append_pdu(uint8_t direction, uint8_t flags, uint16_t conn_handle, uint8_t llid, uint8_t length, uint8_t *p_pdu)
{
    /* Queue is busy, drop PDU (we cannot handle it). */
    if (g_queue_busy)
        return RX_QUEUE_BUSY;

    /* First, make sure we have enough room. */
    if ((g_rx_queue_size + length + 6) <= RX_QUEUE_SIZE)
    {
        /* Mark queue as busy to avoid IRQ concurrency. */
        g_queue_busy = true;

        /* We save direction, flags, conn_handle, llid, length first */
        g_rx_queue[g_rx_queue_size + 0x0] = direction;
        g_rx_queue[g_rx_queue_size + 0x1] = flags;
        g_rx_queue[g_rx_queue_size + 0x2] = (conn_handle & 0xff);
        g_rx_queue[g_rx_queue_size + 0x3] = (conn_handle & 0xff00) >> 8;
        g_rx_queue[g_rx_queue_size + 0x4] = llid;
        g_rx_queue[g_rx_queue_size + 0x5] = length & 0xff;
        memcpy(&g_rx_queue[g_rx_queue_size + 0x6], p_pdu, length);

        /* Update size. */
        g_rx_queue_size += length + 6;

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
int rxqueue_poke_pdu(uint8_t *p_direction, uint8_t *p_flags, uint16_t *p_conn_handle, uint8_t *p_llid, uint8_t *p_length, uint8_t *p_pdu)
{
    uint8_t length;
    int i;

    /* If busy, returns RX_QUEUE_BUSY. */
    if (g_queue_busy)
        return RX_QUEUE_BUSY;

    /* We are now busy, plz dont interrupt. */
    g_queue_busy = true;

    /* Extract the first PDU we have. */
    if (g_rx_queue_size > 0)
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
            g_rx_queue_size -= length;
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
    return g_rx_queue_size;
}


int packet_queue_pop(
    packet_queue_t *queue, uint8_t *p_direction,
    uint8_t *p_flags, uint16_t *p_conn_handle, uint8_t *p_llid,
    uint8_t *p_length, uint8_t *p_pdu
)
{
    uint8_t length;
    int i;

    /* If busy, returns RX_QUEUE_BUSY. */
    if (queue->busy)
        return RX_QUEUE_BUSY;

    /* We are now busy, plz dont interrupt. */
    queue->busy = true;

    /* Extract the first PDU we have. */
    if (queue->size > 0)
    {
        /* Make sure p_pdu buffer is big enough. */
        length = queue->buffer[5]; /* Size is stored at offset 5. */
        if (length <= *p_length)
        {
            /* Read llid & length */
            *p_direction = queue->buffer[0];
            *p_flags = queue->buffer[1];
            *p_conn_handle = queue->buffer[2] | (queue->buffer[3] << 8);
            *p_llid = queue->buffer[4];
            *p_length = length;

            /* Copy PDU to p_pdu. */
            memcpy(p_pdu, &queue->buffer[6],length);

            /* Left-shift bytes. */
            length += 6;
            for (i=length; i<RX_QUEUE_SIZE; i++)
                queue->buffer[i-length] = queue->buffer[i];

            /* Update queue size. */
            queue->size -= length;
        }
        else
        {
            queue->busy = false;
            return RX_QUEUE_INVALID_LENGTH;
        }
    }
    else
    {
        /* Nothing to extract, queue is empty. */
        queue->busy = false;
        return RX_QUEUE_EMPTY;
    }

    /* No more busy ! */
    queue->busy = false;
    return RX_QUEUE_SUCCESS;
}

int packet_queue_append(
    packet_queue_t *queue,
    uint8_t direction,
    uint8_t flags,
    uint16_t conn_handle,
    uint8_t llid,
    uint8_t length,
    uint8_t *p_pdu
)
{
    /* Queue is busy, drop PDU (we cannot handle it). */
    if (queue->busy)
        return RX_QUEUE_BUSY;

    /* First, make sure we have enough room. */
    if ((queue->size + length + 6) <= RX_QUEUE_SIZE)
    {
        /* Mark queue as busy to avoid IRQ concurrency. */
        queue->busy = true;

        /* We save direction, flags, conn_handle, llid, length first */
        queue->buffer[queue->size + 0x0] = direction;
        queue->buffer[queue->size + 0x1] = flags;
        queue->buffer[queue->size + 0x2] = (conn_handle & 0xff);
        queue->buffer[queue->size + 0x3] = (conn_handle & 0xff00) >> 8;
        queue->buffer[queue->size + 0x4] = llid;
        queue->buffer[queue->size + 0x5] = length & 0xff;
        memcpy(&queue->buffer[queue->size + 0x6], p_pdu, length);

        /* Update size. */
        queue->size += length + 6;

        /* Queue is not busy anymore. */
        queue->busy = false;


        /* Success. */
        return RX_QUEUE_SUCCESS;
    }
    else
    {
        return RX_QUEUE_FULL;
    }
}