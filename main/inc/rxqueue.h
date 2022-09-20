#ifndef __INC_QUEUE_H
#define __INC_QUEUE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"

#define RX_QUEUE_SIZE       4096
#define RX_QUEUE_FULL       -1
#define RX_QUEUE_EMPTY      -2
#define RX_QUEUE_BUSY       -3
#define RX_QUEUE_INVALID_LENGTH -4
#define RX_QUEUE_SUCCESS    0

#define RX_QUEUE_FLAG_PROCESSED 1
#define RX_QUEUE_FLAG_DECRYPTED 2
#define RX_QUEUE_FLAG_ENCRYPTED 4

typedef struct t_pckt_queue {
    uint8_t buffer[RX_QUEUE_SIZE];
    int size;
    bool busy;
} packet_queue_t;

void packet_queue_init(packet_queue_t *queue);

/* Add a PDU into our RX queue. */
int rxqueue_append_pdu(uint8_t direction, uint8_t flags, uint16_t conn_handle, uint8_t llid, uint8_t length, uint8_t *p_pdu);

int packet_queue_append(
    packet_queue_t *queue,
    uint8_t direction,
    uint8_t flags,
    uint16_t conn_handle,
    uint8_t llid,
    uint8_t length,
    uint8_t *p_pdu
);

/* Extract a PDU from our RX queue. */
int rxqueue_poke_pdu(uint8_t *p_direction, uint8_t *p_flags, uint16_t *p_conn_handle,uint8_t *p_llid, uint8_t *p_length, uint8_t *p_pdu);

int packet_queue_pop(
    packet_queue_t *queue,
    uint8_t *p_direction,
    uint8_t *p_flags,
    uint16_t *p_conn_handle,
    uint8_t *p_llid,
    uint8_t *p_length,
    uint8_t *p_pdu
);

/* Get queue size. */
int rxqueue_get_size(void);

#endif /* __INC_QUEUE_H */