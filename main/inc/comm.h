#ifndef COMM_INC_H
#define COMM_INC_H

#include "esp_log.h"
#include "driver/uart.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/whad.pb.h"

#define BUF_SIZE (1024)

void reconfigure_uart(void);
void send_pb_message(const void *src_struct);
int receive_pb_message(Message *message);

#endif /* COMM_INC_H */