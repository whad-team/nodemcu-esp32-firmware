#ifndef COMM_INC_H
#define COMM_INC_H

#include "esp_log.h"
#include "driver/uart.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/whad.pb.h"

#define BUF_SIZE (1024)

esp_err_t reconfigure_uart(int speed, bool reinstall_driver);
void send_pb_message(const void *src_struct);
void pending_pb_message(const void *src_struct);
void flush_pending_pb_messages(void);
int receive_pb_message(Message *message);

#endif /* COMM_INC_H */