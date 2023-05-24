#ifndef __INC_CRYPTO_H
#define __INC_CRYPTO_H

#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "inc/adapter.h"
#include "mbedtls/ccm.h"
#include "inc/tinycrypt/constants.h"
#include "inc/tinycrypt/aes.h"
#include "inc/tinycrypt/ccm_mode.h"

int encrypt_pdu(uint8_t llid, uint8_t *p_pdu, int length, uint8_t *p_output, bool b_master);
int decrypt_pdu(uint16_t header, uint8_t *p_pdu, int length, bool b_master);

#endif /* __INC_CRYPTO_H */