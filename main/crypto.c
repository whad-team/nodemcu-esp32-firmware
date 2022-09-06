#include "inc/crypto.h"

extern adapter_t g_adapter;

int IRAM_ATTR encrypt_pdu(uint8_t llid, uint8_t *p_pdu, int length, uint8_t *p_output, bool b_master)
{
    uint8_t nonce[13];
    uint8_t enc_pdu[256];
    uint32_t mic;
    uint8_t aad = llid;
    int ret = 0, i;
    char dbg[256];
    
    /* Generate nonce */
    if (b_master)
    {
        /**
         * Copy packet counter. Counter is supposed to be on 39 bits, but we
         * are only copying 32 bits because we're lazy. Hope a connection won't
         * send billions of packets ...
         */
        memcpy(&nonce[0], &g_adapter.enc_master_counter, 4);
        nonce[4] = 0x80; /* Master counter used */
        memcpy(&nonce[5], g_adapter.enc_iv, 8);
    }
    else
    {
        /**
         * Copy packet counter. Counter is supposed to be on 39 bits, but we
         * are only copying 32 bits because we're lazy. Hope a connection won't
         * send billions of packets ...
         */
        memcpy(&nonce[0], &g_adapter.enc_slave_counter, 4);
        nonce[4] = 0x00; /* Slave counter used */
        memcpy(&nonce[5], g_adapter.enc_iv, 8);        
    }

    /* Initialize context. */
    //mbedtls_ccm_init(&g_adapter.enc_context);

    /* Set AES key */
    //mbedtls_ccm_setkey(&g_adapter.enc_context, MBEDTLS_CIPHER_ID_AES, g_adapter.enc_key, 128);
    
    #if 0
    /* Show plaintext PDU. */
    for (i=0; i<length; i++)
    {
        snprintf(&dbg[i*2], 3, "%02x", p_pdu[i]);
    }
    esp_rom_printf("Plaintext PDU: %s\n", dbg);
    #endif

    /* Encrypt PDU and generate MIC. */
    ret = mbedtls_ccm_encrypt_and_tag(
        &g_adapter.enc_context,
        length,
        nonce,
        13,
        &aad,
        1,
        p_pdu,
        p_output,
        &p_output[length],
        4
    );
 
    #if 0
    /* Show input after encryption. */
    for (i=0; i<length; i++)
    {
        snprintf(&dbg[i*2], 3, "%02x", p_pdu[i]);
    }
    esp_rom_printf("Plaintext PDU after enc.: %s\n", dbg);
    

    /* Show encrypted. */
    for (i=0; i<length+4; i++)
        snprintf(&dbg[i*2], 3, "%02x", p_output[i]);
    esp_rom_printf("Enc PDU: %s\n", dbg);
    #endif

    /* Free context. */
    //mbedtls_ccm_free(&g_adapter.enc_context);

    if (ret == 0)
    {
        //dbg_txt("Encryption succeeded !");
        if (b_master)
        {
            g_adapter.enc_master_counter++;
            //dbg_txt("enc pkt master count: %d", g_adapter.enc_master_counter);
        }
        else
        {
            g_adapter.enc_slave_counter++;
            //dbg_txt("enc pkt slave count: %d", g_adapter.enc_slave_counter);
        }

        /* Success. */
        return 0;
    }
    else
    {
        //dbg_txt_rom("Error while encrypting packet (%d)", ret);
        
        /* Error. */
        return 1;
    }

    return 0;
}

/**
 * @brief Decrypt PDU
 * 
 * @param header Data LL header
 * @param p_pdu pointer to the PDU payload to decrypt
 * @param length length of payload
 * @param b_master true if PDU comes from a Central device, false otherwise
 * @return int 0 on success, 1 on error
 */
int IRAM_ATTR decrypt_pdu(uint16_t header, uint8_t *p_pdu, int length, bool b_master)
{
    uint8_t nonce[16];
    uint8_t dec_pdu[256];
    uint8_t pdu[256];
    uint32_t mic;
    uint8_t aad = (header&0xe3);
    int ret = 0, i;

    char dbg[300];

    /* Init mem & copy PDU. */
    //memset(pdu, 0, 256);
    memcpy(pdu, p_pdu, length);

    #if 0
    esp_rom_printf("PDU header: %02x %02x\n", (header&0xff), (header & 0xff00)>>8);

    /* Convert pdu to hex. */
    for (i=0; i<length; i++)
        snprintf(&dbg[2*i], 3, "%02x", p_pdu[i]);
    esp_rom_printf("Enc. PDU: %s\n", dbg);
    #endif

    /* Generate nonce */
    if (b_master)
    {
        /**
         * Copy packet counter. Counter is supposed to be on 39 bits, but we
         * are only copying 32 bits because we're lazy. Hope a connection won't
         * send billions of packets ...
         */
        memcpy(&nonce[0], &g_adapter.enc_master_counter, 4);
        nonce[4] = 0x80; /* Master counter used */
        memcpy(&nonce[5], g_adapter.enc_iv, 8);
    }
    else
    {
        /**
         * Copy packet counter. Counter is supposed to be on 39 bits, but we
         * are only copying 32 bits because we're lazy. Hope a connection won't
         * send billions of packets ...
         */
        memcpy(&nonce[0], &g_adapter.enc_slave_counter, 4);
        nonce[4] = 0x00; /* Slave counter used */
        memcpy(&nonce[5], g_adapter.enc_iv, 8);        
    }

    #if 0
    /* Convert nonce to hex. */
    for (i=0; i<13; i++)
        snprintf(&dbg[2*i], 3, "%02x", nonce[i]);
    esp_rom_printf("Nonce : %s\n", dbg);
    #endif


    #if 0
    /* Initialize context. */
    mbedtls_ccm_init(&g_adapter.enc_context);

    /* Set AES key */
    mbedtls_ccm_setkey(&g_adapter.enc_context, MBEDTLS_CIPHER_ID_AES, g_adapter.enc_key, 128);
    #endif

    ret= mbedtls_ccm_auth_decrypt(
        &g_adapter.enc_context,
        length-4,
        nonce,
        13,
        &aad,
        1,
        pdu,
        dec_pdu,
        &pdu[length-4],
        4
    );

    if (ret == 0)
    {
        //dbg_txt_rom("Decryption succeeded !");
        //esp_rom_printf("Decryption succeeded !\n");

        /* Increment counter. */
        if (b_master)
        {
            g_adapter.enc_master_counter++;
            //esp_rom_printf("pkt master count: %d\n", g_adapter.enc_master_counter);
        }
        else
        {
            g_adapter.enc_slave_counter++;
            //esp_rom_printf("pkt slave count: %d\n", g_adapter.enc_slave_counter);
        }
        
        /* Copy decrypted pdu into original one. */
        memcpy(p_pdu, dec_pdu, length-4);

        /* Free context. */
        //mbedtls_ccm_free(&g_adapter.enc_context);

        /* Success. */
        return 0;
    }
    else
    {
        //esp_rom_printf("Error while decrypting packet (%d)\n", ret);
        #if 0
        if (b_master)
        {
            esp_rom_printf("pkt master count: %d\n", g_adapter.enc_master_counter);
        }
        else
        {
            esp_rom_printf("pkt slave count: %d\n", g_adapter.enc_slave_counter);
        }
        #endif

        /* Free context. */
        //mbedtls_ccm_free(&g_adapter.enc_context);

        /* Error. */
        return 1;
    }
}