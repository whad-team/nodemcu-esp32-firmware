#include "inc/crypto.h"

extern adapter_t g_adapter;
uint8_t nonce[16];
uint8_t dec_pdu[256];
uint8_t pdu[256];
static uint32_t mic;
uint8_t aad;
char dbg[300];

/* Tinycrypt structures. */
struct tc_aes_key_sched_struct g_aes_key;
struct tc_ccm_mode_struct g_ccm_context;


int IRAM_ATTR encrypt_pdu(uint8_t llid, uint8_t *p_pdu, int length, uint8_t *p_output, bool b_master)
{
    aad = llid;
    int ret = 0, i;
    
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

    /* Set encryption key. */
    tc_aes128_set_encrypt_key(&g_aes_key, g_adapter.enc_key);

    /* Set AES CCM mode. */
    tc_ccm_config(
        &g_ccm_context,
        &g_aes_key,
        nonce,
        13, /* Nonce size */
        4   /* MIC size */
    );

    /* Encrypt PDU and generate MIC. */
    ret = tc_ccm_generation_encryption(
        p_output,
        256,
        &aad,
        1,
        p_pdu,
        length,
        &g_ccm_context
    );
    
    if (ret == TC_CRYPTO_SUCCESS)
    {
        if (b_master)
        {
            g_adapter.enc_master_counter++;
        }
        else
        {
            g_adapter.enc_slave_counter++;
        }

        /* Success. */
        return 0;
    }
    else
    {        
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
    aad = (header&0xe3);
    int ret = 0, i;

    if (length >= 256)
        length = 256;

    /* Init mem & copy PDU. */
    memcpy(pdu, p_pdu, length);

    //esp_rom_printf("PDU header: %02x %02x\n", (header&0xff), (header & 0xff00)>>8);

    /* Convert pdu to hex. */
    #if 0
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

    memcpy(&mic, &pdu[length-4], 4);

    /* Set encryption key. */
    tc_aes128_set_encrypt_key(&g_aes_key, g_adapter.enc_key);

    /* Set AES CCM mode. */
    tc_ccm_config(
        &g_ccm_context,
        &g_aes_key,
        nonce,
        13, /* Nonce size */
        4   /* MIC size */
    );

    #if 0
    /* Convert nonce to hex. */
    for (i=0; i<13; i++)
        snprintf(&dbg[2*i], 3, "%02x", nonce[i]);
    esp_rom_printf("Nonce : %s\n", dbg);
    esp_rom_printf("MIC: 0x%08x\n", mic);
    #endif

    ret = tc_ccm_decryption_verification(
        dec_pdu,
        256,
        &aad,
        1,
        pdu,
        length,
        &g_ccm_context
    );

    if (ret == TC_CRYPTO_SUCCESS)
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