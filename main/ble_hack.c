#include "inc/ble_hack.h"
#include "inc/helpers.h"
#include "esp_bt.h"

/* Callback functions. */
FBLEHACK_IsrCallback gpfn_on_rx_data_pdu = NULL;
FBLEHACK_IsrCallback gpfn_on_rx_control_pdu = NULL;
FBLEHACK_IsrCallback gpfn_on_tx_data_pdu = NULL;
FBLEHACK_CtlCallback gpfn_on_tx_control_pdu = NULL;

/* Global bluetooth platform log level */
extern int g_bt_plf_log_level;

/* RX buffer free function. */
extern uint16_t r_em_buf_rx_free(uint32_t desc);

extern void bb_wdt_int_enable(bool enable);

/* Rx handler hooking (ISR). */
uint8_t *p_rx_buffer = (uint8_t *)(BLE_RX_BUFFER_ADDR);
typedef int (*F_lld_pdu_rx_handler)(int param_1,int param_2);
F_lld_pdu_rx_handler pfn_lld_pdu_rx_handler = NULL;

/* Hook r_lld_data_send() */
typedef int (*F_r_lld_pdu_data_send)(struct hci_acl_data_tx *param);
F_r_lld_pdu_data_send pfn_lld_pdu_data_send = NULL;

/* Hook r_lld_pdu_tx_prog(struct lld_evt_tag *evt) */
typedef int (*F_r_lld_pdu_tx_prog)(struct lld_evt_tag *evt);
F_r_lld_pdu_tx_prog pfn_lld_pdu_tx_prog = NULL;
struct llcp_pdu_tag *g_prev_llcp = NULL;

/* Hook r_lld_pdu_data_tx_push(struct lld_evt_tag *evt, struct em_desc_node *txnode, bool can_be_freed, bool encrypted) */
typedef int (*F_r_lld_pdu_data_tx_push)(struct lld_evt_tag *evt, struct em_desc_node *txnode, bool can_be_freed);
F_r_lld_pdu_data_tx_push pfn_lld_pdu_data_tx_push = NULL;

F_rom_llc_llcp_send pfn_rom_llc_llcp_send = (void*)(0x40043ed4);

volatile bool gb_busy = false;

/* TODO */

/* Declare LLCP original function types and global pointers */
ROM_HOOK(llc_llcp_version_ind_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_ch_map_update_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_pause_enc_req_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_pause_enc_rsp_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_enc_req_pdu_send, uint16_t conhdl, struct hci_le_start_enc_cmd *param)
ROM_HOOK(llc_llcp_enc_rsp_pdu_send, uint16_t conhdl, struct llcp_enc_req *param)
ROM_HOOK(llc_llcp_start_enc_rsp_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_reject_ind_pdu_send, uint16_t conhdl, uint8_t rej_opcode, uint8_t reason)
ROM_HOOK(llc_llcp_con_update_pdu_send, uint16_t conhdl, struct llcp_con_upd_ind *param)
ROM_HOOK(llc_llcp_con_param_req_pdu_send, uint16_t conhdl, struct llc_con_upd_req_ind *param)
ROM_HOOK(llc_llcp_con_param_rsp_pdu_send, uint16_t conhdl, struct llc_con_upd_req_ind *param)
ROM_HOOK(llc_llcp_feats_req_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_feats_rsp_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_start_enc_req_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_terminate_ind_pdu_send, uint16_t conhdl, uint8_t err_code)
ROM_HOOK(llc_llcp_unknown_rsp_send_pdu, uint16_t conhdl, uint8_t unk_type)
ROM_HOOK(llc_llcp_ping_req_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_ping_rsp_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_length_req_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_length_rsp_pdu_send, uint16_t conhdl)
ROM_HOOK(llc_llcp_tester_send, uint8_t conhdl, uint8_t length, uint8_t *data)

/* External BLE controller callback functions structure. */
extern void *r_btdm_option_data[1548];
void *g_ip_funcs_p = (void *)(IP_FUNCS_ARRAY_ADDR);
extern void **r_ip_funcs_p[981];
extern void **r_modules_funcs_p[100];

extern struct em_buf_env_tag em_buf_env;
struct co_list *gp_tx_prog = NULL;
//struct lld_evt_tag *gp_evt = NULL;
extern struct lld_evt_tag lld_evt_env;
struct em_desc_node* pkt = NULL;
//uint32_t *p_llc_env = (uint32_t*)(LLC_ENV_ADDR);
extern uint32_t *llc_env[10];

/* Give access to llc_llcp_send() ROM function. */
typedef int (*F_llc_llcp_send)(uint8_t conhdl, void *param, uint8_t opcode);
F_llc_llcp_send llc_llcp_send = (F_llc_llcp_send)(LLC_LLCP_SEND_ADDR);

typedef void (*F_llc_llcp_tester_send)(uint8_t conhdl, uint8_t length, uint8_t *data);
F_llc_llcp_tester_send llc_llcp_tester_send = (F_llc_llcp_send)(LLC_LLCP_TESTER_SEND_ADDR);

extern uint32_t r_llc_util_get_nb_active_link(void);

extern void r_em_buf_tx_free(struct em_buf_node *node);

void disable_interrupts(void)
{
    portDISABLE_INTERRUPTS();
    esp_rom_printf("Interrupts disabled\n");
}

void enable_interrupts(void)
{
    portENABLE_INTERRUPTS();
    esp_rom_printf("Interrupts enabled\n");
}

/**
 * co_list_is_empty()
 * 
 * Checks if a co_list structure is empty.
 **/

bool co_list_is_empty(const struct co_list *const list)
{
    bool listempty;
    listempty = (list->first == NULL);
    return (listempty);
}


/**
 * co_list_pop_front()
 * 
 * Pops the first item of the list, return NULL if any.
 **/

struct co_list_hdr *co_list_pop_front(struct co_list *list)
{
    struct co_list_hdr *element;

    // check if list is empty
    element = list->first;
    if (element != NULL)
    {

        // The list isn't empty : extract the first element
        list->first = list->first->next;

        if(list->first == NULL)
        {
            list->last = list->first;
        }

        list->cnt--;
        if(list->mincnt > list->cnt)
        {
            list->mincnt = list->cnt;
        }
    }
    return element;
}


/**
 * co_list_push_back()
 * 
 * Appends an item at the end of a given list.
 **/

void co_list_push_back(struct co_list *list,
                       struct co_list_hdr *list_hdr)
{
    // check if list is empty
    if (co_list_is_empty(list))
    {
        // list empty => pushed element is also head
        list->first = list_hdr;
    }
    else
    {
        // list not empty => update next of last
        list->last->next = list_hdr;
    }

    // add element at the end of the list
    list->last = list_hdr;
    list_hdr->next = NULL;

    list->cnt++;
    if(list->maxcnt < list->cnt)
    {
        list->maxcnt = list->cnt;
    }
}

void set_packet_length(int packet_num, uint8_t length)
{
    pkt_hdr_t *p_header = (pkt_hdr_t *)(BLE_RX_PKT_HDR_ADDR);
    uint32_t pkt_header;
    
    /* Read packet header from fifo header (located at 0x3ffb094c). */
    pkt_header = p_header[packet_num].header;

    /* Update length. */
    pkt_header = (pkt_header & 0xffff00ff) | ((length)<<8);

    /* Overwrite header. */
    p_header[packet_num].header = pkt_header;
}

/**
 * _lld_pdu_rx_handler()
 * 
 * Hook for r_lld_pdu_rx_handler(), called each time a BLE packet (header + PDU) is received.
 **/

int IRAM_ATTR _lld_pdu_rx_handler(int param_1,int param_2)
{
  int forward = HOOK_FORWARD;
  uint16_t *p_offset;
  uint8_t fifo_index;
  uint32_t pkt_header;
  uint8_t *p_pdu;
  int channel;
  int pkt_size;
  int rssi;
  int nb_links;
  pkt_hdr_t *p_header = (pkt_hdr_t *)(BLE_RX_PKT_HDR_ADDR);
  uint16_t pkt_status = *(uint16_t *)(BLE_RX_PKT_STATUS);
  int res;
  int i,j,k;
  int skipped = 0;
  #ifdef BLE_HACK_DEBUG
  int i,j,k;
  #endif

  esp_packet_processed_t packets[8];
  int proc_pkt_idx = 0;

  /**
   * If we are called with multiple packets, we need to temporarily allocate
   * memory to reorder packets and put the forwarded ones to the end. So first
   * we call our hooks, then we rewrite the RX descriptors and some internal
   * structures and eventually return to the normal execution flow. 
   */

  esp_rom_printf("param1: 0x%08x, param2: %d\n", (uint32_t)param_1, param_2);

    
  /* We retrieve the fifo index from memory. */
  fifo_index = ((uint8_t *)BLE_RX_CUR_FIFO_ADDR)[0x5c8];

  /* 0. If we don't have any packet to process, just forward. */
  if ((param_2 == 0) || ((pkt_status & 0x13f) != 0))
  {
    /* Re-enable interrupts. */
    //portENABLE_INTERRUPTS();

    /* Forward to original function. */
    esp_rom_printf("forward 1\n");
    return pfn_lld_pdu_rx_handler(param_1, param_2);
  }

  /* BLE_RX_DESC_ADDR -> array of 12-byte items, the first 2 are offsets. */
  /* p_rx_buffer -> BLE RX/TX shared memory. */

  if ((*((uint8_t *)param_1 + 0x72) & 0x10) == 0)
  {
    if (r_llc_util_get_nb_active_link() > 0)
    {
        esp_rom_printf("Current SW FIFO index: %d\n", *((uint32_t *)(0x3ffb933c)));

        /* 1. We parse all the packets and moved them into dynamically allocated structures. */

        for (k=0; k<param_2; k++)
        {
            j = (fifo_index + k) % 8;

            /* Read packet header from fifo header (located at 0x3ffb094c). */
            pkt_header = p_header[j].header;
            
            /* Extract channel, rssi and packet size. */
            channel = (pkt_header>>24);
            rssi = (pkt_header>>16) & 0xff;
            pkt_size = (pkt_header >> 8) & 0xff;

            /* Fill current RX packet. */
            packets[proc_pkt_idx].b_forward = false;
            packets[proc_pkt_idx].header = pkt_header;
            packets[proc_pkt_idx].length = pkt_size;

            if (pkt_size > 0)
            {
                packets[proc_pkt_idx].pdu = (uint8_t*)malloc(pkt_size);
                if (packets[proc_pkt_idx].pdu != NULL)
                {
                    /* Copy PDU into RAM. */
                    p_offset = (uint16_t *)(BLE_RX_DESC_ADDR + 12*j);
                    p_pdu = (uint8_t *)(p_rx_buffer + *p_offset);
                    memcpy(packets[proc_pkt_idx].pdu, p_pdu, pkt_size);

                    /* Call our hook (if any) in case of a control PDU. */
                    if ((pkt_header & 0x03) == 0x3)
                    {
                        if (gpfn_on_rx_control_pdu != NULL)
                        {
                            esp_rom_printf("call rx ctl handler\n");
                            forward = gpfn_on_rx_control_pdu(
                                j,
                                (uint16_t)(pkt_header & 0xffff),
                                packets[proc_pkt_idx].pdu,
                                pkt_size
                            );

                            /* Should we forward this packet ? */
                            packets[proc_pkt_idx].b_forward = (forward == HOOK_FORWARD);
                            if (!packets[proc_pkt_idx].b_forward)
                            {
                                esp_rom_printf("rx ctl must be skipped\n");
                            }
                        }
                    }
                    
                    /* Or call our other hook (if any) in case of a data PDU. */
                    else if ((pkt_header & 0x03) != 0)
                    {
                        if (gpfn_on_rx_data_pdu != NULL)
                        {
                            esp_rom_printf("call rx data handler\n");
                            forward = gpfn_on_rx_data_pdu(
                                j,
                                (uint16_t)(pkt_header & 0xffff),
                                packets[proc_pkt_idx].pdu,
                                pkt_size
                            );

                            /* Should we forward this packet ? */
                            packets[proc_pkt_idx].b_forward = (forward == HOOK_FORWARD);
                            if (!packets[proc_pkt_idx].b_forward)
                            {
                                esp_rom_printf("rx data must be skipped\n");
                            }
                        }
                    }
                }
                else
                {
                    /* Allocation error. */
                    esp_rom_printf("[rx hook] cannot allocate memory\n");
                }
            }
            else
            {
                esp_rom_printf("got empty packet\n");
                packets[proc_pkt_idx].pdu = NULL;
            }

            /* Increment rx pkt index. */
            proc_pkt_idx++;
        }

        /* 2. Ok, now we have a list of `proc_pkt_idx` processed packets, and we need to
        * write them back into ESP32 FIFOs. The main idea is to count the number of skipped
        * packets, increment DWORD @0x3ffb933c used by ESP32-WROOM to keep the current
        * RX FIFO index for every skipped packet, and rewrite the forwarded packets into
        * the last RX FIFOs.
        **/
        for (i=0; i<proc_pkt_idx; i++)
        {
            if (!packets[i].b_forward)
            {
                skipped++;
                *((uint32_t *)(0x3ffb933c)) += 1;
            }
        }
        esp_rom_printf("skipping %d packets\n", skipped);

        /* 3. Rewrite the PDUs in the correct RX FIFOs headers and buffers. */
        for (i=0; i<proc_pkt_idx; i++)
        {
            j = (fifo_index + i + skipped) % 8;

            if (packets[i].b_forward)
            {
                /* Update header. */
                p_header[j].header = packets[i].header;

                /* Retrieve a pointer to the corresponding FIFO PDU buffer. */
                p_offset = (uint16_t *)(BLE_RX_DESC_ADDR + 12*j);
                p_pdu = (uint8_t *)(p_rx_buffer + *p_offset);

                /* Copy packet content and free. */
                if (packets[i].pdu != NULL)
                {
                    memcpy(p_pdu, packets[i].pdu, packets[i].length);
                    free(packets[i].pdu);
                }
            }
        }
    }
    else
    {
        /* Forward to original function. */
    esp_rom_printf("forward 2\n");
    return pfn_lld_pdu_rx_handler(param_1, param_2);
    }
  }

  /* Current fifo debug. */
  esp_rom_printf("Current SW FIFO index: %d\n", *((uint32_t *)(0x3ffb933c)));
  esp_rom_printf("Current HW FIFO index: %d\n", fifo_index);

  /* Forward to original handler. */
  esp_rom_printf("Forward to orig handler with %d packets\n", param_2 - skipped);
  return pfn_lld_pdu_rx_handler(param_1, param_2 - skipped);
}


/**
 * _lld_pdu_tx_prog()
 * 
 * This hook is called during each connection event to handle pending BLE PDUs
 * (data PDU + control PDU).
 **/

int _lld_pdu_tx_prog(struct lld_evt_tag *evt)
{
  int res;
  struct co_list_hdr *item;
  //struct llcp_pdu_tag *node;
  struct llcp_pdu_tag *node;

  /* Parse ready to send packet descriptors. */
  //item = (struct co_list_hdr *)evt->tx_llcp_pdu_rdy.first;
  item = (struct co_list_hdr *)evt->tx_acl_tofree.first;

  while (item != NULL)
  {
    node = (struct llcp_pdu_tag *)item;
    //dbg_txt_rom("item: 0x%08x, llid=%02x length=%d", (uint32_t)item, node->opcode, node->pdu_length&0xff);
    //dbg_txt_rom("item: 0x%08x", (uint32_t)item);
    item = (struct co_list_hdr *)item->next;
  }

  /* Call tx prog. */
  res = pfn_lld_pdu_tx_prog(evt);
  return res;
}


/**
 * _lld_pdu_data_tx_push()
 * 
 * This hook is called during each connection event to handle pending BLE PDUs
 * (data PDU + control PDU).
 **/

int _lld_pdu_data_tx_push(struct lld_evt_tag *evt, struct em_desc_node *txnode, bool can_be_freed)
{
  int res;
  char dbghex[1024];
  uint8_t *p_buf = (uint8_t *)(p_rx_buffer + txnode->buffer_ptr);

  dbg_txt_rom("evt: 0x%08x", evt);
  dbg_txt_rom("txnode->llid=0x%02x, txnode->length=%d, txnode->buf_idx=%d, txnode->buf_ptr=0x%08x",
  txnode->llid,
  txnode->length,
  txnode->buffer_idx,
  txnode->buffer_ptr);

#if 0  
  /* This is for ESP32_WROOM32 only */
  uint32_t *p_evt = (uint32_t *)(*(uint32_t*)((uint32_t)llc_env[0]+0x10) + 0x28);
  int res;

  for (int i=0;i<txnode->length;i++)
    snprintf(&dbghex[2*i], 3, "%02x", p_buf[i]);
  dbghex[2*txnode->length] = '\0';
  
  /* Notify LLID, length and PDU from txnode. */
  dbg_txt_rom("txnode evt:0x%08x llid:0x%02x length:%d buf: %s (freed:%d)", evt, txnode->llid, txnode->length, dbghex, can_be_freed);
#endif

  if (gpfn_on_tx_data_pdu != NULL)
  {
    /* Should we block this data PDU ? */
    if (gpfn_on_tx_data_pdu(-1, txnode->llid | (txnode->length << 8), p_buf, txnode->length) == HOOK_BLOCK)
    {
      /* Set TX buffer length to zero (won't be transmitted, but will be freed later. */
      txnode->length = 0;
    }
  }

  /* Call data tx push. */
  res = pfn_lld_pdu_data_tx_push(evt, txnode, can_be_freed);
  return res;
}


/*********************************************
 * Link-layer Control Procedures hooks
 ********************************************/

void _llc_llcp_version_ind_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_version_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_version_ind_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_VERSION_IND;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_version_ind_pdu_send)(conhdl);
}

void _llc_llcp_ch_map_update_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_ch_map_update_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_ch_map_update_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_CHANNEL_MAP_REQ;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_ch_map_update_pdu_send)(conhdl); 
}

void _llc_llcp_pause_enc_req_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_pause_enc_req_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_pause_enc_req_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_PAUSE_ENC_REQ;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_pause_enc_req_pdu_send)(conhdl);   
}

void _llc_llcp_pause_enc_rsp_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_pause_enc_rsp_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_pause_enc_rsp_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_PAUSE_ENC_RSP;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_pause_enc_rsp_pdu_send)(conhdl);  
}

void _llc_llcp_enc_req_pdu_send(uint16_t conhdl, struct hci_le_start_enc_cmd *param)
{
  int forward = HOOK_FORWARD;
  llcp_enc_req_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_enc_req_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_ENC_REQ;
    params.header.conhdl = conhdl;
    params.param = param;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_enc_req_pdu_send)(conhdl, param);  
}

void _llc_llcp_enc_rsp_pdu_send(uint16_t conhdl, struct llcp_enc_req *param)
{
  int forward = HOOK_FORWARD;
  llcp_enc_rsp_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_enc_rsp_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_ENC_RSP;
    params.header.conhdl = conhdl;
    params.param = param;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_enc_rsp_pdu_send)(conhdl, param);  
}

void _llc_llcp_start_enc_rsp_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_start_enc_rsp_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_start_enc_rsp_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_START_ENC_RSP;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_start_enc_rsp_pdu_send)(conhdl); 
}

void _llc_llcp_reject_ind_pdu_send(uint16_t conhdl, uint8_t rej_opcode, uint8_t reason)
{
  int forward = HOOK_FORWARD;
  llcp_reject_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_reject_ind_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_REJECT_IND;
    params.header.conhdl = conhdl;
    params.rej_opcode = rej_opcode;
    params.reason = reason;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_reject_ind_pdu_send)(conhdl, rej_opcode, reason);  
}


void _llc_llcp_con_update_pdu_send(uint16_t conhdl, struct llcp_con_upd_ind *param)
{
  int forward = HOOK_FORWARD;
  llcp_con_update_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_con_update_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_CONNECTION_UPDATE_REQ;
    params.header.conhdl = conhdl;
    params.param = param;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_con_update_pdu_send)(conhdl, param);  
}

void _llc_llcp_con_param_req_pdu_send(uint16_t conhdl, struct llc_con_upd_req_ind *param)
{
  int forward = HOOK_FORWARD;
  llcp_con_param_req_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_con_param_req_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_CONNECTION_PARAM_REQ;
    params.header.conhdl = conhdl;
    params.param = param;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_con_param_req_pdu_send)(conhdl, param);
}

void _llc_llcp_con_param_rsp_pdu_send(uint16_t conhdl, struct llc_con_upd_req_ind *param)
{
  int forward = HOOK_FORWARD;
  llcp_con_param_rsp_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_con_param_rsp_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_CONNECTION_PARAM_RSP;
    params.header.conhdl = conhdl;
    params.param = param;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_con_param_rsp_pdu_send)(conhdl, param);
}

int _llc_llcp_feats_req_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_feats_req_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_feats_req_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_FEATURE_REQ;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_feats_req_pdu_send)(conhdl);

 return conhdl;
}

void _llc_llcp_feats_rsp_pdu_send(uint32_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_feats_rsp_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_feats_rsp_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_FEATURE_RSP;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_feats_rsp_pdu_send)(conhdl);
}

void _llc_llcp_start_enc_req_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_start_enc_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_start_enc_req_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_START_ENC_REQ;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_start_enc_req_pdu_send)(conhdl); 
}

void _llc_llcp_terminate_ind_pdu_send(uint16_t conhdl, uint8_t err_code)
{
  int forward = HOOK_FORWARD;
  llcp_terminate_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_terminate_ind_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_TERMINATE_IND;
    params.header.conhdl = conhdl;
    params.err_code = err_code;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_terminate_ind_pdu_send)(conhdl, err_code); 
}

void _llc_llcp_unknown_rsp_send_pdu(uint16_t conhdl, uint8_t unk_type)
{
  int forward = HOOK_FORWARD;
  llcp_unknown_rsp_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_unknown_rsp_send_pdu() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_UNKNOWN_RSP;
    params.header.conhdl = conhdl;
    params.unk_type = unk_type;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_unknown_rsp_send_pdu)(conhdl, unk_type);   
}

void _llc_llcp_ping_req_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_ping_req_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_ping_req_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_PING_REQ;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_ping_req_pdu_send)(conhdl);    
}

void _llc_llcp_ping_rsp_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_ping_rsp_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_ping_rsp_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_PING_RSP;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_ping_rsp_pdu_send)(conhdl);    
}

void _llc_llcp_length_req_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_length_req_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_length_req_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_LENGTH_REQ;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_length_req_pdu_send)(conhdl);   
}

void _llc_llcp_length_rsp_pdu_send(uint16_t conhdl)
{
  int forward = HOOK_FORWARD;
  llcp_length_req_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_length_rsp_pdu_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_LENGTH_RSP;
    params.header.conhdl = conhdl;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_length_rsp_pdu_send)(conhdl);   
}

void _llc_llcp_tester_send(uint8_t conhdl, uint8_t length, uint8_t *data)
{
  int forward = HOOK_FORWARD;
  llcp_tester_send_params params;

  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("llc_llcp_tester_send() called\r\n");
  #endif

  if (gpfn_on_tx_control_pdu != NULL)
  {
    params.header.opcode = LL_TESTER_SEND;
    params.header.conhdl = conhdl;
    params.length = length;
    params.data = data;
    forward = gpfn_on_tx_control_pdu((llcp_opinfo *)&params);
  }

  if (forward == HOOK_FORWARD)
    HOOKFUNCPTR(llc_llcp_tester_send)(conhdl, length, data); 
}

/**
 * _lld_pdu_data_send()
 * 
 * This hook is called whenever the BLE stack sends a data PDU.
 **/

int _lld_pdu_data_send(struct hci_acl_data_tx *param)
{
  struct em_buf_tx_desc *p_desc = NULL;
  uint8_t *ptr_data;
  int i, forward=HOOK_FORWARD;
  struct co_list_hdr *tx_desc;
  struct em_desc_node *tx_node;
  
  #ifdef BLE_HACK_DEBUG
  esp_rom_printf("lld_pdu_data_send:\r\n");
  esp_rom_printf("  conn_handle: %d\r\n", param->conhdl);
  esp_rom_printf("  bufsize: %d\r\n", param->length);
  esp_rom_printf("  buffer->idx: %d\r\n", param->buf->idx);
  esp_rom_printf("  buffer->ptr: 0x%08x\r\n", param->buf->buf_ptr);
  esp_rom_printf("  buffer: 0x%08x\r\n", param->buf);
  esp_rom_printf(">> ");
  for (i=0; i<param->length; i++)
    {
      esp_rom_printf("%02x", ((uint8_t *)(p_rx_buffer + param->buf->buf_ptr))[i]);
    }
  esp_rom_printf("\r\n");
  #endif
  
  #if 0
  if (gpfn_on_tx_data_pdu != NULL)
  {
    /* Should we block this data PDU ? */
    if (gpfn_on_tx_data_pdu(0, (uint8_t *)(p_rx_buffer + param->buf->buf_ptr), param->length) == HOOK_BLOCK)
    {
      /* Set TX buffer length to zero (won't be transmitted, but will be freed later. */
      param->length = 0;
    }
  }
  #endif

  return pfn_lld_pdu_data_send(param);
}


/**
 * em_buf_tx_alloc()
 * 
 * Copy of a ROM function that allocates a TX node.
 **/

struct em_buf_node *em_buf_tx_alloc(void)
{
    struct em_buf_node *node = NULL;
    portDISABLE_INTERRUPTS();
    // Get free element from free list
    node = (struct em_buf_node *) co_list_pop_front(&em_buf_env.tx_buff_free);
    portENABLE_INTERRUPTS();
    return node;
}

struct em_desc_node *em_buf_tx_desc_alloc(void)
{
    struct em_desc_node *node = NULL;
    portDISABLE_INTERRUPTS();
    node = (struct em_desc_node *) co_list_pop_front(&em_buf_env.tx_desc_free);
    portENABLE_INTERRUPTS();
    return node;
}


/**
 * send_raw_data_pdu()
 * 
 * @brief Sends a raw data PDU. 
 * @param conhdl: connection handle (by default 0 if there is only one connection alive)
 * @param p_pdu: pointer to a data PDU (bytes)
 * @param length: data PDU length (without its header)
 **/

void send_raw_data_pdu(int conhdl, uint8_t llid, uint8_t *p_pdu, int length, bool can_be_freed)
{
  struct em_buf_node* node;
  struct em_desc_node *data_send;
  struct lld_evt_tag *env = (struct lld_evt_tag *)(*(uint32_t*)((uint32_t)llc_env[conhdl]+0x10) + 0x28);

  /* Disable baseband watchdog. */
  //bb_wdt_int_enable(0);

  /* Allocate data_send. */
  data_send = (struct em_desc_node *)em_buf_tx_desc_alloc();

  /* Allocate a buffer. */
  node = em_buf_tx_alloc();

  //portDISABLE_INTERRUPTS();

  /* Write data into allocated buf node. */
  memcpy((uint8_t *)((uint8_t *)p_rx_buffer + node->buf_ptr), p_pdu, length);

  /* Write information into our em_desc_node structure. */
  data_send->llid = llid;
  data_send->length = length;
  data_send->buffer_idx = node->idx;
  data_send->buffer_ptr = node->buf_ptr;

  /* Call lld_pdu_data_tx_push */  
  pfn_lld_pdu_data_tx_push(env, data_send, can_be_freed);
  //env->tx_prog.maxcnt--;
  //portENABLE_INTERRUPTS();

  //bb_wdt_int_enable(1);
}


/**
 * send_data_pdu()
 * 
 * @brief Sends a data PDU. 
 * @param conhdl: connection handle (by default 0 if there is only one connection alive)
 * @param p_pdu: pointer to a data PDU (bytes)
 * @param length: data PDU length (without its header)
 **/

void send_data_pdu(int conhdl, void *p_pdu, int length)
{
  struct em_buf_node* node;
  struct hci_acl_data_tx *data_send;

  /* Allocate data_send. */
  data_send = (struct hci_acl_data_tx *)malloc(sizeof(struct hci_acl_data_tx));

  /* Allocate a buffer. */
  node = em_buf_tx_alloc();
  #ifdef BLE_HACK_DEBUG
  printf("node: 0x%08x\r\n", (uint32_t)node);
  printf("node buf: 0x%08x\r\n", (uint32_t)node->buf_ptr);
  printf("target buf: 0x%08x\r\n", (uint32_t)(p_rx_buffer + node->buf_ptr));
  printf("buffer idx: %d\r\n", node->idx);
  printf("ppdu: 0x%08x\r\n", (uint32_t)p_pdu);
  #endif

  /* Write data into buffer. */
  data_send->conhdl = conhdl;
  data_send->pb_bc_flag = 2;
  data_send->length = length;
  data_send->buf = node;

  /* Write data into allocated buf node. */
  memcpy((uint8_t *)((uint8_t *)p_rx_buffer + node->buf_ptr), p_pdu, length);

  /* Call lld_pdu_data_send */
  pfn_lld_pdu_data_send(data_send);
}


void send_control_pdu(int conhdl, uint8_t *p_pdu, int length)
{
  /*
   * Sends control PDU through llc_llcp_send().
   *
   * second parameter points to control PDU parameters, while third parameter specifies the
   * control PDU opcode.
   **/
  llc_llcp_send(conhdl, p_pdu, p_pdu[0]);
}

/**
 * ble_hack_install_hooks()
 * 
 * Install our hooks into ESP32's BLE controller memory.
 **/

void ble_hack_install_hooks(void)
{
  /* Hook r_lld_pdu_rx_handler() */
  pfn_lld_pdu_rx_handler = (void *)(r_btdm_option_data[615]);
  #ifdef BLE_HACK_DEBUG
  printf("Hooking function %08x with %08x\n", (uint32_t)pfn_lld_pdu_rx_handler, (uint32_t)_lld_pdu_rx_handler);
  #endif
  r_btdm_option_data[615] = (uint32_t *)_lld_pdu_rx_handler;
  //g_bt_plf_log_level=3;

  /* Hook r_lld_pdu_data_send */
  pfn_lld_pdu_data_send = (void *)(((uint32_t *)g_ip_funcs_p)[598]);
  #ifdef BLE_HACK_DEBUG
  printf("Hooking function %08x with %08x\n", (uint32_t)pfn_lld_pdu_data_send, (uint32_t)_lld_pdu_data_send);
  #endif
  ((uint32_t *)g_ip_funcs_p)[598] = (uint32_t)_lld_pdu_data_send;

  /* Hook r_lld_pdu_tx_prog */
  #if 0
  pfn_lld_pdu_tx_prog = (void *)(((uint32_t *)g_ip_funcs_p)[600]);
  #ifdef BLE_HACK_DEBUG
  printf("Hooking function %08x with %08x\n", (uint32_t)pfn_lld_pdu_tx_prog, (uint32_t)_lld_pdu_tx_prog);
  #endif
  ((uint32_t *)g_ip_funcs_p)[600] = (uint32_t)_lld_pdu_tx_prog;
  #endif

  /* Hook r_lld_pdu_data_tx_push */
  pfn_lld_pdu_data_tx_push = (void *)(((uint32_t *)g_ip_funcs_p)[597]);
  #ifdef BLE_HACK_DEBUG
  printf("Hooking function %08x with %08x\n", (uint32_t)pfn_lld_pdu_data_tx_push, (uint32_t)_lld_pdu_data_tx_push);
  #endif
  ((uint32_t *)g_ip_funcs_p)[597] = (uint32_t)_lld_pdu_data_tx_push;

  /**
   * Install LLCP hooks
   **/
  INSTALL_HOOK(492, llc_llcp_version_ind_pdu_send)
  //INSTALL_HOOK(493, llc_llcp_ch_map_update_pdu_send)
  //INSTALL_HOOK(494, llc_llcp_pause_enc_req_pdu_send)
  //INSTALL_HOOK(495, llc_llcp_pause_enc_rsp_pdu_send)
  //INSTALL_HOOK(496, llc_llcp_enc_req_pdu_send)
  //INSTALL_HOOK(497, llc_llcp_enc_rsp_pdu_send)
  //INSTALL_HOOK(498, llc_llcp_start_enc_rsp_pdu_send)
  INSTALL_HOOK(499, llc_llcp_reject_ind_pdu_send)
  INSTALL_HOOK(500, llc_llcp_con_update_pdu_send)
  INSTALL_HOOK(501, llc_llcp_con_param_req_pdu_send)
  INSTALL_HOOK(502, llc_llcp_con_param_rsp_pdu_send)
  INSTALL_HOOK(503, llc_llcp_feats_req_pdu_send)
  INSTALL_HOOK(504, llc_llcp_feats_rsp_pdu_send)
  //INSTALL_HOOK(505, llc_llcp_start_enc_req_pdu_send)
  INSTALL_HOOK(506, llc_llcp_terminate_ind_pdu_send)
  INSTALL_HOOK(507, llc_llcp_unknown_rsp_send_pdu)
  INSTALL_HOOK(508, llc_llcp_ping_req_pdu_send)
  INSTALL_HOOK(509, llc_llcp_ping_rsp_pdu_send)
  INSTALL_HOOK(510, llc_llcp_length_req_pdu_send)
  INSTALL_HOOK(511, llc_llcp_length_rsp_pdu_send)
  //INSTALL_HOOK(512, llc_llcp_tester_send)
}

/**
 * @brief Set BLE hack Data PDU callback.
 * @param pfn_data_callback: pointer to a callback that'll be notified each time a data PDU is received.
 **/

void ble_hack_rx_data_pdu_handler(FBLEHACK_IsrCallback pfn_data_callback)
{
  gpfn_on_rx_data_pdu = pfn_data_callback;
}


/**
 * @brief Set BLE hack Control PDU callback.
 * @param pfn_data_callback: pointer to a callback that'll be notified each time a control PDU is received.
 **/

void ble_hack_rx_control_pdu_handler(FBLEHACK_IsrCallback pfn_control_callback)
{
  gpfn_on_rx_control_pdu = pfn_control_callback;
}

/**
 * @brief Set BLE hack Control PDU callback.
 * @param pfn_data_callback: pointer to a callback that'll be notified each time a control PDU is transmitted.
 **/

void ble_hack_tx_control_pdu_handler(FBLEHACK_CtlCallback pfn_control_callback)
{
  gpfn_on_tx_control_pdu = pfn_control_callback;
}

/**
 * @brief Set BLE hack Control PDU callback.
 * @param pfn_data_callback: pointer to a callback that'll be notified each time a data PDU is transmitted.
 **/

void ble_hack_tx_data_pdu_handler(FBLEHACK_IsrCallback pfn_data_callback)
{
  gpfn_on_tx_data_pdu = pfn_data_callback;
}



int rom_llc_llcp_send(int conhdl, uint8_t *p_pdu, uint8_t opcode)
{
  return pfn_rom_llc_llcp_send(conhdl, p_pdu, opcode);
}

void debug_fifos(void)
{
    uint16_t *p_offset;
    uint32_t pkt_header;
    uint8_t *p_pdu;
    int channel;
    int pkt_size;
    int rssi;
    int nb_links;
    pkt_hdr_t *p_header = (pkt_hdr_t *)(BLE_RX_PKT_HDR_ADDR);
    uint16_t pkt_status = *(uint16_t *)(BLE_RX_PKT_STATUS);
    int j,k;
    char dbg[256];

    for (j=0; j<8; j++)
    {
        /* Read packet header from fifo header (located at 0x3ffb094c). */
        pkt_header = p_header[j].header;
        
        /* Extract channel, rssi and packet size. */
        channel = (pkt_header>>24);
        rssi = (pkt_header>>16) & 0xff;
        pkt_size = (pkt_header >> 8) & 0xff;

        if (pkt_size >= 0)
        {
            /* TODO: make sure we get the correct offset */
            p_offset = (uint16_t *)(BLE_RX_DESC_ADDR + 12*/*fifo_index*/j);
            p_pdu = (uint8_t *)(p_rx_buffer + *p_offset);

            /* Show PDU */
            for (k=0; k<pkt_size; k++)
                snprintf(&dbg[k*2],3,"%02x", p_pdu[k]);
            esp_rom_printf("FIFO[%d]: %02x%02x%s\n", j, pkt_header&0xff, (pkt_header&0xff00)>>8, dbg);
        }
    }
}

uint32_t ble_read_rwblecntl(void)
{
    return RWBLECNTL;
}

void ble_write_rwblecntl(uint32_t value)
{
    RWBLECNTL = value;
}

void ble_disable_crypto(void)
{
    uint32_t value;

    value = RWBLECNTL;
    value |= (1 << 19); /* CRYPT_DSB = 1 */
    RWBLECNTL = value;
}