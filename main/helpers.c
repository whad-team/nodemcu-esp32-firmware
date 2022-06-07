#include "inc/helpers.h"
#include "inc/comm.h"

void dbg_txt(const char *psz_format, ...)
{
  Message verbose_msg = Message_init_default;
  char message[1024];
  va_list args;

  va_start(args, psz_format);
  vsnprintf(message, 1024, psz_format, args);
  va_end(args);

  /* Create verbose message. */
  whacky_init_verbose_message(&verbose_msg, message);

  send_pb_message(&verbose_msg);
}
