#ifndef HELPERS_INC_H
#define HELPERS_INC_H

#include <stdarg.h>
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/whad.pb.h"
#include "protocol/whad.h"

void dbg_txt(const char *psz_format, ...);
void dbg_txt_rom(const char *psz_format, ...);

#endif /* HELPERS_INC_H */