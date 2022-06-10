#ifndef DISPATCH_INC_H
#define DISPATCH_INC_H

#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "protocol/whad.pb.h"

void dispatch_message(Message *message);

#endif /* DISPATCH_INC_H */