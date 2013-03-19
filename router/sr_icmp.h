/*-----------------------------------------------------------------------------
 * File: sr_ip.h
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_INTERFACE_H
#define sr_INTERFACE_H

#include <stdint.h>

#include "sr_router.h"

int sr_send_icmp_packet(struct sr_instance* sr, uint8_t code, uint8_t type, uint32_t ip, unsigned char* mac, char* interface);

#endif