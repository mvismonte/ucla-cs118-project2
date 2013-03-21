/*-----------------------------------------------------------------------------
 * File: sr_ip.h
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_INTERFACE_H
#define SR_INTERFACE_H

#include <stdint.h>

#include "sr_router.h"

/* TODO(Tim): Write documentation for this function.  For an example, see
    sr_arp.h
*/
int sr_send_icmp_packet(struct sr_instance* sr, uint8_t type, uint8_t code, uint32_t ip, unsigned char* mac, uint8_t* payload, char* interface);

#endif