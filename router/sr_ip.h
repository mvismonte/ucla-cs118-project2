/*-----------------------------------------------------------------------------
 * File: sr_ip.h
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_IP_H
#define SR_IP_H

#include <stdint.h>

#include "sr_router.h"

/* TODO(Tim): Write documentation for this function.  For an example, see
    sr_arp.h
*/
int sr_process_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* iface);

#endif