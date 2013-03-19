/*-----------------------------------------------------------------------------
 * File: sr_arp.h
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ARP_H
#define SR_ARP_H

#include <stdint.h>

#include "sr_arpcache.h"
#include "sr_router.h"

/* Process an ARP packet */
int sr_process_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* iface);

int sr_handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req);

#endif