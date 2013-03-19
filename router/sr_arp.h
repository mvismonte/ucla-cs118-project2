/*-----------------------------------------------------------------------------
 * File: sr_arp.h
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ARP_H
#define SR_ARP_H

#include <stdint.h>

int process_arp_packet(uint8_t * packet, unsigned int len, int minlength);

#endif