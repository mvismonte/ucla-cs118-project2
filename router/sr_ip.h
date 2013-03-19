/*-----------------------------------------------------------------------------
 * File: sr_ip.h
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_IP_H
#define SR_IP_H

#include <stdint.h>

#include "sr_rt.h"

int sr_process_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* iface);

int sr_forward_eth_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, unsigned char* mac, char* iface);

int sendExpiredICMP(struct sr_instance* sr, sr_ip_hdr_t* packet, unsigned int len, char* iface)
#endif