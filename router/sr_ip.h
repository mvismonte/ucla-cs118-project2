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

/* sr_process_ip_packet
  Processes an IP datagram, detecting if it is to be forwarded or to one of our
  interfaces.  ICMP responses are generated in case of error or ping reply.
*/
int sr_process_ip_packet(
  struct sr_instance* sr,
  uint8_t* packet,
  unsigned int len,
  char* iface
);

#endif