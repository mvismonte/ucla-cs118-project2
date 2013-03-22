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

/* sr_send_icmp_packet
  Sends an ICMP type 3 or type 11 message specified by `type` and `code`.
  Destination IP address is specified by `ip` and the ICMP message body is
  copied from `payload`.  sr_send_icmp_packet formats the headers for the ICMP
  message, the IP datagram, and the ethernet frame.
*/
int sr_send_icmp_packet(
  struct sr_instance* sr,
  uint8_t type,
  uint8_t code,
  uint32_t ip,
  uint8_t* payload,
  char* interface
);

#endif