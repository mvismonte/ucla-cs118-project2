/*-----------------------------------------------------------------------------
 * File: sr_arp.h
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ARP_H
#define SR_ARP_H

#include <stdint.h>

#include "sr_router.h"

/* sr_process_arp_packet
  This function is responsible for the overall process of handling ARP packets.
  It differentiates between receiving ARP replies and ARP requests.  If an ARP
  Reply is received, the function will look at the ARP cache queue and find the
  ARP request sent out for this reply.  If it does find one, it will process
  all of the pending outgoing requests waiting on this ARP reply to come back.
  If the function receives an ARP request, it will respond with the MAC address
  of the interface if one of the interfaces is assigned the ARP request query
  IP.
*/
int sr_process_arp_packet(
  struct sr_instance* sr,
  uint8_t* packet,
  unsigned int len,
  char* iface
);

/* sr_handle_arpreq
  sr_handle_arpreq is responsible for processing all of the ARP requests in
  the ARP cache queue.  It basically sends another ARP request or times out
  depending on how many times the ARP request has been sent.
*/
int sr_handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req);

/* sr_eth_frame_send_with_mac
  This function is either directly or indirectly called by
  sr_send_packet_to_ip_addr.  This function completes the sending processing
  by filling in the source and destination MAC addresses and then actually
  calling sr_send_packet.  This function will be called by
  sr_send_packet_to_ip_addr directly if there is an ARP entry for the IP
  address in the ARP cache.  It will be called indirectly through
  sr_process_arp_packet when there is an ARP cache miss and the corresponding
  ARP reply comes back.
*/
int sr_eth_frame_send_with_mac(
  struct sr_instance* sr,
  uint8_t* packet,
  unsigned int len,
  unsigned char* mac,
  char* iface
);

/* sr_send_packet_to_ip_addr
  sr_send_packet_to_ip_addr is meant to be a higher level wrapper function
  for sr_send_packet.  Since we have the IP address we want to send a packet
  to and cannot assume or don't know anything about the destination MAC
  address, we have to use ARP to retrieve the MAC address.  This function
  will initiate the process of retrieving the MAC address through ARP.
*/
int sr_send_packet_to_ip_addr(
  struct sr_instance* sr,
  uint8_t* packet,
  unsigned int len,
  uint32_t dest_ip,
  char* iface
);

#endif