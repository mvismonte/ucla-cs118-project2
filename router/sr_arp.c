/*-----------------------------------------------------------------------------
 * File: sr_ip.c
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sr_arp.h"

#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"

/* TODO(mark): TEST THIS FUNCITON SOMEHOW */
int sr_process_arp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, int minlength, char* iface) {
  minlength += sizeof(sr_arp_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "ARP header: insufficient length\n");
    return -1;
  }
  printf("*** -> ARP Request\n");
  print_hdr_arp(packet);

  /* Create ARP Header and find interface */
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet);
  struct sr_if* interface = sr_find_interface(sr, arp_hdr->ar_tip);

  /* TODO(mark): Check ARP queue to see if the request is in there.
   The ARP reply processing code should move entries from the ARP request
   queue to the ARP cache:

   # When servicing an arp reply that gives us an IP->MAC mapping
   req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)
  */


  if (interface) {
    sr_print_if(interface);

    if (strcmp(interface->name, iface) == 0) {
      /* Set the target to the incoming ARP source. */
      memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      arp_hdr->ar_tip = arp_hdr->ar_sip;

      /* Set the source to this interface. */
      memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
      arp_hdr->ar_sip = interface->ip;

      /* Set ethernet frame MAC information */
      sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)(packet);
      memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_tha, ETHER_ADDR_LEN);
      memcpy(ethernet_hdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

      /* Send the packet back on it's way. */
      print_hdr_arp(packet);
      sr_send_packet(sr, packet, len, iface);
    } else {
      fprintf(stderr, "ARP interface names didn't match: %s, %s\n", interface->name, iface);
      return -1;
    }
  } else {
    printf("ARP interface not found\n");
  }

  return 0;
}

int sr_handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req) {
  /*
  Pseudocode
 if difftime(now, req->sent) > 1.0
   if req->times_sent >= 5:
       send icmp host unreachable to source addr of all pkts waiting
         on this request
       arpreq_destroy(req)
   else:
       send arp request
       req->sent = now
       req->times_sent++
  */
  return 0;
}