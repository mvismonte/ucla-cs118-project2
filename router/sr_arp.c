/*-----------------------------------------------------------------------------
 * File: sr_ip.c
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sr_arp.h"

#include "sr_if.h"
 #include "sr_ip.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"

/* TODO(mark): TEST THIS FUNCITON SOMEHOW */
int sr_process_arp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* iface) {

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr, "ARP header: insufficient length\n");
    return -1;
  }
  printf("*** -> ARP Request\n");
  print_hdr_arp(packet);

  /* Create ARP Header and find interface */
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet);
  struct sr_if* interface = sr_find_interface(sr, arp_hdr->ar_tip);

  if (interface) {
    sr_print_if(interface);

    if (strcmp(interface->name, iface) == 0) {
      struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_tha, arp_hdr->ar_tip);

      if (req) { /* Process ARP Reply */
        struct sr_packet* pckt = req->packets;
        for (; pckt != NULL; pckt = pckt->next) {
          sr_forward_eth_packet(sr, pckt->buf, pckt->len, arp_hdr->ar_sha, iface);
        }
      } else { /* Process ARP Request */
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
      }
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
       
         
       arpreq_destroy(req)
   else:
       send arp request
       req->sent = now
       req->times_sent++
  */
  printf("*** -> Handle ARP Request\n");
  time_t now = time(NULL);
  if (difftime(now, req->sent) > 1.0) {
    if (req->times_sent >= 5) {
      /* Send icmp host unreachable to source addr of all pkts waiting on this request */
      /* TODO(Jon|Tim): Complete this? */

      /* Destroy ARP req */
      sr_arpreq_destroy(&(sr->cache), req);
    } else {
      /* Send an ARP request */
      sr_arp_hdr_t arp_frame;

      /* Set source data */
      /* Just using the first interface in the list.  Is this okay? =\ */
      struct sr_if* iface = sr->if_list;
      arp_frame.ar_sip = iface->ip;
      memcpy(arp_frame.ar_sha, iface->addr, ETHER_ADDR_LEN);

      /* Set target data */
      /* Just using the first interface in the list.  Is this okay? =\ */
      arp_frame.ar_tip = req->ip;
      int i;
      for (i = 0; i < ETHER_ADDR_LEN; i++) {
        arp_frame.ar_tha[i] = 0xFF;
      }

      /* Send the request */
      printf("Sending... \n");
      print_hdr_arp((uint8_t *) (&arp_frame));
      sr_print_if(iface);
      /* TODO(mark): I'm stuck right here.
      Need to look into sr_arp_opcode, and 
      */
      sr_send_packet(sr, (uint8_t *) (&arp_frame), sizeof(sr_arp_hdr_t), iface->name);

      /* Increment req information */
      req->sent = now;
      req->times_sent++;
    }
  }
  return 0;
}
