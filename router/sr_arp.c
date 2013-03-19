/*-----------------------------------------------------------------------------
 * File: sr_ip.c
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sr_arp.h"

#include "sr_if.h"
 #include "sr_ip.h"
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
  printf("*** -> ARP Packet Processing Initiated\n");
  /* print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t)); */

  /* Create ARP Header and find interface */
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* interface = sr_find_interface(sr, arp_hdr->ar_tip);

  if (interface) {
    printf("*** -> Found Interface: ");
    sr_print_if(interface);

    if (strcmp(interface->name, iface) == 0) {
      printf("*** -> Interface name's match up\n");
      unsigned short op_code = ntohs(arp_hdr->ar_op);

      if (op_code == arp_op_reply) { /* Process ARP Reply */
        printf("*** -> Processing ARP Reply\n");

        /* See if there's an ARP request in the queue. */
        struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

        /* Forward all packets waiting on req if req exists. */
        struct sr_packet* pckt = req ? req->packets : NULL;
        for (; pckt != NULL; pckt = pckt->next) {
          sr_forward_eth_packet(sr, pckt->buf, pckt->len, arp_hdr->ar_sha, pckt->iface);
        }
      } else if (op_code == arp_op_request) { /* Process ARP Request */
        printf("*** -> Processing ARP Request\n");

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
        arp_hdr->ar_op = htons(arp_op_reply);
        /* print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t)); */
        sr_send_packet(sr, packet, len, iface);
      } else {
        fprintf(stderr, "ARP Op Code Unknown: (%d)\n", arp_hdr->ar_op);
        return -1;
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
      int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      uint8_t* frame = malloc(len);
      sr_ethernet_hdr_t* ether_hdr = (struct sr_ethernet_hdr*) frame;
      sr_arp_hdr_t* arp_frame = (sr_arp_hdr_t*) (frame + sizeof(sr_ethernet_hdr_t));
      struct sr_if* iface = sr_get_interface(sr, req->iface);

      /* Set Ethernet type to ARP */
      ether_hdr->ether_type = htons(ethertype_arp);
      arp_frame->ar_hrd = htons(arp_hrd_ethernet);
      arp_frame->ar_pro = htons(ethertype_ip);
      arp_frame->ar_hln = ETHER_ADDR_LEN;
      arp_frame->ar_pln = IP_ADDR_LEN;
      arp_frame->ar_op = htons(arp_op_request);

      /* Set source data */
      arp_frame->ar_sip = iface->ip;
      memcpy(arp_frame->ar_sha, iface->addr, ETHER_ADDR_LEN);
      memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
      
      /* Set target data */
      /* Just using the first interface in the list.  Is this okay? =\ */
      arp_frame->ar_tip = req->ip;
      int i;
      for (i = 0; i < ETHER_ADDR_LEN; i++) {
        arp_frame->ar_tha[i] = 0xFF;
        ether_hdr->ether_dhost[i] = 0xFF;
      }

      /* Send the request */
      printf("*** -> Sending out ARP Request\n");
      /* print_hdrs(frame, len); */
      sr_send_packet(sr, frame, len, iface->name);
      free(frame);

      /* Increment req information */
      req->sent = now;
      req->times_sent++;
    }
  }
  return 0;
}
