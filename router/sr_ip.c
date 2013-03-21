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

#include "sr_ip.h"

#include "sr_arp.h"
#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

<<<<<<< HEAD
=======
#include "sr_icmp.h"

/* jon needs dis for unique IDs for ip headers */
static uint16_t ipID = 0;  /* may be unnecessary, ok to set id 0? - tim */
>>>>>>> a5753c64fbad0f9c9755656977a83d1b98eb2f0c

int sr_process_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* iface) {

  /* Start of next header: add to packet head */
  unsigned int next_hdr = sizeof(sr_ethernet_hdr_t);

  if (len < next_hdr + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "IP header: insufficient length\n");
    return -1;
  }

  printf("*** -> Processing IP Packet\n");
  print_hdr_ip(packet + next_hdr);

  /* Generate ethernet packet: used to get mac destination */
  sr_ethernet_hdr_t* req_eth = (sr_ethernet_hdr_t *)(packet);

  /* Create request IP Packet */
  sr_ip_hdr_t *req_ip = (sr_ip_hdr_t *)(packet + next_hdr);

  uint16_t req_cksum = req_ip->ip_sum;
  req_ip->ip_sum = 0;

  if (cksum(packet + next_hdr, sizeof(sr_ip_hdr_t)) != req_cksum) {
    fprintf(stderr, "IP: invalid checksum\n");
    return -1;
  }

  /* Check if in router's interfaces */
  struct sr_if* own_interface = sr_find_interface(sr, req_ip->ip_dst);

  if (own_interface) {
    /* Interface exists */

    next_hdr += sizeof(sr_ip_hdr_t);


    if (req_ip->ip_p == ip_protocol_icmp) { /* ICMP */
      if (len < next_hdr + sizeof(sr_icmp_hdr_t)) {
        fprintf(stderr, "ICMP header: insufficient length\n");
        return -1;
      }

      /* Create ICMP Packet */
      sr_icmp_hdr_t* req_icmp = (sr_icmp_hdr_t *)(packet + next_hdr);

      uint16_t req_icmp_cksum = req_icmp->icmp_sum;
      req_icmp->icmp_sum = 0;

      if (cksum(packet + next_hdr, len - next_hdr) != req_icmp_cksum) {
        fprintf(stderr, "ICMP: invalid checksum\n");
        return -1;
      }

      /* 
        Process ICMP message 
      */
      if (req_icmp->icmp_type != 8 || req_icmp->icmp_code != 0) {
        /* Drop packet if not echo request */
        return -1;
      }

      /* Set response length equal to request's */
      uint16_t response_length = len;

      /* Create ethernet packet with ICMP */
      uint8_t* response_packet = (uint8_t *)malloc(response_length);

      /* Copy over packet ICMP header + body */
      memcpy(response_packet + next_hdr, packet + next_hdr, response_length - next_hdr);

      /*
        Populate ICMP Message
      */
      sr_icmp_hdr_t* response_icmp = (sr_icmp_hdr_t *)(response_packet +
                                                       next_hdr);

      /* Format echo reply */
      response_icmp->icmp_type = 0;
      response_icmp->icmp_code = 0;

      /* Generate ICMP checksum */
      response_icmp->icmp_sum = 0;  /* Clear just in case */
      response_icmp->icmp_sum = cksum(response_packet + next_hdr,
                                      response_length - next_hdr);

      /*
        Populate response IP Packet
      */
      sr_ip_hdr_t* response_ip = (sr_ip_hdr_t *)(response_packet +
                                                 sizeof(sr_ethernet_hdr_t));

      /* Swap src and dst addresses */
      response_ip->ip_dst = req_ip->ip_src;
      response_ip->ip_src = req_ip->ip_dst;

      /* Set IP Headers */
      response_ip->ip_v = 4;
      response_ip->ip_hl = 5;
      response_ip->ip_tos = 0;
      response_ip->ip_len = htons(response_length - sizeof(sr_ethernet_hdr_t));
      response_ip->ip_id = htons(0);
      response_ip->ip_off = htons(IP_DF);
      response_ip->ip_ttl = 100;
      response_ip->ip_p = ip_protocol_icmp;

      /* Generate IP checksum */
      response_ip->ip_sum = 0;
      response_ip->ip_sum = cksum(response_packet + sizeof(sr_ethernet_hdr_t),
                                  sizeof(sr_ip_hdr_t));

      /*
        Generate ethernet packet
      */
      sr_ethernet_hdr_t* response_eth = (sr_ethernet_hdr_t *)(response_packet);

      response_eth->ether_type = htons(ethertype_ip);

      /* Swap mac addresses */
      memcpy(response_eth->ether_dhost, req_eth->ether_shost, ETHER_ADDR_LEN);
      memcpy(response_eth->ether_shost, req_eth->ether_dhost, ETHER_ADDR_LEN);

      printf("***-> Sending packet\n");
      print_hdrs(response_packet, response_length);  /* DEBUG */

      if (sr_send_packet(sr, response_packet, response_length, iface) == -1) {
        fprintf(stderr, "Error sending packet\n");
        return -1;
      }
      printf("*** -> Packet sent (%d)\n", response_length);

      free(response_packet);

    } else if (req_ip->ip_p == 6 || req_ip->ip_p == 17) {
      /* TCP or UDP */

      if (sr_send_icmp_packet(sr, 3, 3, req_ip->ip_src, req_eth->ether_shost,
                              (uint8_t *)req_ip, iface) == -1) {
        fprintf(stderr, "Failure sending ICMP message\n");
        return -1;
      }

    } else {
      /* Drop packet if other protocol */
      return -1;
    }

  } else {
    /* Forward the Packet */
    printf("*** -> Forwarding Process Initiated\n");

    /* Routing Table lookup */
    struct sr_rt* route = sr_find_rt_entry(sr, req_ip->ip_dst);
    struct sr_arpcache* arp_cache = &sr->cache;

    /* TODO(mark|tim|jon): Error checking
      If the route does not exist, send ICMP host unreachable
     */
    if (route == NULL) {
      printf("*** -> Route does not exist.  Forwarding terminated\n");

      if (sr_send_icmp_packet(sr, 3, 0, req_ip->ip_src, req_eth->ether_shost,
                              (uint8_t *)req_ip, iface) == -1) {
        fprintf(stderr, "Failure sending ICMP message\n");
        return -1;
      }

      return -2;
    }

    /* Decrement the TTL */
    req_ip->ip_ttl--;
    if (req_ip->ip_ttl == 0) {
      /* Send back ICMP time exceeded */
      printf("*** -> Packet TTL expired.\n");
      if (sr_send_icmp_packet(sr, 11, 0, req_ip->ip_src, req_eth->ether_shost,
                              (uint8_t *)req_ip, iface) == -1) {
        fprintf(stderr, "Failure sending ICMP message\n");
        return -1;
      }
      return 0;
    }

    /* Update the checksum */
    eq_ip->ip_sum = 0;
    req_ip->ip_sum = cksum((uint8_t*) ip_hdr, sizeof(sr_ip_hdr_t));

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(arp_cache, route->gw.s_addr);

    if (arp_entry) {
      printf("*** -> ARP Cache Hit\n");
      /* Forward the packet */
      sr_eth_frame_send_with_mac(sr, packet, len, arp_entry->mac, route->interface);

      /* Free ARP entry */
      free(arp_entry);
    } else {
      printf("*** -> ARP Cache Miss\n");
      struct sr_arpreq* req = sr_arpcache_queuereq(arp_cache, route->gw.s_addr, packet, len, route->interface);
      req->iface = route->interface;
      sr_handle_arpreq(sr, req);
    }
  }

  return 0;
}
