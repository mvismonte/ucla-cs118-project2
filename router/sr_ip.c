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


int sr_process_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* iface) {

  /* Start of next header: add to packet head */
  unsigned int next_hdr = sizeof(sr_ethernet_hdr_t);

  if (len < next_hdr + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "IP header: insufficient length\n");
    return -1;
  }

  printf("*** -> Processing IP Packet\n");
  print_hdr_ip(packet + next_hdr);

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

    /* Initialize response */
    uint16_t response_length = 0;
    uint8_t* response_packet = 0;

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

      /* Process ICMP message */
      printf("ICMP (type %d, code %d)\n", req_icmp->icmp_type, req_icmp->icmp_code);

      if (req_icmp->icmp_type != 8 || req_icmp->icmp_code != 0) {
        /* Drop packet if not echo request */
        return -1;
      }

      /* Set response length equal to request's */
      response_length = len;

      /* Create ethernet packet with ICMP */
      response_packet = (uint8_t *)malloc(response_length);

      /* Copy over packet with ICMP + body */
      memcpy(response_packet + next_hdr, packet + next_hdr, response_length - next_hdr);

      /* Populate ICMP Message */
      sr_icmp_hdr_t* response_icmp = (sr_icmp_hdr_t *)(response_packet +
                                                       next_hdr);

      /* Format echo reply */
      response_icmp->icmp_type = 0;
      response_icmp->icmp_code = 0;

      /* Generate ICMP checksum */
      response_icmp->icmp_sum = 0;  /* Clear just in case */
      response_icmp->icmp_sum = cksum(response_packet + next_hdr,
                                      response_length - next_hdr);

    } else if (req_ip->ip_p == 6 || req_ip->ip_p == 17) {
      /* TCP or UDP */

      response_length = next_hdr + sizeof(sr_icmp_t3_hdr_t);

      /* Create ethernet packet with ICMP Type 3 */
      response_packet = (uint8_t *)malloc(response_length);

      /* Populate ICMP Message */
      sr_icmp_t3_hdr_t* response_icmp = (sr_icmp_t3_hdr_t *)(response_packet +
                                                             next_hdr);
      response_icmp->icmp_type = 3;
      response_icmp->icmp_code = 3;

      /* Copy over IP Header + 8 bytes */
      memcpy(response_icmp->data, req_ip, ICMP_DATA_SIZE);

      /* Generate ICMP checksum */
      response_icmp->icmp_sum = 0;  /* Clear just in case */
      response_icmp->icmp_sum = cksum(response_packet + next_hdr,
                                      sizeof(sr_icmp_t3_hdr_t));

    } else {
      /* Drop packet if other protocol */
      return -1;
    }

    /* Populate respone IP Packet */
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

    print_hdr_ip(response_packet + sizeof(sr_ethernet_hdr_t));
    /* Generate ethernet packet */
    sr_ethernet_hdr_t* request_eth = (sr_ethernet_hdr_t *)(packet);
    sr_ethernet_hdr_t* response_eth = (sr_ethernet_hdr_t *)(response_packet);

    response_eth->ether_type = htons(ethertype_ip);

    /* Swap mac addresses */
    memcpy(response_eth->ether_dhost, request_eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(response_eth->ether_shost, request_eth->ether_dhost, ETHER_ADDR_LEN);

    printf("***-> Sending packet\n");
    print_hdrs(response_packet, response_length);  /* DEBUG */

    if (sr_send_packet(sr, response_packet, response_length, iface) == -1) {
      fprintf(stderr, "Error sending packet\n");
    }
    printf("*** -> Packet sent (%d)\n", response_length);

  } else {
    /* Forward the Packet */
    printf("*** -> Forwarding Process Initiated\n");

    /* Routing Table lookup */
    struct sr_rt* route = sr_find_rt_entry(sr, req_ip->ip_dst);
    struct sr_arpcache* arp_cache = &sr->cache;

    /* TODO(mark|tim|jon): Error checking
      If the route does not exist, send ICMP host unreachable
     */

    /* Decrement the TTL */
    req_ip->ip_ttl--;
    if (req_ip->ip_ttl == 0) {
      printf("*** -> Packet TTL expired.\n");
      /* TODO(mark|tim|jon): Send back ICMP time exceeded */
      return 0;
    }

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(arp_cache, route->gw.s_addr);

    if (arp_entry) {
      printf("*** -> ARP Cache Hit\n");
      /* Forward the packet */
      sr_forward_eth_packet(sr, packet, len, arp_entry->mac, route->interface);

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


int sr_forward_eth_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, unsigned char* mac, char* iface) {
  printf("*** -> Forwarding Packet\n");

  /* Created the packet */
  sr_ethernet_hdr_t* e_packet = (sr_ethernet_hdr_t *)(packet);
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if* interface = sr_get_interface(sr, iface);

  /* Set fields */
  memcpy(e_packet->ether_dhost, mac, ETHER_ADDR_LEN);
  memcpy(e_packet->ether_shost, interface->addr, ETHER_ADDR_LEN);

  /* Update IP checksum */
  ip_hdr->ip_sum = cksum((uint8_t*) ip_hdr, sizeof(sr_ip_hdr_t));

  /* Send the packet */
  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, iface);
  return 0;
}

