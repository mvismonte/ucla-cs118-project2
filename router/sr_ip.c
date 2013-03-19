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
#include "sr_router.h"

/* Helpers */

int process_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, int minlength, char* iface) {
  minlength += sizeof(sr_ip_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "IP header: insufficient length\n");
    return -1;
  }

  print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

  /* Create IP Packet */
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  uint16_t ip_checksum = iphdr->ip_sum;
  iphdr->ip_sum = 0;

  if (cksum(packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t)) != ip_checksum) {
    fprintf(stderr, "IP: invalid checksum\n");
    return -1;
  }

  /* Check if in router's interfaces */
  struct sr_if* own_interface = sr_find_interface(sr, iphdr->ip_dst);

  if (own_interface) {
    /* Interface exists */

    /* Initialize response */
    unsigned int response_length = 0;
    uint8_t* response_packet = 0;

    if (iphdr->ip_p == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (len < minlength) {
        fprintf(stderr, "ICMP header: insufficient length\n");
        return -1;
      }

      /* Create ICMP Packet */
      sr_icmp_hdr_t * icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      uint16_t icmp_checksum = icmphdr->icmp_sum;
      icmphdr->icmp_sum = 0;

      if (cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)) != icmp_checksum) {
        fprintf(stderr, "ICMP: invalid checksum\n");
        return -1;
      }

      /* Process ICMP message */
      printf("ICMP (type %d, code %d)\n", icmphdr->icmp_type, icmphdr->icmp_code);

      if (icmphdr->icmp_type != 8 || icmphdr->icmp_code != 0) {
        /* Drop packet if not echo request */
        return -1;
      }

      response_length = len;

      /* Use request packet as response: saves alloc - tim */
      response_packet = packet;

      /* Format echo reply */
      icmphdr->icmp_type = 0;

      /* Generate ICMP checksum */
      icmphdr->icmp_sum = cksum(
          response_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
          len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    } else if (iphdr->ip_p == 6 || iphdr->ip_p == 17) {
      /* TCP or UDP */

      response_length = sizeof(sr_ethernet_hdr_t) +
                                     sizeof(sr_ip_hdr_t) +
                                     sizeof(sr_icmp_t3_hdr_t);

      /* Create ethernet packet with ICMP Type 3 */
      response_packet = (uint8_t *)malloc(response_length);

      /* Populate ICMP Message */
      sr_icmp_t3_hdr_t* response_icmp = (sr_icmp_t3_hdr_t *)(response_packet +
                                                             sizeof(sr_ethernet_hdr_t) +
                                                             sizeof(sr_ip_hdr_t));
      response_icmp->icmp_type = 3;
      response_icmp->icmp_code = 3;
      memcpy(response_icmp->data, iphdr, ICMP_DATA_SIZE);  /* IP Header + 8 bytes */

      /* Generate ICMP checksum */
      response_icmp->icmp_sum = cksum(
          response_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
          sizeof(sr_icmp_t3_hdr_t));

    } else {
      /* Drop packet if other protocol */
      return -1;
    }

    /* Populate respone IP Packet */
    sr_ip_hdr_t* response_ip = (sr_ip_hdr_t *)(response_packet +
                                               sizeof(sr_ethernet_hdr_t));

    /* Swap src and dst addresses */
    response_ip->ip_dst = iphdr->ip_src;
    response_ip->ip_src = own_interface->ip;

    /* Generate IP checksum */
    response_ip->ip_sum = 0;
    response_ip->ip_sum = cksum(response_packet + sizeof(sr_ethernet_hdr_t),
                                response_length - sizeof(sr_ethernet_hdr_t));

    /* Generate ethernet packet */
    sr_ethernet_hdr_t* e_packet = (sr_ethernet_hdr_t *)(response_packet);
    uint8_t ether_swap[ETHER_ADDR_LEN];
    memcpy(ether_swap, e_packet->ether_dhost, ETHER_ADDR_LEN);
    memcpy(e_packet->ether_dhost, e_packet->ether_shost, ETHER_ADDR_LEN);
    memcpy(e_packet->ether_shost, ether_swap, ETHER_ADDR_LEN);

    sr_send_packet(sr, response_packet, response_length, iface);

  } else {
    /* Forward */

    /* Routing Table lookup */
    struct sr_rt* route = sr_find_rt_entry(sr, iphdr->ip_dst);
    struct sr_arpcache* arp_cache = &sr->cache;
    /*
       entry = arpcache_lookup(next_hop_ip)

     if entry:
         use next_hop_ip->mac mapping in entry to send the packet
         free entry
     else:
         req = arpcache_queuereq(next_hop_ip, packet, len)
         handle_arpreq(req)*/
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(arp_cache, route->gw.s_addr);

    if (arp_entry) {
      /* Set fields in ethernet pack for quick forwarding and send */
      sr_ethernet_hdr_t* e_packet = (sr_ethernet_hdr_t *)(packet);
      memcpy(e_packet->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, iface);

      /* Free arp entry */
      free(arp_entry);
    } else {
      struct sr_arpreq* req = sr_arpcache_queuereq(arp_cache, route->gw.s_addr, packet, len, iface);
      sr_handle_arpreq(sr, req);
    }
  }

  return 0;
}

