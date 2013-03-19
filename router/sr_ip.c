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

struct sr_rt* find_route(struct sr_instance* sr, uint32_t ip_dst) {
  struct sr_rt* rt_entry = 0;

  if (sr->routing_table == 0) {
    fprintf(stderr, "Routing table empty\n");
    return 0;
  } else {
    rt_entry = sr->routing_table;

    fprintf(stderr, "*** -> Checking routing table\n");
    while (rt_entry) {
      sr_print_routing_entry(rt_entry);  /* DEBUG */

      /* Check masked destination to routing table entry */
      if ((ip_dst & (rt_entry->mask).s_addr) == (rt_entry->dest).s_addr) {
        /* Route found */
        return rt_entry;
      }

      rt_entry = rt_entry->next;
    }
  }
  return 0;
}

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

      if (icmphdr->icmp_type == 8 && icmphdr->icmp_code == 0) {
        /* Echo Request */

        /* Format echo reply */
        icmphdr->icmp_type = 0;
      }

      /* Generate ICMP checksum */
      icmphdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    }

    /* Swap src and dst addresses */
    iphdr->ip_dst = iphdr->ip_src;
    iphdr->ip_src = own_interface->ip;

    /* Generate IP checksum */
    iphdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t));

    /* Generate ethernet packet - quick and dirty */
    sr_ethernet_hdr_t* e_packet = (sr_ethernet_hdr_t *)(packet);
    uint8_t ether_swap[ETHER_ADDR_LEN];
    memcpy(ether_swap, e_packet->ether_dhost, ETHER_ADDR_LEN);
    memcpy(e_packet->ether_dhost, e_packet->ether_shost, ETHER_ADDR_LEN);
    memcpy(e_packet->ether_shost, ether_swap, ETHER_ADDR_LEN);

    sr_send_packet(sr, packet, len, iface);


  } else {
    /* Forward */

    /* Routing Table lookup */
    struct sr_rt* route = find_route(sr, iphdr->ip_dst);
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

