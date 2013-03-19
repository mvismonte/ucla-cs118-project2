/*-----------------------------------------------------------------------------
 * File: sr_ip.c
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <assert.h>

#include "sr_ip.h"

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

int process_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, int minlength) {
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

  /* TODO */
  int self = 0;

  if (self) {
    /* Route exists */

    if (iphdr->ip_p == ip_protocol_icmp) {/* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (len < minlength) {
        fprintf(stderr, "ICMP header: insufficient length\n");
        return -1;
      }
    }

  } else {
    /* Forward */

    /* Routing Table lookup */
    struct sr_rt* route = find_route(sr, iphdr->ip_dst);
  }

  return 0;
}

