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
#include "sr_icmp.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"


int sr_process_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* iface) {

  /* Start of next header: add to packet head */
  unsigned int next_hdr = sizeof(sr_ethernet_hdr_t);

  if (len < next_hdr + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "IP header: insufficient length\n");
    return -1;
  }

  printf("*** -> Processing IP Packet\n");
  /* DEBUG only print_hdr_ip(packet + next_hdr); */

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
      printf("*** -> Processing ICMP Packet\n");

      /* Create ICMP Packet */
      sr_icmp_hdr_t* req_icmp = (sr_icmp_hdr_t *)(packet + next_hdr);

      uint16_t req_icmp_cksum = req_icmp->icmp_sum;
      req_icmp->icmp_sum = 0;

      if (cksum(packet + next_hdr, len - next_hdr) != req_icmp_cksum) {
        fprintf(stderr, "ICMP: invalid checksum\n");
        return -1;
      }

      /* Process ICMP message */
      if (req_icmp->icmp_type != 8 || req_icmp->icmp_code != 0) {
        /* Drop packet if not echo request */
        printf("*** -> ICMP wasn't type echo.  Dropping packet\n");
        return -1;
      }

      /* Set response length equal to request's */
      uint16_t response_length = len;

      /* TODO(Tim): This code looks redundant.  We should probably use
          sr_send_icmp_packet to send the ping so we don't do all of
          this repeated work.  DRY DRY DRY
      */
      /* Create Ethernet packet with ICMP */
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

      /* Populate response IP Packet */
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

      /* Modify Ethernet packet */
      sr_ethernet_hdr_t* response_eth = (sr_ethernet_hdr_t *)(response_packet);
      response_eth->ether_type = htons(ethertype_ip);

      printf("*** -> Sending ICMP ping reply\n");
      if (sr_send_packet_to_ip_addr(sr, response_packet, response_length,
          response_ip->ip_dst, iface) == -1) {
        fprintf(stderr, "Error sending packet\n");
        return -1;
      }
      printf("*** -> Packet sent (%d)\n", response_length);

      free(response_packet);

    } else if (req_ip->ip_p == 6 || req_ip->ip_p == 17) {
      /* TCP or UDP */
      printf("*** -> TCP or UDP found.  Sending back ICMP type 3, code 3\n");

      if (sr_send_icmp_packet(sr, 3, 3, req_ip->ip_src, (uint8_t *)req_ip, iface) == -1) {
        fprintf(stderr, "Failure sending ICMP message\n");
        return -1;
      }

    } else {
      /* Drop packet if other protocol */
      printf("*** -> Protocol not found.  Dropping packet\n");
      return -1;
    }

  } else {
    /* Forward the Packet */
    printf("*** -> Forwarding Process Initiated\n");

    /* Routing Table lookup */
    struct sr_rt* route = sr_find_rt_entry(sr, req_ip->ip_dst);

    /* Make sure there is a next route. */
    if (route == NULL) {
      printf("*** -> Route does not exist.  Forwarding terminated\n");

      if (sr_send_icmp_packet(sr, 3, 0, req_ip->ip_src, (uint8_t *)req_ip, iface) == -1) {
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
      if (sr_send_icmp_packet(sr, 11, 0, req_ip->ip_src, (uint8_t *)req_ip, iface) == -1) {
        fprintf(stderr, "Failure sending ICMP message\n");
        return -1;
      }
      return 0;
    }

    /* Update the checksum */
    req_ip->ip_sum = 0;
    req_ip->ip_sum = cksum((uint8_t*) req_ip, sizeof(sr_ip_hdr_t));

    /* Send the packet to the correct IP */
    if (sr_send_packet_to_ip_addr(sr, packet, len, route->gw.s_addr,
        route->interface) != 0) {
      fprintf(stderr, "Failure from sr_send_packet_to_ip_addr\n");
      return -1;
    }
  }

  return 0;
}
