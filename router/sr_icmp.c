/*-----------------------------------------------------------------------------
 * File: sr_ip.c
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_icmp.h"

#include "sr_if.h"
#include "sr_utils.h"

#include "sr_router.h"

int sr_send_icmp_packet(struct sr_instance* sr, uint8_t type, uint8_t code, uint32_t ip, unsigned char* mac, uint8_t* payload, char* interface) {
  /* ip should be in network byte order */

  assert(sr);
  assert(mac);
  assert(payload);
  assert(interface);

  if (type != 3 && type != 11) {
    return -1;
  }

  unsigned int icmp_start = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  unsigned int response_length = icmp_start + sizeof(sr_icmp_t3_hdr_t);

  /* Create ethernet packet with ICMP Type 3 */
  uint8_t* response_packet = (uint8_t *)malloc(response_length);

  /* Populate ICMP Message */
  sr_icmp_t3_hdr_t* response_icmp = (sr_icmp_t3_hdr_t *)(response_packet +
                                                         icmp_start);
  response_icmp->icmp_type = type;
  response_icmp->icmp_code = code;

  response_icmp->unused = 0;
  response_icmp->next_mtu = 0;

  /* Copy over IP Header + 8 bytes */
  memcpy(response_icmp->data, payload, ICMP_DATA_SIZE);

  /* Generate ICMP checksum */
  response_icmp->icmp_sum = 0;  /* Clear just in case */
  response_icmp->icmp_sum = cksum(response_packet + icmp_start,
                                  sizeof(sr_icmp_t3_hdr_t));

  /* Populate respone IP Packet */
  sr_ip_hdr_t* response_ip = (sr_ip_hdr_t *)(response_packet +
                                             sizeof(sr_ethernet_hdr_t));

  /* Get interface */
  printf("Sender interface: %s\n", interface);
  struct sr_if* sender = sr_get_interface(sr, interface);

  /* Set src and dst addresses */
  response_ip->ip_dst = ip;
  response_ip->ip_src = sender->ip;

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

  /* Generate ethernet packet */
  sr_ethernet_hdr_t* response_eth = (sr_ethernet_hdr_t *)(response_packet);

  response_eth->ether_type = htons(ethertype_ip);

  /* Set mac addresses */
  memcpy(response_eth->ether_dhost, mac, ETHER_ADDR_LEN);
  memcpy(response_eth->ether_shost, sender->addr, ETHER_ADDR_LEN);

  printf("***-> Sending packet\n");
  print_hdrs(response_packet, response_length);  /* DEBUG */

  /* TODO(Tim): Switch this so that it uses sr_send_packet_to_ip_addr in 
      sr_arp.c.  Don't worry about filling in the Ethernet MAC address info.
      The function will take care of this for you because you pass in the
      target IP address and the source interface.
  */
  if (sr_send_packet(sr, response_packet, response_length, interface) == -1) {
    fprintf(stderr, "Error sending packet\n");
    return -1;
  }
  printf("*** -> Packet sent (%d)\n", response_length);

  free(response_packet);

  return 0;
}
