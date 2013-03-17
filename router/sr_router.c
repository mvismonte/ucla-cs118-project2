/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  print_hdr_eth(packet);  /* DEBUG */

  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "ETHERNET header: insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "IP header: insufficient length\n");
    }

    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

    /* Create IP Packet */
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    uint16_t ip_checksum = iphdr->ip_sum;
    iphdr->ip_sum = 0;

    if (cksum(packet + sizeof(sr_ethernet_hdr_t), len - sizeof(sr_ethernet_hdr_t)) != ip_checksum) {
      fprintf(stderr, "IP: invalid checksum\n");
      return;
    }

    /* Routing Table lookup */
    struct sr_rt* route = find_route(sr, iphdr->ip_dst);

    if (route) {
      /* Route exists */

      if (iphdr->ip_p == ip_protocol_icmp) {/* ICMP */
        minlength += sizeof(sr_icmp_hdr_t);
        if (len < minlength) {
          fprintf(stderr, "ICMP header: insufficient length\n");
          return;
        }
      }

    } else {
      /* Forward */
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "ARP header: insufficient length\n");
      return;
    }
    printf("*** -> ARP Request\n");
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    return;
  }

}/* end sr_ForwardPacket */

