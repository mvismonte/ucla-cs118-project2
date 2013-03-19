/*-----------------------------------------------------------------------------
 * File: sr_ip.c
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <assert.h>

#include "sr_arp.h"

#include "sr_protocol.h"
#include "sr_utils.h"

int process_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, int minlength) {
  minlength += sizeof(sr_arp_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "ARP header: insufficient length\n");
    return;
  }
  printf("*** -> ARP Request\n");
}