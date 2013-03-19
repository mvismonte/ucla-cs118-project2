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

#include "sr_router.h"

int sr_send_icmp_packet(struct sr_instance* sr, uint8_t code, uint8_t type, uint32_t ip, unsigned char* mac, char* interface) {
  /* TODO(Jon|Tim): Implement this function to easily send ICMP packets.
    Allocate enough memory for packet
    Fill it in with information
    Send it using send packet
    free free packet
  */
  return 0;
}
