/*-----------------------------------------------------------------------------
 * File: sr_ip.h
 * Date: 03/18/2013
 * Authors: Timothy Wang, Mark Vismonte, Jonathan Li
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_IP_H
#define SR_IP_H

#include <stdint.h>

int process_ip_packet(uint8_t * packet, unsigned int len, int minlength);

#endif