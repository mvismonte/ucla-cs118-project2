UCLA CS 118
Project 2
Winter 2013
Authors: Mark Vismonte, Timothy Wang, Jonathan Li
Date: 03/22/2013

Project Implmentation:
We've created 3 additional c files: sr_arp.c, sr_ip.c, and sr_icmp.c.  The bulk
of our code is in these files.  We've commented each of the functions and they
should give you a high level overview of how our code works.


Handling Requests:
In sr_handlepacket of sr_router.c, we check to see what type of ethernet packet
we're handling.  If it's an ARP type, then we forward the request to
sr_process_arp_packet in sr_arp.c for handling.  If it's an IP type, then we
forwarding the request to sr_process_ip_packet in sr_ip.c for handling.  We also
have a handful of helper functions that are in sr_ip, sr_arp, and sr_icmp.
Please take a look at those to get a better understanding of how to process each
packet.
