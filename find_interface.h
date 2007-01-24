/*
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version
 *   2 of the License, or (at your option) any later version.
 *
 *   Hans Liss <hans.liss@its.uu.se>  Uppsala Universitet
 *
 *   The file LICENSE must accompany this package when redistributed.
 *   Please refer to it for specific acknowledgements.
 *
 */

#ifndef _FIND_INTERFACE_H
#define _FIND_INTERFACE_H

/* Routing table and interface handling code */

typedef struct interfacenode_s {
  int ifindex;
  struct sockaddr_storage *addresses;
  int addrcount;
  int addralloc;
  char ifname[32];
  struct interfacenode_s *next;
} *interfacenode;

typedef struct routenode_s {
  int family;
  struct sockaddr_storage prefix;
  int prefixlen;
  int ifindex;
  int islocal;
  struct sockaddr_storage source_address;
  struct routenode_s *next;
} *routenode;

typedef struct routingdata_s {
  interfacenode interfaces;
  routenode routes;
} *routingdata;

#ifndef USER_TYPE_NONE
#define USER_TYPE_NONE 0
#define USER_TYPE_ARPPING 1
#define USER_TYPE_PING 2
#endif

/* Look up an address of an interface */
struct sockaddr_storage *get_interface_address(routingdata d, int ifindex, int family);

/* Look up the name of an interface */
char *get_interface_name(routingdata d, int ifindex);

/* If needed, update the route entry list */
int netlink_maybeupdateroutes (routingdata d, int debug);

/*
  Look up interface index, interface name, source address and type for a destination address.
  Return the type (USER_TYPE_ICMP, USER_TYPE_ARP or USER_TYPE_NONE if fail). The rest are call-by-reference.
  */
int find_interface(routingdata d,
		   struct sockaddr *dest_address, int dalen,
		   int *ifindex, char *ifname, int ifnamelen, struct sockaddr *source_address, int salen, int debug);

#endif
