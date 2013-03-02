#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#include <sys/ioctl.h>

#include "config.h"
#include "find_interface.h"

/* #define GETROUTE_DEBUG 1 */

/* Notes:
RTM_GETROUTE
---------------------
rtm_family
IPv6 (N/I) AF_INET6
IPv4 AF_INET

rtm_dst_len
Save

rtm_src_len
OK: 0 (can't handle source routing)
Fail otherwise

rtm_tos
dontcare

rtm_table
dontcare

rtm_protocol
RTPROT_REDIRECT skip

rtm_scope
ICMP: RT_SCOPE_UNIVERSE | RT_SCOPE_SITE | RT_SCOPE_HOST
ARP:  RT_SCOPE_LINK
Fail otherwise

rtm_type
RTN_UNICAST Skip

rtm_flags
RTM_F_CLONED Skip

rtaddr Attributes
---------------
RTA_DST Save!
RTA_OIF save!
RTA_PREFSRC source address



RTM_GETADDR
----------------------------
ifa_index save

ifa_family
Ok: AF_INET
N/I AF_INET6

rtaddr Attributes
---------------
IFA_ADDRESS save
IFA_LABEL save
*/

typedef int (*callback)(struct nlmsghdr *h, routingdata rd, int debug);

/* Clear and set to NULL an interface list */
int free_interfacelist(interfacenode *list, int debug);

/* Set interface address for an interface */
int add_interface_address(interfacenode *list, int ifindex, struct sockaddr *address, int salen, int debug);

/* Set interface name for an interface */
int set_interface_name(interfacenode *list, int ifindex, char *name, int debug);

/* Look up the address of an interface, warning (via syslog()) if the interface has multiple addresses */
struct sockaddr_storage *get_interface_address(routingdata d, int ifindex, int family);

/* Look up the name of an interface */
char *get_interface_name(routingdata d, int ifindex);

/* Clear and set to NULL a route list */
int free_routelist(routenode *list);

/* Add a route entry to a list */
int add_route(routenode *list, struct sockaddr *prefix, int psalen, int prefixlen, int ifindex, int islocal, struct sockaddr *source_address, int salen);

/* Parse a NETLINK rtattr structure into an array of attribute values */
static void netlink_Parse_rtattr(struct rtattr **tb, int max,
				 struct rtattr *rta, int len);

/* Callback to record an interface address entry */
int netlink_add_address(struct nlmsghdr *h, routingdata d, int debug);

/* Callback to record an interface name entry */
int netlink_add_ifname(struct nlmsghdr *h, routingdata d, int debug);

/* Callback to record a route entry */
int netlink_addroute(struct nlmsghdr *h, routingdata d, int debug);

/* Send a query to NETLINK, receive the reply and call a callback for each entry in the reply */
int netlink_query(int querytype, int family, routingdata d, callback handler, int debug);

/* Compare two memory blocks like memcmp() up to a given number of bits */
int bitcmp(unsigned char *a, unsigned char *b, int bits);

/* Refresh the list of interfaces */
int collect_interfaces(routingdata d, int debug);

/* Refresh the list of routing entries and the list of interfaces */
int collect_routes(routingdata d, int debug);

/* Create a socket for listening to netlink events */
int netlink_event_socket();

/* If needed, update the route entry list */
int netlink_maybeupdateroutes (routingdata d, int debug);

/* Construct a sockaddr structure for either AF_INET or AF_INET6, given an address
   family and a buffer. */
int fillSA(struct sockaddr_storage *r, short family, void *addr);

/* Allocate a new sockaddr structure for either AF_INET or AF_INET6, given an address
   family and a buffer. */
struct sockaddr_storage *getNewSA(short family, void *addr);

/* Hack to return a static string containing an {INET|INET6} address on readable form */
char *sockaddr_ntoa(struct sockaddr *sa, int salen) {
  static char buf[256];
  getnameinfo((struct sockaddr *)sa, salen, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV);
  return buf;
} 

/* Here be debugging code for the routing entry loader. All it does is to print the entries
   in human-readable form, but the value thereof should not be underestimated... */
typedef struct stringdef_s {
  int value;
  char *string;
  int type;
} stringdef;

stringdef s_rtm_family[] = {
  {AF_INET, "AF_INET", 0},
  {AF_INET6, "AF_INET6", 0},
  {0, 0, 0}
};

stringdef s_rtm_type[] = {
  {RTN_UNSPEC, "RTN_UNSPEC",0},
  {RTN_UNICAST, "RTN_UNICAST",0},
  {RTN_LOCAL, "RTN_LOCAL",0},
  {RTN_BROADCAST, "RTN_BROADCAST",0},
  {RTN_ANYCAST, "RTN_ANYCAST",0},
  {RTN_MULTICAST, "RTN_MULTICAST",0},
  {RTN_BLACKHOLE, "RTN_BLACKHOLE",0},
  {RTN_UNREACHABLE, "RTN_UNREACHABLE",0},
  {RTN_PROHIBIT, "RTN_PROHIBIT",0},
  {RTN_THROW, "RTN_THROW",0},
  {RTN_NAT, "RTN_NAT",0},
  {RTN_XRESOLVE, "RTN_XRESOLVE",0},
  {0, 0, 0}
};

stringdef s_rtm_protocol[] = {
  {RTPROT_UNSPEC, "RTPROT_UNSPEC",0},
  {RTPROT_REDIRECT, "RTPROT_REDIRECT",0},
  {RTPROT_KERNEL, "RTPROT_KERNEL",0},
  {RTPROT_BOOT, "RTPROT_BOOT",0},
  {RTPROT_STATIC, "RTPROT_STATIC",0},
  {0, 0, 0}
};

stringdef s_rtm_scope[] = {
  {RT_SCOPE_UNIVERSE, "RT_SCOPE_UNIVERSE",0},
  {RT_SCOPE_SITE, "RT_SCOPE_SITE",0},
  {RT_SCOPE_LINK, "RT_SCOPE_LINK",0},
  {RT_SCOPE_HOST, "RT_SCOPE_HOST",0},
  {RT_SCOPE_NOWHERE, "RT_SCOPE_NOWHERE",0},
  {0, 0, 0}
};

stringdef s_rtm_flags[] = {
  {RTM_F_NOTIFY, "RTM_F_NOTIFY",0},
  {RTM_F_CLONED, "RTM_F_CLONED",0},
  {RTM_F_EQUALIZE, "RTM_F_EQUALIZE",0},
  {0, 0, 0}
};

stringdef s_rtm_table[] = {
  {RT_TABLE_UNSPEC, "RT_TABLE_UNSPEC",0},
  {RT_TABLE_DEFAULT, "RT_TABLE_DEFAULT",0},
  {RT_TABLE_MAIN, "RT_TABLE_MAIN",0},
  {RT_TABLE_LOCAL, "RT_TABLE_LOCAL",0},
  {0, 0, 0}
};

stringdef s_rtm_attributes[] = {
  {RTA_UNSPEC, "RTA_UNSPEC",0},
  {RTA_DST, "RTA_DST",2},
  {RTA_SRC, "RTA_SRC",2},
  {RTA_IIF, "RTA_IIF",1},
  {RTA_OIF, "RTA_OIF",1},
  {RTA_GATEWAY, "RTA_GATEWAY",2},
  {RTA_PRIORITY, "RTA_PRIORITY",1},
  {RTA_PREFSRC, "RTA_PREFSRC",2},
  {RTA_METRICS, "RTA_METRICS",1},
  {RTA_MULTIPATH, "RTA_MULTIPATH",0},
  {RTA_PROTOINFO, "RTA_PROTOINFO",0},
  {RTA_FLOW, "RTA_FLOW",0},
  {RTA_CACHEINFO, "RTA_CACHEINFO",0},
  {0, 0, 0}
};

stringdef s_rtm_msgtypes[] = {
  {RTM_NEWLINK, "RTM_NEWLINK", 0},
  {RTM_DELLINK, "RTM_DELLINK", 0},
  {RTM_GETLINK, "RTM_GETLINK", 0},
  {RTM_SETLINK, "RTM_SETLINK", 0},
  {RTM_NEWADDR, "RTM_NEWADDR", 0},
  {RTM_DELADDR, "RTM_DELADDR", 0},
  {RTM_GETADDR, "RTM_GETADDR", 0},
  {RTM_NEWROUTE, "RTM_NEWROUTE", 0},
  {RTM_DELROUTE, "RTM_DELROUTE", 0},
  {RTM_GETROUTE, "RTM_GETROUTE", 0},
  {RTM_NEWNEIGH, "RTM_NEWNEIGH", 0},
  {RTM_DELNEIGH, "RTM_DELNEIGH", 0},
  {RTM_GETNEIGH, "RTM_GETNEIGH", 0},
  {RTM_NEWRULE, "RTM_NEWRULE", 0},
  {RTM_DELRULE, "RTM_DELRULE", 0},
  {RTM_GETRULE, "RTM_GETRULE", 0},
  {RTM_NEWQDISC, "RTM_NEWQDISC", 0},
  {RTM_DELQDISC, "RTM_DELQDISC", 0},
  {RTM_GETQDISC, "RTM_GETQDISC", 0},
  {RTM_NEWTCLASS, "RTM_NEWTCLASS", 0},
  {RTM_DELTCLASS, "RTM_DELTCLASS", 0},
  {RTM_GETTCLASS, "RTM_GETTCLASS", 0},
  {RTM_NEWTFILTER, "RTM_NEWTFILTER", 0},
  {RTM_DELTFILTER, "RTM_DELTFILTER", 0},
  {RTM_GETTFILTER, "RTM_GETTFILTER", 0},
  {RTM_NEWACTION, "RTM_NEWACTION", 0},
  {RTM_DELACTION, "RTM_DELACTION", 0},
  {RTM_GETACTION, "RTM_GETACTION", 0},
  {RTM_NEWPREFIX, "RTM_NEWPREFIX", 0},
#ifdef RTM_GETPREFIX
  {RTM_GETPREFIX, "RTM_GETPREFIX", 0},
#endif
  {RTM_GETMULTICAST, "RTM_GETMULTICAST", 0},
  {RTM_GETANYCAST, "RTM_GETANYCAST", 0},
  {0, 0, 0}
};

char *s_val(stringdef *stab, int value, int *type) {
  int i;
  if (type) *type=0;
  for (i=0; stab[i].string; i++) {
    if (stab[i].value == value) {
      if (type) *type=stab[i].type;
      return stab[i].string;
    }
  }
  return "N/A";
}

void dumppacket(struct nlmsghdr *h) {
  struct rtmsg *rtm;
  struct rtattr *tb [RTA_MAX + 1];
  int t;
  int i;
  int len;
  struct sockaddr_storage tmpaddress;
  static char address_string[256];

  rtm = NLMSG_DATA (h);

  if ((len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg))) < 0) {
    fprintf(stderr, "len incorrect\n");
    return;
  }

  memset(tb, 0, sizeof(tb));
  netlink_Parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);
  
  fprintf(stderr, "Route family=[%s] type=[%s] protocol=[%s] scope=[%s] table=[%s]\n",
	  s_val(s_rtm_family, rtm->rtm_family, &t),
	  s_val(s_rtm_type, rtm->rtm_type, &t),
	  s_val(s_rtm_protocol, rtm->rtm_protocol, &t),
	  s_val(s_rtm_scope, rtm->rtm_scope, &t),
	  s_val(s_rtm_table, rtm->rtm_table, &t)
	  );

  if (tb[RTA_SRC] && rtm->rtm_src_len > 0) {
    fillSA(&tmpaddress, rtm->rtm_family, RTA_DATA (tb[RTA_SRC]));
    getnameinfo((struct sockaddr *)(&tmpaddress), sizeof(tmpaddress), address_string, sizeof(address_string), NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV);
    fprintf(stderr, "\tSource address: [%s]\n", address_string);
  }

  int pf=0;
  for (i=0; s_rtm_flags[i].string; i++) {
    if (rtm->rtm_flags & s_rtm_flags[i].value) {
      if (pf == 0) fprintf (stderr, "\tFlags: %s", s_rtm_flags[i].string);
      else fprintf(stderr, " | %s", s_rtm_flags[i].string);
      pf=1;
    }
  }
  if (pf) fprintf(stderr, "\n");

  if (tb[RTA_OIF]) fprintf(stderr, "\tInterface: %d\n", *(int *) RTA_DATA (tb[RTA_OIF]));

  if (tb[RTA_DST]) fillSA(&tmpaddress, rtm->rtm_family, RTA_DATA (tb[RTA_DST]));
  else fillSA(&tmpaddress, rtm->rtm_family, NULL);
  getnameinfo((struct sockaddr *)(&tmpaddress), sizeof(tmpaddress), address_string, sizeof(address_string), NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV);
  fprintf(stderr, "\tPrefix/len: %s/%d\n", address_string, rtm->rtm_dst_len);  

  if (tb[RTA_PREFSRC]) {
    fillSA(&tmpaddress, rtm->rtm_family, RTA_DATA (tb[RTA_PREFSRC]));
    getnameinfo((struct sockaddr *)(&tmpaddress), sizeof(tmpaddress), address_string, sizeof(address_string), NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV);
    fprintf(stderr, "\tPref. src: [%s]\n", address_string);
  }

  if (tb[RTA_GATEWAY]) {
    fillSA(&tmpaddress, rtm->rtm_family, RTA_DATA (tb[RTA_GATEWAY]));
    getnameinfo((struct sockaddr *)(&tmpaddress), sizeof(tmpaddress), address_string, sizeof(address_string), NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV);
    fprintf(stderr, "\tGateway: [%s]\n", address_string);
  }
}

/****************** End of debug code *******************/

/*
  Look up interface index, interface name, source address and type for a destination address.
  Return the type (USER_TYPE_PING, USER_TYPE_ARPPING or USER_TYPE_NONE if fail). The rest are call-by-reference.
  */
int find_interface(routingdata d,
		   struct sockaddr *dest_address, int dalen,
		   int *ifindex, char *ifname, int ifnamelen, struct sockaddr *source_address, int salen, int debug) {
  routenode tmpnode;
  char *nm;
  unsigned char *abuf, *pbuf;
  if (dest_address->sa_family == AF_INET) {
    abuf=(unsigned char *)&(((struct sockaddr_in *)dest_address)->sin_addr.s_addr);
  } else {
    abuf=(unsigned char *)&(((struct sockaddr_in6 *)dest_address)->sin6_addr.s6_addr);
  }
  for (tmpnode=d->routes; tmpnode; tmpnode=tmpnode->next) {
    if (tmpnode->family == dest_address->sa_family) {
      if (debug) {
	fprintf(stderr, "Comparing %s/%d", sockaddr_ntoa((struct sockaddr *)&(tmpnode->prefix), sizeof(tmpnode->prefix)), tmpnode->prefixlen);
	fprintf(stderr, " with %s\n", sockaddr_ntoa(dest_address, dalen));
      }
      if (tmpnode->prefix.ss_family == AF_INET) {
	pbuf=(unsigned char *)&(((struct sockaddr_in *)&(tmpnode->prefix))->sin_addr.s_addr);
      } else {
	pbuf=(unsigned char *)&(((struct sockaddr_in6 *)&(tmpnode->prefix))->sin6_addr.s6_addr);
      }
      if(!bitcmp(abuf, pbuf, tmpnode->prefixlen)) {
	*ifindex=tmpnode->ifindex;
	if ((nm=get_interface_name(d, tmpnode->ifindex)))
	  strncpy(ifname, nm, ifnamelen);
	else strncpy(ifname, "N/A", ifnamelen);
	ifname[ifnamelen-1]='\0';
	//	if (salen < sizeof(struct sockaddr_storage)) syslog(LOG_ERR, "find_interface(): source_address buffer too small");
	memcpy(source_address, &(tmpnode->source_address), salen);
	return (tmpnode->family==AF_INET && tmpnode->islocal)?USER_TYPE_ARPPING:USER_TYPE_PING;
      }
    }
  }
  return USER_TYPE_NONE;
}

/* Clear and set to NULL and interface list */
int free_interfacelist(interfacenode *list, int debug) {
  interfacenode tmpnode;
  while ((*list)!=NULL) {
    tmpnode=(*list);
    (*list)=(*list)->next;
    if (debug) fprintf(stderr, "Freeing interface %d (at 0x%08lX) with %d addresses\n", tmpnode->ifindex, (unsigned long)tmpnode, tmpnode->addrcount);
    if (tmpnode->addresses) free(tmpnode->addresses);
    free(tmpnode);
  }
  return 1;
}

/* Set interface address for an interface */
int add_interface_address(interfacenode *list, int ifindex, struct sockaddr *address, int salen, int debug) {
  while ((*list) != NULL && ((*list)->ifindex != ifindex)) list=&((*list)->next);
  if (!(*list)) {
    interfacenode tmpnode=(interfacenode)malloc(sizeof(struct interfacenode_s));
    if (!tmpnode) return 0;
    memset(tmpnode, 0, sizeof(struct interfacenode_s));
    tmpnode->addralloc=5;
    tmpnode->addresses=(struct sockaddr_storage *)malloc(tmpnode->addralloc * sizeof(struct sockaddr_storage));
    if (!(tmpnode->addresses)) {
      free(tmpnode);
      return 0;
    }
    memset(tmpnode->addresses, 0, tmpnode->addralloc * sizeof(struct sockaddr_storage));
    tmpnode->ifindex=ifindex;
    memcpy(&(tmpnode->addresses[(tmpnode->addrcount)++]), address, salen);
    if (debug) fprintf(stderr, "Interface %d (at 0x%08lX) now has %d addresses\n", tmpnode->ifindex, (unsigned long)tmpnode, tmpnode->addrcount);
    (*list)=tmpnode;
  } else {
    if ((*list)->addralloc <= (*list)->addrcount) {
      /* Quick&dirtyish way to handle suitable scaling even when the current alloc size is zero :) */
      (*list)->addralloc = ((*list)->addrcount + 1) * 1.5;
      (*list)->addresses=(struct sockaddr_storage *)realloc((*list)->addresses, (*list)->addralloc * sizeof(struct sockaddr_storage));
    }
    memcpy(&((*list)->addresses[((*list)->addrcount)++]), address, salen);
    if (debug) fprintf(stderr, "Interface %d (at 0x%08lX) now has %d addresses\n", (*list)->ifindex, (unsigned long)(*list), (*list)->addrcount);
  }
  return 1;
}

/* Set interface name for an interface */
int set_interface_name(interfacenode *list, int ifindex, char *name, int debug) {
  while ((*list) != NULL && ((*list)->ifindex != ifindex)) list=&((*list)->next);
  if (!(*list)) {
    interfacenode tmpnode=(interfacenode)malloc(sizeof(struct interfacenode_s));
    if (!tmpnode) return 0;
    memset(tmpnode, 0, sizeof(struct interfacenode_s));
    tmpnode->ifindex=ifindex;
    if (name) {
      strncpy(tmpnode->ifname, name, sizeof(tmpnode->ifname));
      tmpnode->ifname[sizeof(tmpnode->ifname) - 1] = '\0';
    }
    (*list)=tmpnode;
    if (debug) fprintf(stderr, "Interface %d (at 0x%08lX) now has the name %s\n", (*list)->ifindex, (unsigned long)(*list), (*list)->ifname);
  } else {
    if (name) {
      strncpy((*list)->ifname, name, sizeof((*list)->ifname));
      (*list)->ifname[sizeof((*list)->ifname) - 1] = '\0';
    } else (*list)->ifname[0] = '\0';
    if (debug) fprintf(stderr, "Interface %d (at 0x%08lX) now has the name %s\n", (*list)->ifindex, (unsigned long)(*list), (*list)->ifname);
  }
  return 1;
}

/* Look up the address of an interface, warning if the interface has multiple addresses */
struct sockaddr_storage *get_interface_address(routingdata d, int ifindex, int family) {
  interfacenode list=d->interfaces;
  while (list && list->ifindex != ifindex) list=list->next;
  if (list) {
    int i;
    for (i=0; i<list->addrcount; i++) {
      /* Return the first address we find that belongs to the correct family. */
      if (list->addresses[i].ss_family == family) return &(list->addresses[i]);
    }
  }
  return NULL;
}

/* Look up the name of an interface */
char *get_interface_name(routingdata d, int ifindex) {
  interfacenode list=d->interfaces;
  while (list && list->ifindex != ifindex) list=list->next;
  if (list && strlen(list->ifname)>0) return list->ifname;
  else return NULL;
}

/* Clear and set to NULL a route list */
int free_routelist(routenode *list) {
  routenode tmpnode;
  while ((*list)!=NULL) {
    tmpnode=(*list);
    (*list)=(*list)->next;
    free(tmpnode);
  }
  return 1;
}

/* Add a route entry to a list */
int add_route(routenode *list, struct sockaddr *prefix, int psalen, int prefixlen, int ifindex, int islocal, struct sockaddr *source_address, int salen) {
  while ((*list) != NULL && ((*list)->prefixlen >= prefixlen)) list=&((*list)->next);

  routenode tmpnode=(routenode)malloc(sizeof(struct routenode_s));
  if (!tmpnode) return 0;
  memcpy(&(tmpnode->prefix), prefix, psalen);
  tmpnode->family=prefix->sa_family;
  tmpnode->prefixlen=prefixlen;
  tmpnode->ifindex=ifindex;
  tmpnode->islocal=islocal;
  memcpy(&(tmpnode->source_address), source_address, salen);
  tmpnode->next=(*list);
  (*list)=tmpnode;
  return 1;
}

/* Parse a NETLINK rtattr structure into an array of attribute values */
static void netlink_Parse_rtattr(struct rtattr **tb, int max,
				 struct rtattr *rta, int len) {
  while (RTA_OK(rta, len)) {
    if (rta->rta_type <= max) tb[rta->rta_type] = rta;
    rta = RTA_NEXT(rta,len);
  }
}

/* Callback to record an interface address entry */
int netlink_add_address(struct nlmsghdr *h, routingdata d, int debug) {
  int len;
  struct ifaddrmsg *iam;
  struct rtattr *tb [RTA_MAX + 1];
  struct sockaddr_storage tmpaddress;
  int ifindex;

  if (h->nlmsg_type != RTM_NEWADDR) return 0;
  if ((len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg))) < 0) return 0;

  iam = NLMSG_DATA (h);
  
  if ((iam->ifa_family != AF_INET) && (iam->ifa_family != AF_INET6)) return 0;
  
  memset (tb, 0, sizeof(tb));
  netlink_Parse_rtattr (tb, RTA_MAX, IFA_RTA (iam), len);

  ifindex= iam->ifa_index;

  if (tb[IFA_ADDRESS]) fillSA(&tmpaddress, iam->ifa_family, RTA_DATA (tb[IFA_ADDRESS]));
  else fillSA(&tmpaddress, iam->ifa_family, NULL);

  add_interface_address(&(d->interfaces), ifindex, (struct sockaddr *)(&tmpaddress), sizeof(struct sockaddr_storage), debug);
  return 1;
}

/* Callback to record an interface name entry */
int netlink_add_ifname(struct nlmsghdr *h, routingdata d, int debug) {
  int len;
  struct ifinfomsg *iim;
  struct rtattr *tb [RTA_MAX + 1];
  int ifindex;

  if (h->nlmsg_type != RTM_NEWLINK) return 0;
  if ((len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg))) < 0) return 0;

  iim = NLMSG_DATA (h);
  
  if (iim->ifi_family != AF_UNSPEC) return 0;
  
  memset (tb, 0, sizeof(tb));

  netlink_Parse_rtattr (tb, RTA_MAX, IFLA_RTA (iim), len);
  
  ifindex= iim->ifi_index;

  if (tb[IFLA_IFNAME])
    set_interface_name(&(d->interfaces), ifindex, (char *) RTA_DATA (tb[IFLA_IFNAME]), debug);

  return 1;
}

/* Callback to record a route entry */
int netlink_addroute(struct nlmsghdr *h, routingdata d, int debug) {
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb [RTA_MAX + 1];
  struct sockaddr_storage rdest;
  int rdest_len;
  struct sockaddr_storage prefsrc;
  int ifindex;
  
  rtm = NLMSG_DATA (h);

  if (debug) dumppacket(h);

  if (h->nlmsg_type != RTM_NEWROUTE) {
    if (debug) fprintf(stderr, "(Ignoring route entry - wrong message type)\n");
    return 0;
  }

  if ((len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg))) < 0) {
    if (debug) fprintf(stderr, "(Ignoring route entry - wrong message length)\n");
    return 0;
  }

  if (((rtm->rtm_family != AF_INET) && (rtm->rtm_family != AF_INET6)) ||
      ((rtm->rtm_type != RTN_UNICAST) &&
      (rtm->rtm_type != RTN_LOCAL)) ||
      (rtm->rtm_flags & RTM_F_CLONED) ||
      (rtm->rtm_protocol == RTPROT_REDIRECT)) {
    if (debug) fprintf(stderr, "(Ignoring route entry - wrong family/type/flags/protocol)\n");
    return 0;
  }

  if (rtm->rtm_src_len != 0) {
    if (debug) fprintf(stderr, "(Ignoring route entry - has a source address)\n");
    return 0;
  }

  memset(tb, 0, sizeof(tb));
  netlink_Parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);
  
  if (tb[RTA_OIF]) ifindex = *(int *) RTA_DATA (tb[RTA_OIF]);
  else {
    if (debug) fprintf(stderr, "(Ignoring route entry - no outgoing interface)\n");
    return 0;
  }
  
  memset(&rdest, 0, sizeof(rdest));
  memset(&prefsrc, 0, sizeof(prefsrc));

  if (tb[RTA_DST]) {
    fillSA(&rdest, rtm->rtm_family, RTA_DATA (tb[RTA_DST]));
  } else fillSA(&rdest, rtm->rtm_family, NULL);

  rdest_len=rtm->rtm_dst_len;

  if (tb[RTA_PREFSRC]) {
    fillSA(&prefsrc, rtm->rtm_family, RTA_DATA (tb[RTA_PREFSRC]));
  } else {
    struct sockaddr_storage *tmp=get_interface_address(d, ifindex, rtm->rtm_family);
    if (tmp) memcpy(&prefsrc, tmp, sizeof(prefsrc));
    else fillSA(&prefsrc, rtm->rtm_family, NULL);
  }
  
  add_route(&(d->routes), (struct sockaddr *)(&rdest), sizeof(rdest), rdest_len, ifindex, rtm->rtm_scope==RT_SCOPE_LINK, (struct sockaddr *)(&prefsrc), sizeof(prefsrc));

  return 1;
}

/* Send a query to NETLINK, receive the reply and call a callback for each entry in the reply */
int netlink_query(int querytype, int family, routingdata d, callback handler, int debug) {
  int sock = -1;
  int count = 0;
  static char buf[131072];
  int status;
  static struct msghdr msg;
  static struct iovec iov = {buf, sizeof(buf)};
  static struct sockaddr_nl snl;
  struct nlmsghdr *h;
  
  static unsigned int netlink_seqno=0;
  
  /* netlink message struct */  
  struct {
    struct nlmsghdr nlh;
    struct rtgenmsg g;
    char pad[3];
  } req;
  
  /* Create a netlink socket which will be closed shortly */
  if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
    syslog(LOG_ERR, "In netlink_query(): socket(): %m");
    goto fail;
  }
  
  memset(&snl, 0, sizeof(snl));
  snl.nl_family = AF_NETLINK;
  snl.nl_groups = 0;
  snl.nl_pid = 0;
  
  /* Bind the socket to the netlink sockaddr. */
  if (bind (sock, (struct sockaddr *) &snl, sizeof(snl)) < 0) {
    syslog(LOG_ERR, "In netlink_query(): bind(): %m");
    goto fail;
  }
  
  /* Prepare the message. We want all routing entries */
  memset(&snl, 0, sizeof(snl));
  snl.nl_family = AF_NETLINK;
  
  req.nlh.nlmsg_len = sizeof(req);
  req.nlh.nlmsg_type = querytype;
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = ++ netlink_seqno;
  req.g.rtgen_family = family;
  
  if (sendto(sock, (void *) &req, sizeof(req), 0,
	     (struct sockaddr *) &snl, sizeof(snl)) < 0) {
    syslog(LOG_ERR, "In netlink_query(): sendto(): %m");
    goto fail;
  }
  
  msg.msg_name=(void *)&snl;
  msg.msg_namelen=sizeof(snl);
  msg.msg_iov=&iov;
  msg.msg_iovlen=1;
  msg.msg_control=NULL;
  msg.msg_controllen=0;
  msg.msg_flags=0;
  
  while (1) {
    status = recvmsg (sock, &msg, 0);
    
    if (status < 0) {
      if (errno == EINTR) continue;
      
      if (errno == EWOULDBLOCK) {
	syslog(LOG_ERR, "In netlink_query(): recvmsg(): %m");
	goto fail;
      }
      continue;
    }
    
    if (status == 0) {
      syslog(LOG_ERR, "In netlink_query(): recvmsg(): EOF");
      goto fail;
    }
    
    if (msg.msg_namelen != sizeof(snl)) {
      syslog(LOG_ERR, "In netlink_query(): Netlink sockaddr length error");
      goto fail;
    }

    if (msg.msg_flags & MSG_TRUNC) {
      syslog(LOG_ERR, "In netlink_query(): message truncated");
      continue;
    }

    for (h = (struct nlmsghdr *) buf;
	 NLMSG_OK (h, status);
	 h = NLMSG_NEXT (h, status)) {

      
      if (h->nlmsg_seq == netlink_seqno) {
	
	/* Finished. */
	if (h->nlmsg_type == NLMSG_DONE) goto success;
	
	/* Error handling. */
	if (h->nlmsg_type == NLMSG_ERROR) {
	  struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
	  if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
	    syslog(LOG_ERR, "In netlink_query(): short message");
	  else
	    syslog(LOG_ERR, "In netlink_query(): netlink error: %s", strerror(-err->error));
	  goto fail;
	}
	
	/* OK we got netlink message. */
	if ((handler)(h, d, debug) > 0) count++;
      } else goto fail;
    }
    if (status) {
      syslog(LOG_ERR, "In netlink_query(): data remnant size %d", status);
      goto fail;
    }
  }
fail:
  count = 0;
success:
  if (sock != -1) close(sock);
  return count;
}

/* Compare two memory blocks like memcmp() up to a given number of bits */
int bitcmp(unsigned char *a, unsigned char *b, int bits) {
  int r1;
  int bytes=bits/8;
  bits %= 8;
  if (((r1=memcmp(a,b,bytes))!=0) || (!bits)) return r1;
  else {
    if ((a[bytes]&((unsigned char)0xFF << (8-bits))) < 
	(b[bytes]&((unsigned char)0xFF << (8-bits))))
      return -1;
    else {
      if ((a[bytes]&((unsigned char)0xFF << (8-bits))) ==
	  (b[bytes]&((unsigned char)0xFF << (8-bits))))
	return 0;
      else return 1;
    }
  }
}

/* Refresh the list of interfaces */
int collect_interfaces(routingdata d, int debug) {
  free_interfacelist(&(d->interfaces), debug);
  if ((netlink_query(RTM_GETADDR, AF_INET, d, netlink_add_address, debug) +
      netlink_query(RTM_GETADDR, AF_INET6, d, netlink_add_address, debug)) == 0) return 0;
  return (netlink_query(RTM_GETLINK, AF_INET, d, netlink_add_ifname, debug) + 
	  netlink_query(RTM_GETLINK, AF_INET6, d, netlink_add_ifname, debug));
}

/* Refresh the list of routing entries and the list of interfaces */
int collect_routes(routingdata d, int debug) {
  if (!collect_interfaces(d, debug)) return 0;
  free_routelist(&(d->routes));
  return (netlink_query(RTM_GETROUTE, AF_INET, d, netlink_addroute, debug) +
	  netlink_query(RTM_GETROUTE, AF_INET6, d, netlink_addroute, debug));
}

/* Create a socket for listening to netlink events */
int netlink_event_socket() {
  int s;
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = RTMGRP_IPV4_ROUTE|RTMGRP_IPV6_ROUTE;
  s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  bind(s, (struct sockaddr*)&sa, sizeof(sa));
  listen(s, 10);
  return s;
}

/* If needed, update the route entry list */
int netlink_maybeupdateroutes(routingdata d, int debug) {
  static int ev_s=-1;
  fd_set myfdset;
  int count=-1;
  struct timeval select_timeout={0,0};
  static char buf[NLMSG_SPACE(1024)];
  struct nlmsghdr *nlmsg=(struct nlmsghdr *)buf;
  static struct msghdr msg;
  static struct iovec iov = {buf, sizeof(buf)};
  static struct sockaddr_nl snl;

  if (ev_s == -1) {
    ev_s=netlink_event_socket();
    count=collect_routes(d, debug);
  } else {
    /* Initialize an fd_set with all the fd:s we are interested in */
    FD_ZERO(&myfdset);
    FD_SET(ev_s, &myfdset);
    
    if (select(ev_s+1, &myfdset, NULL, NULL, &select_timeout)>0) {
      memset(buf, 0, sizeof(buf));
      msg.msg_name=(void *)&snl;
      msg.msg_namelen=sizeof(snl);
      msg.msg_iov=&iov;
      msg.msg_iovlen=1;
      msg.msg_control=NULL;
      msg.msg_controllen=0;
      msg.msg_flags=0;
      while(recvmsg (ev_s, &msg, MSG_DONTWAIT)>=0) {
	if (debug) fprintf(stderr, "Received %s message\n", s_val(s_rtm_msgtypes, nlmsg->nlmsg_type, NULL));
      }
      count=collect_routes(d, debug);
    }
  }
  if (count == 0) syslog(LOG_NOTICE, "Update routing table failed");
  else if (count > 0) syslog(LOG_NOTICE, "Updated routing table: %d entries", count);
  return count;
}

/* Construct a sockaddr structure for either AF_INET or AF_INET6, given an address
   family and a buffer. */
int fillSA(struct sockaddr_storage *r, short family, void *addr) {
  struct sockaddr_in *r_in=(struct sockaddr_in *)r;
  struct sockaddr_in6 *r_in6=(struct sockaddr_in6 *)r;
  memset(r, 0, sizeof(struct sockaddr_storage));
  if (family == AF_INET) {
    if (addr) memcpy(&(r_in->sin_addr.s_addr), addr, sizeof(r_in->sin_addr.s_addr));
    r_in->sin_family=AF_INET;
  } else {
    if (addr) memcpy(&(r_in6->sin6_addr.s6_addr), addr, sizeof(r_in6->sin6_addr.s6_addr));
    r_in6->sin6_family=AF_INET6;
  }
  return 1;
}

