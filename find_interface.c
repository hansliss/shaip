/*
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version
 *   2 of the License, or (at your option) any later version.
 *
 *   Hans Liss <Hans@Liss.pp.se>
 *
 *   This is based in part on code from IP-login2 from the same author,
 *   which uses ICMP ping code from Mike Muuss 'ping' program.
 *
 */

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
#include <netinet/in.h>
#include <time.h>
#include <linux/if_arp.h>

#include "config.h"

#define RETURN_ERROR -2
#define RETURN_NOTFOUND -1

/* Global vars */

/* Utility functions for parse rtattr. */
static void netlink_Parse_rtattr(struct rtattr **tb, int max,
				 struct rtattr *rta, int len)
{
  while (RTA_OK(rta, len)) 
    {
      if (rta->rta_type <= max)
	tb[rta->rta_type] = rta;
      rta = RTA_NEXT(rta,len);
    }
}

/* Compare two memory blocks like memcmp() up to a given number of bits */
int bitcmp(unsigned char *a, unsigned char *b, int bits)
{
  int r1;
  int bytes=bits/8;
  bits %= 8;
  if (((r1=memcmp(a,b,bytes))!=0) || (!bits))
    return r1;
  else
    {
      if ((a[bytes]&((unsigned char)0xFF << (8-bits))) < 
	  (b[bytes]&((unsigned char)0xFF << (8-bits))))
	return -1;
      else
	{
	  if ((a[bytes]&((unsigned char)0xFF << (8-bits))) ==
	      (b[bytes]&((unsigned char)0xFF << (8-bits))))
	    return 0;
	  else
	    return 1;
	}
    }
}

/* Looking up routing table by netlink interface. */
int netlink_MatchRoute(struct nlmsghdr *h, struct in_addr *dest)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb [RTA_MAX + 1];
  struct in_addr rdest;
  struct in_addr gate;
  char anyaddr[16] = {0};
  int table;
  int index;

  rtm = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWROUTE)
    return RETURN_NOTFOUND;

  if ((len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg))) < 0)
    return RETURN_ERROR;

  if (rtm->rtm_family != AF_INET)
    return RETURN_NOTFOUND;

  if (rtm->rtm_type != RTN_UNICAST)
    return RETURN_NOTFOUND;

  if (rtm->rtm_flags & RTM_F_CLONED)
    return RETURN_NOTFOUND;

  if (rtm->rtm_protocol == RTPROT_REDIRECT)
    return RETURN_NOTFOUND;

  /*  if (rtm->rtm_protocol == RTPROT_KERNEL)
      return RETURN_NOTFOUND; */

  if (rtm->rtm_src_len != 0)
    return RETURN_ERROR;

  table = rtm->rtm_table;

  bzero (tb, sizeof(tb));
  netlink_Parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);
  
  bzero (&rdest, sizeof(rdest));
  bzero (&gate, sizeof(gate));

  if (tb[RTA_OIF])
    index = *(int *) RTA_DATA (tb[RTA_OIF]);
  else
    return RETURN_NOTFOUND;

  if (tb[RTA_DST])
    {
      rdest.s_addr = *( unsigned long int *)  RTA_DATA (tb[RTA_DST]);
    }
  else
    rdest.s_addr = *( unsigned long int *)  anyaddr;
  
#if 0
  if (tb[RTA_GATEWAY])
    {
      gate.s_addr =  *( unsigned long int *) RTA_DATA (tb[RTA_GATEWAY]);
    }

  printf(" Matching %s ",  inet_ntoa(*dest));
  printf(" %s/%d,  %d\n", inet_ntoa(rdest), rtm->rtm_dst_len, index);
#endif 

  if(!bitcmp((unsigned char*)&(rdest.s_addr),
	     (unsigned char*)&(dest->s_addr), rtm->rtm_dst_len))
    {
      return index;
    }
  return RETURN_NOTFOUND;
}

/* Receive messages from netlink interface and try to find a route to
   the given destination */
int netlink_CheckRoute(int netlink_socket, struct in_addr *dest)
{
  int status;
  int ret=RETURN_NOTFOUND;
  int seq = 0;
  static char buf[4096];
  static struct msghdr msg;
  static struct iovec iov = {buf, sizeof(buf)};
  static struct sockaddr_nl snl;
  struct nlmsghdr *h;

  msg.msg_name=(void *)&snl;
  msg.msg_namelen=sizeof(snl);
  msg.msg_iov=&iov;
  msg.msg_iovlen=1;
  msg.msg_control=NULL;
  msg.msg_controllen=0;
  msg.msg_flags=0;

  while (1)
    {
      status = recvmsg (netlink_socket, &msg, 0);

      if (status < 0)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EWOULDBLOCK)
	    {
	      return RETURN_NOTFOUND;
	    }
#if 0
	  printf("netlink recvmsg overrun");
#endif
	  continue;
	}

      if (status == 0)
	{
	  syslog(LOG_ERR,"In find_interface(): netlink EOF");
	  return RETURN_ERROR;
	}

      if (msg.msg_namelen != sizeof(snl))
	{
	  syslog(LOG_ERR,
		 "In find_interface(): Netlink sender address length error");
	  return RETURN_ERROR;
	}

      for (h = (struct nlmsghdr *) buf;
	   NLMSG_OK (h, status);
	   h = NLMSG_NEXT (h, status))
	{
	  /* Message sequence. */
	  seq = h->nlmsg_seq;
	  
	  /* Finish of reading. */
	  if (h->nlmsg_type == NLMSG_DONE)
	    return ret;

	  /* Error handling. */
	  if (h->nlmsg_type == NLMSG_ERROR)
	    {
	      struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
	      if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
		syslog(LOG_ERR, "netlink error: message truncated");
	      else
		syslog(LOG_ERR, "netlink error: %s", strerror(-err->error));
	      return RETURN_ERROR;
	    }

	  /* OK we got netlink message. */
	  if (ret < 0)
	    {
	      if ((ret = netlink_MatchRoute(h, dest)) < RETURN_NOTFOUND)
		{
		  syslog(LOG_ERR, "netlink filter function error");
		  return RETURN_ERROR;
		}
	    }
	}

      /* After error care. */
      if (msg.msg_flags & MSG_TRUNC)
	{
	  syslog(LOG_ERR, "netlink error: message truncated");
	  continue;
	}
      if (status)
	{
	  syslog(LOG_ERR, "netlink error: data remnant size %d", status);
	  return RETURN_ERROR;
	}
      /* This message will be from kernel but reply to user request. */
      if (seq == 0)
	return ret;
    }
  return ret;
}

/* Get interface index and IP address for 'dest' from netlink.
   Return >=0 iff both index and address are found!
*/
int find_interface(struct in_addr *dest, struct in_addr *src, char *namebuf, int namelen)
{
  struct sockaddr_nl snl;
  int sock;
  int ret=RETURN_ERROR, index;
  static char buff[1024];
  struct ifconf ifc;
  struct ifreq *ifr;
  int i;
  
  struct
  {
    struct nlmsghdr nlh;
    struct rtgenmsg g;
  } req;

  if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
    {
      syslog(LOG_ERR, "In find_interface(): socket(): %m");
      return RETURN_ERROR;
    }
  
  bzero (&snl, sizeof(snl));
  snl.nl_family = AF_NETLINK;
  snl.nl_groups = 0;

  /* Bind the socket to the netlink sockaddr. */
  if (bind (sock, (struct sockaddr *) &snl, sizeof(snl)) < 0)
    {
      syslog(LOG_ERR, "In find_interface(): bind(): %m");
      close (sock);
      return RETURN_ERROR;
    }
  
  bzero (&snl, sizeof(snl));
  snl.nl_family = AF_NETLINK;

  req.nlh.nlmsg_len = sizeof(req);
  req.nlh.nlmsg_type = RTM_GETROUTE;
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
  req.nlh.nlmsg_pid = 0;
  req.g.rtgen_family = AF_INET;
  
  if (sendto(sock, (void *) &req, sizeof(req), 0,
	     (struct sockaddr *) &snl, sizeof(snl)) < 0)
    {
      syslog(LOG_ERR, "In find_interface(): sendto(): %m");
      close(sock);
      return RETURN_ERROR;
    }

  index = netlink_CheckRoute(sock, dest);
  close(sock);
  if (index >= 0)
    {
      if ((sock=socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	syslog(LOG_ERR, "In find_interface(): finding if: socket(): %m");
      else
	{
	  ifc.ifc_len = sizeof(buff);
	  ifc.ifc_buf = buff;
	  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
	    syslog(LOG_ERR, "In find_interface(): finding if: ioctl(): %m");
	  else
	    {
	      ifr = ifc.ifc_req;
	      for (i=0; i<(ifc.ifc_len/sizeof(struct ifreq)); i++)
		{
		  if (ifr[i].ifr_addr.sa_family == AF_INET)
		    {
		      if (ioctl(sock, SIOCGIFINDEX, &(ifr[i])) < 0)
			syslog(LOG_ERR,
			       "In find_interface(): ioctl(..GIFINDEX..): %m");
		      else
			{
			  if (ifr[i].ifr_ifindex == index)
			    {
			      memcpy(&(src->s_addr),
				     &(((struct sockaddr_in*)&ifr[i].ifr_addr)->
				       sin_addr.s_addr),
				     sizeof(struct in_addr));
			      if (namebuf)
				{
				  memset(namebuf, 0, namelen);
				  strncpy(namebuf, ifr[i].ifr_name, namelen-1);
				}
			      ret=index;
			    }
#if 0
			  printf("%d: %s %s\n", ifr[i].ifr_ifindex,
				 ifr[i].ifr_name,
				 inet_ntoa(((struct sockaddr_in*)&
					    ifr[i].ifr_addr)->sin_addr));
#endif
			}
		    }
		}
	    }
	  close(sock);
	}
    }
  return ret;
}


