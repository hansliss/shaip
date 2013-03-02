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
#include <string.h>
#include <sys/types.h>

#ifndef WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include "config.h"
#else
#define HAVE_STRING_H 1
#define strcasecmp(a,b) _stricmp((a),(b))
#include <process.h>
#include <io.h>
#include <winsock2.h>
#endif

#include "makeaddress.h"

/* Translate an ASCII hostname or ip address to a struct in_addr - return 0
   if unable */
int makeaddress(char *name_or_ip, struct in_addr *res)
{
  struct hostent *listen_he;
  if (!strcmp(name_or_ip, "any"))
    {
      memset(res, 0, sizeof(res));
      return 1;
    }
  
#ifdef WIN32
  if (!(res->S_un.S_addr=inet_addr(name_or_ip)))
#else
  if (!inet_aton(name_or_ip,res))
#endif
    {
      if (!(listen_he=gethostbyname(name_or_ip)))
	return 0;
      else
	{
	  memcpy(res, listen_he->h_addr_list[0], sizeof(res));
	  return 1;
	}
    }
  else
    return 1;
}

/* Translate a service name or port number (as a string) into an NBO
   integer. Return 0 on failure. */

int makeport(char *name_or_port)
{
  struct servent *listen_se;
  unsigned short listen_port;
  char *c;
  listen_port=(unsigned short)strtol(name_or_port,&c,10);
  if (c != '\0')
    {
      if (!(listen_se=getservbyname(name_or_port, "tcp")))
	{
	  if (sscanf(name_or_port,"%hu",&listen_port)<1)
	    {
	      listen_port=0;
	    }
	  else
	    listen_port=htons(listen_port);
	}
      else
	listen_port=listen_se->s_port;
    }
  else
    listen_port=htons(listen_port);
  return listen_port;
}

