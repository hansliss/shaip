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

/*
  A structure for keeping track of a list of sockets and misc data
  for them.
  */

typedef struct socketnode_s
{
  /* IP address to use as source address */
  struct in_addr srcaddress;

  /* The socket's fd */
  int socket;

  /* Link */
  struct socketnode_s *next;
} *socketnode;
