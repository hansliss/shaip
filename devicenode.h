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

 */

typedef struct devicenode_s
{
  char *devicename;
  char *parentname;

  struct in_addr address;
  struct in_addr srcaddress;
  int interface_no;

  int nreplies;
  int gotreply;
 
  int state;
  int laststate;

  char dtstamp[50];

  double rttime;
  struct timeval senttime;

  int dontreport;

  /* Link */
  struct devicenode_s *next;
} *devicenode;
