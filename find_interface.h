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
  Determine the interface index and source address to use for
  outgoing packet to a given destination.

  Parameters:
  'dest' (in): The destination we are looking for
  'src' (out): The source address to use - preallocated!

  'namebuf' (out): A buffer for the interface name - preallocated - or NULL.
  'namelen' (in): The size of the 'namebuf'

  Returns the interface index or <0 if an error has occured.

  syslog() is used here so openlog() before calling this
  */
int find_interface(struct in_addr *dest, struct in_addr *src, char *namebuf, int namelen);

