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

#include <linux/sockios.h>

int send_icmpping(socketnode *rawsockets, devicenode dev, int ident);
int recv_icmpreply(devicenode devicelist, unsigned char *buf, int len, struct sockaddr_in *from, int ident, int debug);

