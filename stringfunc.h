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

#ifndef STRINGFUNC_H
#define STRINGFUNC_H

/* Remove junk characters from a string for logging and stuff */
void dejunkifyforlog(char *s);

/*
  Remove all blanks at the beginning and end of the string 'string' (in/out).
  */
void cleanupstring(char *string);

/*
  Chop off all whitespace characters (including newline characters etc)
  from the end of the string 'string' (in/out).
  */
void chop(char *string);

/* Base64 encode/decode */
int b64_encode(unsigned char *indata, int indatalen, char *result, int reslen);
int b64_decode(unsigned char *indata, int indatalen, char *result, int reslen);

#endif
