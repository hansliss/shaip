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

#include <ctype.h>

#ifndef WIN32
#include "config.h"
#else
#define HAVE_STRING_H 1
#endif

#if HAVE_STRINGS_H==1
#include <strings.h>
#endif
#if HAVE_STRING_H==1
#include <string.h>
#endif

/* Functions for cleaning up random strings for logging */
int isjunk(char c)
{
  return ((c < ' ') || (c>126));
}

void dejunkifyforlog(char *s)
{
  unsigned int i;
  if (strlen(s)>32)
    s[32]='\0';
  for (i=0; i<strlen(s); i++)
    if (isjunk(s[i]))
      s[i]='.';
}

/* Remove line breaks at end of string */

int choppable(int c)
{
  return (isspace(c));
}

void chop(char *string)
{
  if (string)
    {
      while (strlen(string) && choppable(string[strlen(string)-1]))
	string[strlen(string)-1]='\0';
    }
}

/* Remove all blanks at the beginning and end of a string */

void cleanupstring(char *string)
{
  int i=strlen(string)-1;
  while (i>0 && isspace((int)string[i]))
    i--;
  string[i+1]='\0';
  i=0;
  while (isspace((int)string[i]))
    i++;
  memmove(string,&(string[i]),strlen(&(string[i]))+1);
}

