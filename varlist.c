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

#include <stdlib.h>
#include <ctype.h>

#ifdef WIN32
#define strcasecmp(a,b) _stricmp((a),(b))
#define strncasecmp(a,b,c) _strnicmp((a),(b), (c))
#define HAVE_STRING_H 1
#else
#include "config.h"
#endif

#if HAVE_STRINGS_H==1
#include <strings.h>
#endif
#if HAVE_STRING_H==1
#include <string.h>
#endif
#include "stringfunc.h"
#include "varlist.h"

/* Add a name:value pair to the end of a 'varlist'.
   Cease to function on allocation errors */

void addvar(varlist *vars, char *name, char *value)
{
  if ((*vars) != NULL)
    addvar(&((*vars)->next),name,value);
  else
    {
      (*vars)=(struct varnode *)malloc(sizeof(struct varnode));
      if (!(*vars))
	{
/*	  perror("malloc()");*/
	  exit(17);
	}
      (*vars)->next=NULL;
      (*vars)->name=(char *)malloc(strlen(name)+1);
      if (!((*vars)->name))
	{
/*	  perror("malloc()");*/
	  exit(17);
	}
      strcpy((*vars)->name,name);
      (*vars)->value=(char *)malloc(strlen(value)+1);
      if (!((*vars)->value))
	{
/*	  perror("malloc()");*/
	  exit(17);
	}
      strcpy((*vars)->value,value);
    }
}

void setvar(varlist *vars, char *name, char *value)
{
  varlist tmpvar;
  if (!(*vars))
    {
      if (value)
	addvar(vars, name, value);
      return;
    }
  if (strcasecmp((*vars)->name, name))
    setvar(&((*vars)->next), name, value);
  else
    {
      if (value)
	{
	  if (!strcasecmp((*vars)->value, value))
	    return;
	  else
	    {
	      if (strlen(value) > strlen((*vars)->value))
		(*vars)->value=realloc((*vars)->value, strlen(value)+1);
	      strcpy((*vars)->value, value);
	    }
	}
      else
	{
	  tmpvar=(*vars);
	  (*vars)=(*vars)->next;
	  free(tmpvar->name);
	  free(tmpvar->value);
	  free(tmpvar);
	}
    }
}

void delvar(varlist *vars, char *name)
{
  setvar(vars, name, NULL);
}

char *findvar(varlist vars, char *name)
{
  varlist tmplist=vars;
  while (tmplist)
    {
      if (!strcasecmp(tmplist->name,name))
	return tmplist->value;
      tmplist=tmplist->next;
    }
  return NULL;
}

/* Return all the memory allocated to a 'varlist' */

void freevarlist(varlist *vars)
{
  if ((*vars)==NULL)
    return;
  freevarlist(&((*vars)->next));
  free((*vars)->name);
  free((*vars)->value);
  free((*vars));
  (*vars)=NULL;
}

/* Add an item to the end of a 'namelist'.
   Cease to function on allocation errors */

void addname(namelist *names, char *name)
{
  if ((*names) != NULL)
    addname(&((*names)->next),name);
  else
    {
      (*names)=(struct namenode *)malloc(sizeof(struct namenode));
      if (!(*names))
	{
/*	  perror("malloc()");*/
	  exit(17);
	}
      (*names)->next=NULL;
      (*names)->name=(char *)malloc(strlen(name)+1);
      if (!((*names)->name))
	{
/*	  perror("malloc()");*/
	  exit(17);
	}
      strcpy((*names)->name,name);
    }
}

/* Add an item to the end of a 'namelist'.
   Cease to function on allocation errors */

void addname_front(namelist *names, char *name)
{
  namelist tmpname;
  tmpname=(struct namenode *)malloc(sizeof(struct namenode));
  tmpname->next=(*names);
  tmpname->name=(char *)malloc(strlen(name)+1);
  if (!(tmpname->name))
    exit(17);
  strcpy(tmpname->name, name);
  (*names)=tmpname;
}

/*
  Find an item in 'namelist'. Return 0 if not found, otherwise something
  else.
  */

int findname(namelist names, char *name)
{
  namelist tmplist=names;
  while (tmplist && (strcasecmp(tmplist->name, name)))
    tmplist=tmplist->next;
  return (tmplist!=NULL);
}

/* Return all the memory allocated to a 'namelist' */

void freenamelist(namelist *names)
{
  if ((*names)==NULL)
    return;
  freenamelist(&((*names)->next));
  free((*names)->name);
  free((*names));
  (*names)=NULL;
}

/* Split a string into substrings, returning the number of substrings found. */

int splitstring(char *string, char splitter, namelist *substrings)
{
  char *p1, *p2;  /* Pointers for walking the string */
  char *tmpbuf;
  int found=0;
  if (!(tmpbuf=(char*)malloc(strlen(string)+1)))
    return 0;
  strcpy(tmpbuf,string); /* Preserve the original string */
  p1=tmpbuf;
  while (*(p1))
    {
      if ((p2=strchr(p1,splitter))!=NULL)
	{
	  *(p2++)='\0';
	  cleanupstring(p1);  /* cleanupstring() is supposed to be able to handle this */
	  addname(substrings,p1);
	  found++;
	  p1=p2;
	}
      else
	if (strlen(p1)>0 || found==0)
	  {
	    cleanupstring(p1);  /* cleanupstring() is supposed to be able to handle this */
	    addname(substrings, p1);
	    p1+=strlen(p1);
	    found++;
	  }
    }
  free(tmpbuf);
  return found;
}

