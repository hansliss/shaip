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

#ifndef VARLIST_H
#define VARLIST_H

/********************************

 A list node for handling variable lists and
 functions to make use of it

********************************/

typedef struct varnode
{
  char *name;
  char *value;
  struct varnode *next;
} *varlist;

/*
  Add an attribute/value pair to the list 'vars' (in/out).
  'name' and 'value' are in parameters and their contents
  will be copied.
  */
void addvar(varlist *vars, char *name, char *value);

/*
  Change or add an attribute value. See addvar().
  */
void setvar(varlist *vars, char *name, char *value);

/*
  Delete an attribute.
  */
void delvar(varlist *vars, char *name);

/*
  Find and return a node in 'vars' (in) with the
  attribute name 'name' (in).
  */
char *findvar(varlist vars, char *name);

/*
  Release all memory allocated for the list 'vars' (in/out) and
  set it to NULL.
  */
void freevarlist(varlist *vars);


/*******************************

 Another list node for handling simple name lists.
 Very useful for splitstring().

 *******************************/

typedef struct namenode
{
  char *name;
  struct namenode *next;
} *namelist;

/*
  Add a new name node to 'names' (in/out) with the name 'name' (in).
  'name' will be copied.
  */
void addname(namelist *names, char *name);

/*
  Add a new name node to the front of 'names' (in/out) with the name 'name' (in).
  'name' will be copied.
  */
void addname_front(namelist *names, char *name);

/*
  Find and return a node in 'names' (in) with the name 'name' (in)
  and return it, or NULL if nothing found.
  */
int findname(namelist names, char *name);

/*
  Release all memory allocated for the list 'names' (in/out) and
  set it to NULL.
  */
void freenamelist(namelist *names);

/*
  Split the string 'string' (in) into components using the delimiter
  'splitter' (in). Add the components to 'substrings' (in/out), which
  must be initialized prior to calling this function.
  The substrings will be cleaned up with cleanupstring() (see below).
  */
int splitstring(char *string, char splitter, namelist *substrings);

#endif
