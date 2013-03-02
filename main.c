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
#define SYSLOG_NAMES
#define SYSLOG_NAMES_H
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>

#include "stringfunc.h"
#include "varlist.h"
#include "makeaddress.h"

#include "config.h"
#include "devicenode.h"
#include "socketnode.h"
#include "find_interface.h"
#include "icmpping.h"

#define BUFSIZE 1024

#define ROOT "<root>"

#define STATE_DOWN 0
#define STATE_UP 1
#define STATE_WARNING 2
#define STATE_ERROR 3

void usage(char *progname)
{
  fprintf(stderr, "Usage: %s -c <configuration file> -s <state file>\n", progname);
  fprintf(stderr, "\t[-a (report all)][-n <number of packets>] [-P <interpacket delay>]\n");
  fprintf(stderr, "\t[-T <timeout>] [-v (verbose)] [-t (report round trip time)]\n");
  fprintf(stderr, "\t[-w (report warnings)] [-D <delay ms between runs>]\n");
}

void freedevicelist(devicenode *head)
{
  devicenode tmp, tmp2;
  for (tmp=*head; tmp;)
    {
      tmp2=tmp;
      tmp=tmp->next;
      if (tmp2->devicename)
	free(tmp2->devicename);
      if (tmp2->parentname)
	free(tmp2->parentname);
      free(tmp2);
    }
  *head=NULL;
}

devicenode findnode(devicenode list, char *devname)
{
  devicenode tmpnode;
  for (tmpnode=list; tmpnode; tmpnode=tmpnode->next)
    if (!strcasecmp(devname, tmpnode->devicename))
      return tmpnode;
  return NULL;
}

/*
  Receive and handle all pending replies on all the open
  sockets.

  Parameters:
  'allsockets' (in): A list of currently open sockets
  'devicelist' (in): List of all devices
  'ident' (in): An identity for ICMP echo reply
  'timeout' (in): How many ms will we collect replies?
  'debug' (in): Debug flag
  */
void receive_replies(socketnode allsockets, devicenode devicelist, int ident, int timeout, int debug)
{
  fd_set myfdset;
  int maxsock=-1, i;
  socketnode tmpsock;
  struct timeval select_timeout;
  static unsigned char packet[4096];
  unsigned char from[16384];
  socklen_t alen;
  struct timeval starttime, endtime;
  struct timezone tz;
  devicenode tmpnode;
  int ready;

#if 0
  static char tmpbuf[BUFSIZE];
  long nbytes;
  tmpsock=allsockets;
  while (tmpsock)
    {
      ioctl(tmpsock->socket, FIONREAD, &nbytes);
      if (nbytes>0)
	{
	  sprintf(tmpbuf, "%ld bytes waiting on fd %d",nbytes, tmpsock->socket);
	  trace_msg(tmpbuf);
	}
      tmpsock=tmpsock->next;
    }
#endif

  /* Loop until select() says 'no' */
  while (1)
    {
      select_timeout.tv_sec=timeout/1000;
      select_timeout.tv_usec=1000*(timeout%1000);
      /* Initialize an fd_set with all the fd:s we are interested in */
      FD_ZERO(&myfdset);
      tmpsock=allsockets;
      while (tmpsock)
	{
	  FD_SET(tmpsock->socket, &myfdset);
	  if (tmpsock->socket > maxsock)
	    maxsock=tmpsock->socket;
	  tmpsock=tmpsock->next;
	}

      gettimeofday(&starttime,&tz);
      /* Check if there is anything to receive */
      if (select(maxsock+1, &myfdset, NULL, NULL, &select_timeout)>0)
	{
	  for (i=0; i<(maxsock+1); i++)
	    if (FD_ISSET(i, &myfdset))
	      {
		/* fprintf(stderr,"Packet received on fd %d\n", i);*/

		/* Receive a packet */
		alen=sizeof(from);
		if (recvfrom(i, packet, sizeof(packet), 0,
			     (struct sockaddr *)&from, &alen)<0)
		  syslog(LOG_ERR, "recvfrom(): %m");
		else /* recvfrom */
		  {
		    recv_icmpreply(devicelist, packet, sizeof(packet), 
				   (struct sockaddr_in *)from,
				   ident, debug);
		  }
	      }
	}
      else /* select */
	break;
      gettimeofday(&endtime,&tz);
      timeout-=(1000*(endtime.tv_sec-starttime.tv_sec) + (endtime.tv_usec-starttime.tv_usec)/1000);
      ready=1;
      for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
	if (!(tmpnode->gotreply))
	  ready=0;
      if (ready)
	break;
    } /* while */
  return;
}

int main(int argc, char *argv[])
{
  int o;
  char *conffilename=NULL;
  char *statefilename=NULL;
  FILE *infile, *sfile;
  int report_all=0;
  int number_of_packets=3;
  int pause_between_packets=5;
  int rttime=0;
  int receive_timeout=2000;
  int changed;
  time_t now;
  char timestamp[50];
  int repwarn=0;
  int type,r;
  char ifname[32];
  struct routingdata_s rd;
  struct addrinfo *devaddress;
  char devip[32];
  struct addrinfo hints={0,
                         PF_UNSPEC,
			 SOCK_STREAM,
                         IPPROTO_TCP,
                         0, NULL, NULL, NULL};

  static char line[BUFSIZE], tmpbuf[BUFSIZE], infilename[BUFSIZE];
  char *p;
  namelist items=NULL;
  int lno=0, n;
  char *devname, *parentname;
  int verbose=0;
  int delay=1;

  devicenode devicelist=NULL,
    tmpnode, tmpnode2;

  struct timezone tz;

  socketnode rawsockets=NULL;

  memset(&rd, 0, sizeof(rd));

  // check options -c <configuration file> -s <state file> [-a]
  while ((o=getopt(argc, argv, "c:s:an:P:T:tvwD:"))!=-1)
    {
      switch (o)
	{
	case 'c':
	  conffilename=optarg;
	  break;
	case 's':
	  statefilename=optarg;
	  break;
	case 'a':
	  report_all=1;
	  break;
	case 'n':
	  number_of_packets=atoi(optarg);
	  break;
	case 'P':
	  pause_between_packets=atoi(optarg);
	  break;
	case 'T':
	  receive_timeout=1000*atoi(optarg);
	  break;
	case 't':
	  rttime=1;
	  break;
	case 'v':
	  verbose++;
	  break;
	case 'w':
	  repwarn=1;
	  break;
	case 'D':
	  delay=atoi(optarg);
	  break;
	default:
	  usage(argv[0]);
	  return -1;
	  break;
	}
    }
  if (optind<argc)
    {
      usage(argv[0]);
      return -1;
    }

  if (!conffilename || !statefilename)
    {
      usage(argv[0]);
      return -1;
    }

  // read configuration file and state file
  if (!(infile=fopen(conffilename, "r")))
    {
      perror(infilename);
      return -2;
    }
  netlink_maybeupdateroutes(&rd,0);
  while (fgets(line, sizeof(line), infile))
    {
      lno++;
      chop(line);
      if ((p=strchr(line, '#'))!=NULL)
	*p='\0';
      cleanupstring(line);
      if (!strlen(line))
	continue;

      //     split name:address[:[parentname]]
      if ((n=splitstring(line, ':', &items)) < 2 || n > 3)
	{
	  fprintf(stderr, "Syntax error in %s on line %d\n", conffilename, lno);
	  fclose(infile);
	  freedevicelist(&devicelist);
	  return -3;
	}
      devname=items->name;
      if ((r=getaddrinfo(items->next->name, NULL, &hints, &devaddress))!=0) {
	if (r==EAI_SYSTEM) perror("getaddrinfo()");
	else fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(r));
      }
      getnameinfo(devaddress->ai_addr, devaddress->ai_addrlen, devip, sizeof(devip), NULL, 0, NI_NUMERICHOST);
      if (r != 0 || devaddress->ai_family != AF_INET) {
	fprintf(stderr, "Bad address %s in %s on line %d\n", items->next->name,
		conffilename, lno);
	fclose(infile);
	freedevicelist(&devicelist);
	return -4;
      }
      if (items->next->next && strlen(items->next->next->name))
	parentname=items->next->next->name;
      else
	parentname=ROOT;
      if (!(tmpnode=(devicenode)calloc(sizeof(struct devicenode_s), 1)))
	{
	  perror("calloc()");
	  return -3;
	}
      if (findnode(devicelist, devname))
	{
	  fprintf(stderr, "Duplicate name %s in %s on line %d\n", devname,
		  conffilename, lno);
	  fclose(infile);
	  freedevicelist(&devicelist);
	  return -4;
	}
      tmpnode->nreplies=0;
      tmpnode->laststate=STATE_UP;
      tmpnode->state=STATE_UP;
      tmpnode->dontreport=0;
      tmpnode->devicename=strdup(devname);
      tmpnode->parentname=strdup(parentname);
      tmpnode->rttime=0;
      
      memcpy(&(tmpnode->address), devaddress->ai_addr, devaddress->ai_addrlen);
      if ((type=find_interface(&rd, (struct sockaddr *)(&(tmpnode->address)), sizeof(tmpnode->address), &(tmpnode->interface_no), ifname, sizeof(ifname),
			       (struct sockaddr *)(&(tmpnode->srcaddress)), sizeof(tmpnode->srcaddress), 0)) == USER_TYPE_NONE) {
	fprintf(stderr, "Unreachable device %s in %s on line %d\n", devip, conffilename, lno);
	fclose(infile);
	freedevicelist(&devicelist);
	return -5;
      }
      tmpnode->next=devicelist;
      devicelist=tmpnode;

      freenamelist(&items);
    }
  fclose(infile);

  // traverse list and find undefined objects. error message & stop
  for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
    {
      if (!findnode(devicelist, tmpnode->parentname) && strcasecmp(tmpnode->parentname, ROOT))
	{
	  fprintf(stderr, "Unknown parent name %s referred to in %s\n", tmpnode->parentname,
		  conffilename);
	  fclose(infile);
	  freedevicelist(&devicelist);
	  return -4;
	}
    }
  if ((infile=fopen(statefilename, "r"))!=NULL)
    {
      while (fgets(line, sizeof(line), infile))
	{
	  chop(line);
	  if ((p=strchr(line, '#'))!=NULL)
	    *p='\0';
	  cleanupstring(line);
	  if (!strlen(line))
	    continue;

	  if (((n=splitstring(line, ':', &items))==2 || n==3) && (tmpnode=findnode(devicelist, items->name)))
	    {
	      switch (items->next->name[0])
		{
		case 'd':
		case 'D':
		  tmpnode->laststate=STATE_DOWN;
		  break;
		case 'u':
		case 'U':
		  tmpnode->laststate=STATE_UP;
		  break;
		case 'w':
		case 'W':
		  tmpnode->laststate=STATE_WARNING;
		  break;
		case 'e':
		case 'E':
		  tmpnode->laststate=STATE_ERROR;
		  break;
		}
	      if (items->next->next)
		strncpy(tmpnode->dtstamp, items->next->next->name, sizeof(tmpnode->dtstamp));
	      else
		tmpnode->dtstamp[0]=0;
	      tmpnode->dtstamp[sizeof(tmpnode->dtstamp)-1]='\0';
	      freenamelist(&items);
	    }
	}

      fclose(infile);
    }

  if (!(sfile=fopen(statefilename, "w")))
    {
      perror(statefilename);
      return -2;
    }

  if (verbose>1)
    for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
      {
	strcpy(tmpbuf, inet_ntoa(tmpnode->srcaddress.sin_addr));
	printf ("%s: address=%s, srcaddress=%s, parent=%s, interface=%d\n", tmpnode->devicename, inet_ntoa(tmpnode->address.sin_addr), tmpbuf, tmpnode->parentname, tmpnode->interface_no);
      }

  for (n=0; (number_of_packets==0) || n<number_of_packets; n++)
    {
      if (verbose==1)
	{
	  fputc('.', stderr);
	  fflush(stderr);
	}
      if (verbose>1)
	fprintf(stderr, "*****  Run %3d ******\n", n+1);
      //  traverse tree and send packets with a small pause between each
      for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
	{
	  // send an icmp packet
	  if (!send_icmpping(&rawsockets, tmpnode, 4711+n))
	    {
	      fprintf(stderr, "ICMP send to %s failed.\n", tmpnode->devicename);
	      tmpnode->state=STATE_ERROR;
	    }
	  gettimeofday(&(tmpnode->senttime), &tz);
	  tmpnode->gotreply=0;
	  receive_replies(rawsockets, devicelist, 4711+n, pause_between_packets, verbose>2);
	}
      receive_replies(rawsockets, devicelist, 4711+n, receive_timeout, verbose>2);
      usleep(1000*delay);
    }
  if (verbose==1)
    {
      fputc('\n', stderr);
      fflush(stderr);
    }

  for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
    {
      if (tmpnode->state!=STATE_ERROR)
	{
	  if (tmpnode->nreplies==0)
	    tmpnode->state=STATE_DOWN;
	  else if (tmpnode->nreplies==number_of_packets)
	    tmpnode->state=STATE_UP;
	  else
	    tmpnode->state=STATE_WARNING;
	}
    }

  if (report_all)
    {
      for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
	{
	  if (rttime)
	    printf("%s:%s:%.2f\n", 
		   tmpnode->devicename,
		   (tmpnode->state==STATE_UP)?"up":
		   ((tmpnode->state==STATE_DOWN)?"down":
		    ((tmpnode->state==STATE_WARNING)?(repwarn?"warning":"up"):"error"))
		   ,(tmpnode->nreplies>0)?tmpnode->rttime/(double)(tmpnode->nreplies):-1
		   );
	  else
	    printf("%s:%s\n", 
		   tmpnode->devicename,
		   (tmpnode->state==STATE_UP)?"up":
		   ((tmpnode->state==STATE_DOWN)?"down":
		    ((tmpnode->state==STATE_WARNING)?(repwarn?"warning":"up"):"error"))
		   );
	}
    }

  //traverse tree, depth-first
  // cut branches wherever a node is down (no reply and no reply from any nodes below)

  changed=1;
  while (changed)
    {
      changed=0;
      for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
	{
	  if (tmpnode->state == STATE_DOWN)
	    {
	      for (tmpnode2=devicelist; tmpnode2; tmpnode2=tmpnode2->next)
		{
		  if (!strcasecmp(tmpnode2->parentname, tmpnode->devicename) && !tmpnode2->dontreport)
		    {
		      if (verbose>2)
			fprintf(stderr, "Not reporting %s since %s is down\n", tmpnode2->devicename, tmpnode2->parentname);
		      tmpnode2->dontreport=1;
		      changed=1;
		    }
		}
	    }
	}
    }

  time(&now);
  strncpy(timestamp, ctime(&now), sizeof(timestamp));
  timestamp[sizeof(timestamp)-1]='\0';
  for (n=0; n<strlen(timestamp); n++)
    if (timestamp[n]==':')
      timestamp[n]='.';
  for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
    {
      if (verbose>1)
	{
	  fprintf(stderr, "%s was %s is now %s\n",  tmpnode->devicename,
		  (tmpnode->laststate==STATE_UP)?"up":
		  ((tmpnode->laststate==STATE_DOWN)?"down":
		   ((tmpnode->laststate==STATE_WARNING)?(repwarn?"warning":"up"):"error")),
		  (tmpnode->state==STATE_UP)?"up":
		  ((tmpnode->state==STATE_DOWN)?"down":
		   ((tmpnode->state==STATE_WARNING)?(repwarn?"warning":"up"):"error")));
	}

      if (!(tmpnode->dontreport))
	{
	  fprintf(sfile, "%s:%s", tmpnode->devicename,
		  (tmpnode->state==STATE_UP)?"up":
		  ((tmpnode->state==STATE_DOWN)?"down":
		   ((tmpnode->state==STATE_WARNING)?"warning":"error")));
	  if (tmpnode->state==STATE_DOWN)
	    {
	      if (strlen(tmpnode->dtstamp))
		fprintf(sfile, ":%s\n", tmpnode->dtstamp);
	      else
		fprintf(sfile, ":%s", timestamp);
	    }
	  else
	    fputc('\n', sfile);
	}
    }
  fclose(sfile);

  if (report_all)
    {
      freedevicelist(&devicelist);
      return 0;
    }

  for (tmpnode=devicelist; tmpnode; tmpnode=tmpnode->next)
    {
      if (!repwarn)
	{
	  if (tmpnode->state==STATE_WARNING)
	    tmpnode->state=STATE_UP;
	  if (tmpnode->laststate==STATE_WARNING)
	    tmpnode->laststate=STATE_UP;
	}
      if (!tmpnode->dontreport && (tmpnode->state != tmpnode->laststate))
	{
	  if (rttime)
	    printf("%s:%s:%.2f\n",
		   tmpnode->devicename,
		   (tmpnode->state==STATE_UP)?"up":
		   ((tmpnode->state==STATE_DOWN)?"down":
		    ((tmpnode->state==STATE_WARNING)?(repwarn?"warning":"up"):"error"))
		   ,(tmpnode->nreplies>0)?
		   tmpnode->rttime/(double)(tmpnode->nreplies):
		   -1
		   );
	  else
	    printf("%s:%s\n",
		   tmpnode->devicename,
		   (tmpnode->state==STATE_UP)?"up":
		   ((tmpnode->state==STATE_DOWN)?"down":
		    ((tmpnode->state==STATE_WARNING)?(repwarn?"warning":"up"):"error"))
		   );
	}
    }
  freedevicelist(&devicelist);

  return 0;
}
