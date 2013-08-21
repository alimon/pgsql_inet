/*-------------------------------------------------------------------------
 *
 * inet.h
 *	  Declarations for operations on INET datatypes.
 *
 *
 * Portions Copyright (c) 1996-2011, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/utils/inet.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef PGSQL_INET_H
#define PGSQL_INET_H

#include <stdint.h>

/**
 * PGSQL_INET errors
 */
#define PGSQL_OK						 0
#define PGSQL_ERROR_MEMORY				-1
#define PGSQL_ERROR_ADDRESS_FORMAT		-2
#define PGSQL_ERROR_ADDRESS_CIDR_FORMAT	-3

/*
 *	This is the internal storage format for IP addresses
 *	(both INET and CIDR datatypes):
 */
typedef struct
{
	unsigned char family;		/* PGSQL_AF_INET or PGSQL_AF_INET6 */
	unsigned char bits;			/* number of bits in netmask */
	unsigned char ipaddr[16];	/* up to 128 bits of address */
} inet;

/*
 * Referencing all of the non-AF_INET types to AF_INET lets us work on
 * machines which may not have the appropriate address family (like
 * inet6 addresses when AF_INET6 isn't present) but doesn't cause a
 * dump/reload requirement.  Existing databases used AF_INET for the family
 * type on disk.
 */
#define PGSQL_AF_INET	(AF_INET + 0)
#define PGSQL_AF_INET6	(AF_INET + 1)


/*
 *	This is the internal storage format for MAC addresses:
 */
typedef struct macaddr
{
	unsigned char a;
	unsigned char b;
	unsigned char c;
	unsigned char d;
	unsigned char e;
	unsigned char f;
} macaddr;

/**
 * Interface functions.
 */
int pgsql_network_in(inet **, char *src, int is_cidr);
int pgsql_network_out(char **, inet *src, int is_cidr);
int32_t pgsql_network_cmp(inet *a1, inet *a2);

/**
 * Boolean ordering tests.
 */
int pgsql_network_lt(inet *a1, inet *a2);
int pgsql_network_le(inet *a1, inet *a2);
int pgsql_network_eq(inet *a1, inet *a2);
int pgsql_network_ge(inet *a1, inet *a2);
int pgsql_network_gt(inet *a1, inet *a2);
int pgsql_network_ne(inet *a1, inet *a2);

/**
 * Boolean inclusion tests.
 */
int pgsql_network_sub(inet *a1, inet *a2);
int pgsql_network_subeq(inet *a1, inet *a2);
int pgsql_network_sup(inet *a1, inet *a2);
int pgsql_network_supeq(inet *a1, inet *a2);

#endif   /* PGSQL_INET_H */
