/*
 *	PostgreSQL type definitions for the INET and CIDR types.
 *
 *	src/backend/utils/adt/network.c
 *
 *	Jon Postel RIP 16 Oct 1998
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "pgsql_inet.h"

/**
 */
#define Min(x, y)			((x) < (y) ? (x) : (y))
#define HIGHBIT				(0x80)
#define IS_HIGHBIT_SET(ch)	((unsigned char)(ch) & HIGHBIT)

static int bitncmp(void *l, void *r, int n);
static int addressOK(unsigned char *a, int bits, int family);
static int ip_addrsize(inet *inetptr);

/*
 *	Access macros.	We use VARDATA_ANY so that we can process short-header
 *	varlena values without detoasting them.  This requires a trick:
 *	VARDATA_ANY assumes the varlena header is already filled in, which is
 *	not the case when constructing a new value (until SET_INET_VARSIZE is
 *	called, which we typically can't do till the end).  Therefore, we
 *	always initialize the newly-allocated value to zeroes (using palloc0).
 *	A zero length word will look like the not-1-byte case to VARDATA_ANY,
 *	and so we correctly construct an uncompressed value.
 *
 *	Note that ip_maxbits() and SET_INET_VARSIZE() require
 *	the family field to be set correctly.
 */

#define ip_family(inetptr) \
	(inetptr->family)

#define ip_bits(inetptr) \
	(inetptr->bits)

#define ip_addr(inetptr) \
	(inetptr->ipaddr)

#define ip_maxbits(inetptr) \
	(ip_family(inetptr) == PGSQL_AF_INET ? 32 : 128)

/*
 * int
 * bitncmp(l, r, n)
 *		compare bit masks l and r, for n bits.
 * return:
 *		-1, 1, or 0 in the libc tradition.
 * note:
 *		network byte order assumed.  this means 192.5.5.240/28 has
 *		0x11110000 in its fourth octet.
 * author:
 *		Paul Vixie (ISC), June 1996
 */
static int
bitncmp(void *l, void *r, int n)
{
	u_int		lb,
				rb;
	int			x,
				b;

	b = n / 8;
	x = memcmp(l, r, b);
	if (x || (n % 8) == 0)
		return x;

	lb = ((const u_char *) l)[b];
	rb = ((const u_char *) r)[b];
	for (b = n % 8; b > 0; b--)
	{
		if (IS_HIGHBIT_SET(lb) != IS_HIGHBIT_SET(rb))
		{
			if (IS_HIGHBIT_SET(lb))
				return 1;
			return -1;
		}
		lb <<= 1;
		rb <<= 1;
	}
	return 0;
}

/**
 * Check if address have good state.
 */
static int
addressOK(unsigned char *a, int bits, int family)
{
	int			byte;
	int			nbits;
	int			maxbits;
	int			maxbytes;
	unsigned char mask;

	if (family == PGSQL_AF_INET)
	{
		maxbits = 32;
		maxbytes = 4;
	}
	else
	{
		maxbits = 128;
		maxbytes = 16;
	}
	
	if (bits >= maxbits)
		return 1;

	byte = bits / 8;

	nbits = bits % 8;
	mask = 0xff;
	if (bits != 0)
		mask >>= nbits;

	while (byte < maxbytes)
	{
		if ((a[byte] & mask) != 0)
			return 0;
		mask = 0xff;
		byte++;
	}

	return 1;
}

/*
 * Return the number of bytes of address storage needed for this data type.
 */
static int
ip_addrsize(inet *inetptr)
{
	switch (ip_family(inetptr))
	{
		case PGSQL_AF_INET:
			return 4;
		case PGSQL_AF_INET6:
			return 16;
		default:
			return 0;
	}
}

/*
 * Common INET/CIDR input routine
 */
int
pgsql_network_in(inet **dstp, char *src, int is_cidr)
{
	int			bits;
	inet	   *dst;

	*dstp = NULL;

	dst = (inet *) calloc(1, sizeof(inet));
	if (dst == NULL)
		return PGSQL_ERROR_MEMORY;

	/*
	 * First, check to see if this is an IPv6 or IPv4 address.	IPv6 addresses
	 * will have a : somewhere in them (several, in fact) so if there is one
	 * present, assume it's V6, otherwise assume it's V4.
	 */

	if (strchr(src, ':') != NULL)
		ip_family(dst) = PGSQL_AF_INET6;
	else
		ip_family(dst) = PGSQL_AF_INET;

	bits = inet_net_pton(ip_family(dst), src, ip_addr(dst),
						 is_cidr ? ip_addrsize(dst) : -1);
	if ((bits < 0) || (bits > ip_maxbits(dst)))
		return PGSQL_ERROR_ADDRESS_FORMAT; 

	/*
	 * Error check: CIDR values must not have any bits set beyond the masklen.
	 */
	if (is_cidr)
		if (!addressOK(ip_addr(dst), bits, ip_family(dst)))
			return PGSQL_ERROR_ADDRESS_CIDR_FORMAT; 

	ip_bits(dst) = bits;

	*dstp = dst;

	return PGSQL_OK;
}


/*
 * Common INET/CIDR output routine
 */
int
pgsql_network_out(char **dstp, inet *src, int is_cidr)
{
	char		tmp[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255/128")];
	char	   *dst;
	int			len;

	*dstp = NULL;

	dst = inet_net_ntop(ip_family(src), ip_addr(src), ip_bits(src),
						tmp, sizeof(tmp));
	if (dst == NULL)
		return PGSQL_ERROR_ADDRESS_FORMAT;

	/* For CIDR, add /n if not present */
	if (is_cidr && strchr(tmp, '/') == NULL) {
		len = strlen(tmp);
		snprintf(tmp + len, sizeof(tmp) - len, "/%u", ip_bits(src));
	}

	dst = strdup(tmp);

	return PGSQL_OK;
}

/*
 *	Basic comparison function for sorting and inet/cidr comparisons.
 *
 * Comparison is first on the common bits of the network part, then on
 * the length of the network part, and then on the whole unmasked address.
 * The effect is that the network part is the major sort key, and for
 * equal network parts we sort on the host part.  Note this is only sane
 * for CIDR if address bits to the right of the mask are guaranteed zero;
 * otherwise logically-equal CIDRs might compare different.
 */
int32_t
pgsql_network_cmp(inet *a1, inet *a2)
{
	if (ip_family(a1) == ip_family(a2))
	{
		int			order;

		order = bitncmp(ip_addr(a1), ip_addr(a2),
						Min(ip_bits(a1), ip_bits(a2)));
		if (order != 0)
			return order;
		order = ((int) ip_bits(a1)) - ((int) ip_bits(a2));
		if (order != 0)
			return order;
		return bitncmp(ip_addr(a1), ip_addr(a2), ip_maxbits(a1));
	}

	return ip_family(a1) - ip_family(a2);
}

/*
 *  Boolean ordering tests.
 */
int
pgsql_network_lt(inet *a1, inet *a2)
{
	return (pgsql_network_cmp(a1, a2) < 0);
}

int
pgsql_network_le(inet *a1, inet *a2)
{
	return (pgsql_network_cmp(a1, a2) <= 0);
}

int
pgsql_network_eq(inet *a1, inet *a2)
{
	return (pgsql_network_cmp(a1, a2) == 0);
}

int
pgsql_network_ge(inet *a1, inet *a2)
{
	return (pgsql_network_cmp(a1, a2) >= 0);
}

int
pgsql_network_gt(inet *a1, inet *a2)
{
	return (pgsql_network_cmp(a1, a2) > 0);
}

int
pgsql_network_ne(inet *a1, inet *a2)
{
	return (pgsql_network_cmp(a1, a2) != 0);
}

/*
 *  Boolean network-inclusion tests.
 */
int
pgsql_network_sub(inet *a1, inet *a2)
{
	if (ip_family(a1) == ip_family(a2))
		return (ip_bits(a1) > ip_bits(a2)
				&& bitncmp(ip_addr(a1), ip_addr(a2), ip_bits(a2)) == 0);

	return 0;
}

int
pgsql_network_subeq(inet *a1, inet *a2)
{
	if (ip_family(a1) == ip_family(a2))
		return (ip_bits(a1) >= ip_bits(a2)
				&& bitncmp(ip_addr(a1), ip_addr(a2), ip_bits(a2)) == 0);

	return 0;
}

int
pgsql_network_sup(inet *a1, inet *a2)
{
	if (ip_family(a1) == ip_family(a2))
		return (ip_bits(a1) < ip_bits(a2)
				&& bitncmp(ip_addr(a1), ip_addr(a2), ip_bits(a2)) == 0);

	return 0;
}

int
pgsql_network_supeq(inet *a1, inet *a2)
{
	if (ip_family(a1) == ip_family(a2))
		return (ip_bits(a1) <= ip_bits(a2)
				&& bitncmp(ip_addr(a1), ip_addr(a2), ip_bits(a2)) == 0);

	return 0;
}
