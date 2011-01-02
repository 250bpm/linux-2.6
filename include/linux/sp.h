/*
 * SP: An implementation of SP sockets.
 *
 * Copyright 2010 VMware, Inc.
 */

#ifndef _LINUX_SP_H
#define _LINUX_SP_H

#define SP_ENDPOINT_MAX   108

struct sockaddr_sp {
	sa_family_t ssp_family; /* AF_SP */
	char ssp_endpoint[SP_ENDPOINT_MAX];  /* endpoint name */
};

#endif /* _LINUX_SP_H */
