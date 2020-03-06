/*
 *			GPAC - Multimedia Framework C SDK
 *
 *			Authors: Rodolphe Fouquet
 *			Copyright (c) Telecom ParisTech 2000-2020
 *					All rights reserved
 *
 *  This file is part of GPAC / PCAP input filter
 *
 *  GPAC is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  GPAC is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _IN_PCAP_H_
#define _IN_PCAP_H_

/*module interface*/
#include <gpac/filters.h>
#include <gpac/constants.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>


#define GF_PCAP_MAX_PKT_SIZE 8192
typedef struct GF_PcapInputCtx
{   
    // TODO: add filters & TCP
	char *src;
    
	GF_FilterPid *pid;
    FILE *fd;
    Bool isEthernet;
    u8 buffer[GF_PCAP_MAX_PKT_SIZE];
} GF_PcapInputCtx;

typedef struct GF_PcapFileHeader
{
    u32 magic_number;  /* magic number */
    u16 version_major; /* major version number */
    u16 version_minor; /* minor version number */
    s32 thiszone;       /* GMT to local correction */
    u32 sigfigs;       /* accuracy of timestamps */
    u32 snaplen;       /* max length of captured packets, in octets */
    u32 network;       /* data link type */
} GF_PcapFileHeader;

typedef struct GF_PcapPacketHeader
{
    u32 ts_sec;   /* timestamp seconds */
    u32 ts_usec;  /* timestamp microseconds */
    u32 incl_len; /* number of octets of packet saved in file */
    u32 orig_len; /* actual length of packet */
} GF_PcapPacketHeader;

typedef enum
{
    PCAP_PASS,
    PCAP_OK,
    PCAP_FAIL,
    PCAP_DONE
} ReadStatus;




#endif