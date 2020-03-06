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

#include "in_pcap.h"

GF_PcapFileHeader *read_pcap_header(const GF_PcapInputCtx *input)
{
	GF_PcapFileHeader *pcapHeader;
	pcapHeader = gf_malloc(sizeof(GF_PcapFileHeader));

	if (pcapHeader == NULL)
	{
		return NULL;
	}

	// read pcap header
	memset(pcapHeader, 0, sizeof(GF_PcapFileHeader));
	size_t read = fread(pcapHeader, 1, sizeof(GF_PcapFileHeader), input->fd);
	if (pcapHeader->magic_number == 0xA1B2C3D4 || read != sizeof(GF_PcapFileHeader))
	{
		printf("PCAP header OK\n");
	}
	else
	{
		fprintf(stderr, "This isn't a PCAP file\n");
		return NULL;
	}
	return pcapHeader;
}

static GF_Err pcapin_initialize(GF_Filter *filter)
{

	GF_LOG(GF_LOG_INFO, GF_LOG_MMIO, ("[PcapIn] Initializing PCAP source\n"));

	GF_PcapInputCtx *ctx = (GF_PcapInputCtx *)gf_filter_get_udta(filter);
	GF_Err e;
	if (!ctx || !ctx->src)
	{
		GF_LOG(GF_LOG_ERROR, GF_LOG_MMIO, ("[PcapIn] Missing src for PCAP input\n"));
		e = GF_URL_ERROR;
		gf_filter_setup_failure(filter, e);
		return e;
	}
	else
	{
		GF_LOG(GF_LOG_INFO, GF_LOG_MMIO, ("[PcapIn] Opening PCAP %s\n", ctx->src));
	}

	// open PCAP file
	if (!ctx->fd)
		ctx->fd = gf_fopen(ctx->src, "rb");

	// Oopsie
	if (!ctx->fd)
	{
		GF_LOG(GF_LOG_ERROR, GF_LOG_MMIO, ("[PcapIn] Failure to PCAP %s, check your permissions or its presence\n", ctx->src));

		e = GF_IO_ERR;
		gf_filter_setup_failure(filter, e);
		return e;
	}
	else
	{
		GF_LOG(GF_LOG_INFO, GF_LOG_MMIO, ("[PcapIn] PCAP %s opened\n", ctx->src));
	}

	// Check that the file is really a PCAP
	GF_PcapFileHeader *pcapHeader = read_pcap_header(ctx);
	if (pcapHeader == NULL)
	{
		GF_LOG(GF_LOG_ERROR, GF_LOG_MMIO, ("[PcapIn] The file %s is not a PCAP, file\n", ctx->src));
		gf_fclose(ctx->fd);
		gf_free(pcapHeader);
		e = GF_BAD_PARAM;
		gf_filter_setup_failure(filter, e);
		return e;
	}

	ctx->isEthernet = (pcapHeader->network == 1);

	if (ctx->isEthernet != 1)
	{
		GF_LOG(GF_LOG_ERROR, GF_LOG_MMIO, ("[PcapIn] only Ethernet mode is supported\n"));
		e = GF_IO_ERR;
		gf_filter_setup_failure(filter, e);
		return e;
	}

	// Configure output
	ctx->pid = gf_filter_pid_new(filter);
	memset(ctx->buffer, 0, GF_PCAP_MAX_PKT_SIZE);
	return gf_filter_pid_raw_new(filter, ctx->src, ctx->src, NULL, NULL, NULL, 0, GF_TRUE, &ctx->pid);;
}

static GF_FilterProbeScore pcapin_probe_url(GF_Filter *filter)
{

	return GF_FPROBE_SUPPORTED;
}

static Bool pcapin_process_event(GF_Filter *filter, const GF_FilterEvent *evt)
{
	return GF_OK;
}

static void pcapin_pck_destructor(GF_Filter *filter, GF_FilterPid *pid, GF_FilterPacket *pck)
{
	/*GF_FileInCtx *ctx = (GF_FileInCtx *) gf_filter_get_udta(filter);
	ctx->pck_out = GF_FALSE;*/
	//ready to process again
	gf_filter_post_process_task(filter);
}

ReadStatus read_packet(const GF_PcapInputCtx *input, uint8_t *dest, size_t *packet_size, uint64_t *time)
{
	GF_PcapPacketHeader header;
	memset(&header, 0, sizeof(header));
	size_t read = fread(&header, 1, sizeof(header), input->fd);

	if (read == 0)
		return PCAP_DONE;
	if (read != sizeof(header))
		return PCAP_FAIL;

	if (GF_PCAP_MAX_PKT_SIZE < header.incl_len)
	{
		GF_LOG(GF_LOG_ERROR, GF_LOG_MMIO, ("[PcapIn] The PCAP packet size "
										   "must be inferior or equal to %d\n",
										   GF_PCAP_MAX_PKT_SIZE));
		return PCAP_FAIL;
	}
	read = fread(dest, 1, header.incl_len, input->fd);
	if (read != header.incl_len)
	{
		GF_LOG(GF_LOG_ERROR, GF_LOG_MMIO, ("[PcapIn] The packet must be complete",
										   GF_PCAP_MAX_PKT_SIZE));
		return PCAP_FAIL;
	}

	*time = (header.ts_sec * 1000000LL + header.ts_usec) / 1000LL;
	*packet_size = header.incl_len;
	if (input->isEthernet)
	{
		// remove ethernet header
		size_t ethHdrSize = 6 + 6 + 2;
		uint32_t etherType = dest[13] + dest[12] * 256;

		// discard non-IPV4 packets
		if (etherType != 0x0800)
			return PCAP_PASS;

		// remove ethernet header + IP + UDP
		uint8_t ipheader_len = (dest[14] & 0xF) * 4;

		uint8_t ip_protocol = dest[23];

		uint8_t protocol_header_size = 0;
		switch (ip_protocol)
		{
		case 17: //UDP
			protocol_header_size = 8;
			break;
		default:
			GF_LOG(GF_LOG_ERROR, GF_LOG_MMIO, ("[PcapIn] Only UDP is supported",
										   GF_PCAP_MAX_PKT_SIZE));
			return PCAP_FAIL;
			break;
		}
		uint32_t offset = ethHdrSize + ipheader_len + protocol_header_size;
		*packet_size = (header.incl_len - offset);
		memmove(dest, dest + offset, *packet_size);
	}
	return PCAP_OK;
}

static GF_Err pcapin_process(GF_Filter *filter)
{
	GF_LOG(GF_LOG_INFO, GF_LOG_MMIO, ("[PcapIn] Process"));
	GF_FilterPacket *pck_dst;
	GF_PcapInputCtx *ctx = (GF_PcapInputCtx *)gf_filter_get_udta(filter);
	size_t packet_size = 0;
	uint64_t time_in_ms = 0;
	char *data_dst;
	
	ReadStatus stat = read_packet(ctx, ctx->buffer, &packet_size, &time_in_ms);
	switch (stat)
	{
	case PCAP_OK:
		GF_LOG(GF_LOG_DEBUG, GF_LOG_MMIO, ("[PcapIn] Read packet of size %zu\n", packet_size));
		pck_dst = gf_filter_pck_new_alloc(ctx->pid, packet_size, &data_dst);
		if (!pck_dst) return GF_OUT_OF_MEM;
		
		memcpy(data_dst, ctx->buffer, packet_size);
		gf_filter_pck_send(pck_dst);
		break;
	case PCAP_FAIL:
		GF_LOG(GF_LOG_ERROR, GF_LOG_MMIO, ("[PcapIn] Failed to read PCAP packet"));
		return GF_IO_ERR;
		break;
	case PCAP_PASS:
		GF_LOG(GF_LOG_DEBUG, GF_LOG_MMIO, ("[PcapIn] Nothing to read"));
		return GF_OK;
		break;
	case PCAP_DONE:
		GF_LOG(GF_LOG_INFO, GF_LOG_MMIO, ("[PcapIn] End of PCAP"));
		return GF_EOS;
	default:
		return GF_NOT_SUPPORTED;
		break;
	}

	return GF_OK;
}

static void pcapin_finalize(GF_Filter *filter)
{
	GF_PcapInputCtx *ctx = (GF_PcapInputCtx *)gf_filter_get_udta(filter);
}

#define OFFS(_n) #_n, offsetof(GF_PcapInputCtx, _n)

static const GF_FilterArgs PcapInArgs[] =
	{ 
		{OFFS(src), "location of source content", GF_PROP_NAME, NULL, NULL, 0},
		{0}};

static const GF_FilterCapability PcapInCaps[] =
	{
		CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_FILE),
};

GF_FilterRegister PcapInRegister = {
	.name = "pcapin",
	GF_FS_SET_DESCRIPTION("PCAP input")
		GF_FS_SET_HELP("This filter dispatch packets from pcap (without UDP/IP headers) file into a filter chain.\n"
					   "Warning: Only PCAP v1 are supported, no PCAPNG\n"
					   "Warning: Only UDP in PCAP is supported\n")
			GF_FS_SET_AUTHOR("Rodolphe Fouquet")
				.private_size = sizeof(GF_PcapInputCtx),
	.args = PcapInArgs,
	.initialize = pcapin_initialize,
	SETCAPS(PcapInCaps),
	.finalize = pcapin_finalize,
	.process = pcapin_process,
	.process_event = pcapin_process_event,
	.probe_url = pcapin_probe_url};

const GF_FilterRegister *pcapin_register(GF_FilterSession *session)
{
	return &PcapInRegister;
}