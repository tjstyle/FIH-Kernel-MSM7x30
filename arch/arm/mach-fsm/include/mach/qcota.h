/* Copyright (c) 2010, Code Aurora Forum. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of Code Aurora Forum, Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __QCOTA__H
#define __QCOTA__H

#include <linux/types.h>
#include <linux/ioctl.h>


#define QCE_OTA_MAX_BEARER   31
#define OTA_KEY_SIZE 16   /* 128 bits of keys. */

enum qce_ota_dir_enum {
	QCE_OTA_DIR_UPLINK   = 0,
	QCE_OTA_DIR_DOWNLINK = 1,
	QCE_OTA_DIR_LAST
};

enum qce_ota_algo_enum {
	QCE_OTA_ALGO_KASUMI = 0,
	QCE_OTA_ALGO_SNOW3G = 1,
	QCE_OTA_ALGO_LAST
};

/**
 * struct qce_f8_req - qce f8 request
 * @data_in:	packets input data stream to be ciphered.
 *		If NULL, streaming mode operation.
 * @data_out:	ciphered packets output data.
 * @data_len:	length of data_in and data_out in bytes.
 * @count_c:	count-C, ciphering sequence number, 32 bit
 * @bearer:	5 bit of radio bearer identifier.
 * @ckey:	128 bits of confidentiality key,
 *		ckey[0] bit 127-120, ckey[1] bit 119-112,.., ckey[15] bit 7-0.
 * @direction:	uplink or donwlink.
 * @algorithm:	Kasumi, or Snow3G.
 *
 * If data_in is NULL, the engine will run in a special mode called
 * key stream mode. In this special mode, the engine will generate
 * key stream output for the number of bytes specified in the
 * data_len, based on the input parameters of direction, algorithm,
 * ckey, bearer, and count_c. The data_len is restricted to
 * the length of multiple of 16 bytes.  Application can then take the
 * output stream, do a exclusive or to the input data stream, and
 * generate the final cipher data stream.
 */
struct qce_f8_req {
	uint8_t  *data_in;
	uint8_t  *data_out;
	uint16_t  data_len;
	uint32_t  count_c;
	uint8_t   bearer;
	uint8_t   ckey[OTA_KEY_SIZE];
	enum qce_ota_dir_enum  direction;
	enum qce_ota_algo_enum algorithm;
};

/**
 * struct qce_f8_multi_pkt_req - qce f8 multiple packet request
 *			Muliptle packets with uniform size, and
 *			F8 ciphering parameters can be ciphered in a
 *			single request.
 *
 * @num_pkt:		number of packets.
 *
 * @cipher_start:	ciphering starts offset within a packet.
 *
 * @cipher_size:	number of bytes to be ciphered within a packet.
 *
 * @qce_f8_req:		description of the packet and F8 parameters.
 *			The following fields have special meaning for
 *			multiple packet operation,
 *
 *	@data_len:	data_len indicates the length of a packet.
 *
 *	@data_in:	packets are concatenated together in a byte
 *			stream started at data_in.
 *
 *	@data_out:	The returned ciphered output for multiple
 *			packets.
 *			Each packet ciphered output are concatenated
 *			together into a byte stream started at data_out.
 *			Note, each ciphered packet output area from
 *			offset 0 to cipher_start-1, and from offset
 *			cipher_size to data_len -1 are remained
 *			unaltered from packet input area.
 *	@count_c:	count-C of the first packet, 32 bit.
 *
 *
 *   In one request, multiple packets can be ciphered, and output to the
 *   data_out stream.
 *
 *   Packet data are layed out contiguously in sequence in data_in,
 *   and data_out area. Every packet is identical size.
 *   If the PDU is not byte aligned, set the data_len value of
 *   to the rounded up value of the packet size. Eg, PDU size of
 *   253 bits, set the packet size to 32 bytes. Next packet starts on
 *   the next byte boundary.
 *
 *   For each packet, data from offset 0 to cipher_start
 *   will be left unchanged and output to the data_out area.
 *   This area of the packet can be for the RLC header, which is not
 *   to be ciphered.
 *
 *   The ciphering of a packet starts from offset cipher_start, for
 *   cipher_size bytes of data. Data starting from
 *   offset cipher_start + cipher_size to the end of packet will be left
 *   unchanged and output to the dataOut area.
 *
 *   For each packet the input arguments of bearer, direction,
 *   ckey, algoritm have to be the same. count_c is the ciphering sequence
 *   number of the first packet. The 2nd packet's ciphering sequence
 *   number is assumed to be count_c + 1. The 3rd packet's ciphering sequence
 *   number is count_c + 2.....
 *
 */
struct qce_f8_multi_pkt_req {
	uint16_t    num_pkt;
	uint16_t    cipher_start;
	uint16_t    cipher_size;
	struct qce_f8_req qce_f8_req;
};

/**
 * struct qce_f9_req - qce f9 request
 * @message:	message
 * @msize:	message size in bytes (include the last partial byte).
 * @last_bits:	valid bits in the last byte of message.
 * @mac_i:	32 bit message authentication code, to be returned.
 * @fresh:	random 32 bit number, one per user.
 * @count_i:	32 bit count-I integrity sequence number.
 * @direction:	uplink or donwlink.
 * @ikey:	128 bits of integrity key,
 *		ikey[0] bit 127-120, ikey[1] bit 119-112,.., ikey[15] bit 7-0.
 * @algorithm:  Kasumi, or Snow3G.
 */
struct qce_f9_req {
	uint8_t   *message;
	uint16_t   msize;
	uint8_t    last_bits;
	uint32_t   mac_i;
	uint32_t   fresh;
	uint32_t   count_i;
	enum qce_ota_dir_enum direction;
	uint8_t    ikey[OTA_KEY_SIZE];
	enum qce_ota_algo_enum algorithm;
};

#define QCOTA_IOC_MAGIC     0x85

#define QCOTA_F8_REQ _IOWR(QCOTA_IOC_MAGIC, 1, struct qce_f8_req)
#define QCOTA_F8_MPKT_REQ _IOWR(QCOTA_IOC_MAGIC, 2, struct qce_f8_multi_pkt_req)
#define QCOTA_F9_REQ _IOWR(QCOTA_IOC_MAGIC, 3, struct qce_f9_req)


#endif /* __QCOTA__H */
