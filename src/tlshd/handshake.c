/**
 * @file handshake.c
 * @brief Service a request for a TLS handshake on behalf of an
 *	  in-kernel TLS consumer
 *
 * @copyright
 * Copyright (c) 2022 Oracle and/or its affiliates.
 */

/*
 * ktls-utils is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/tcp.h>
#include <netdb.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <linux/tls.h>

#include <glib.h>
#include <linux/tls.h>

#include "tlshd.h"
#include "netlink.h"

#define GNUTLS_HANDSHAKE 22

/*
 * This is copied from the internal gnutls function to support ktls
 * https://gitlab.com/gnutls/gnutls/-/blob/master/lib/system/ktls.c#L942
 */
int _gnutls_ktls_send_control_msg(gnutls_session_t session,
				  unsigned char record_type, const void *data,
				  size_t data_size)
{
	const char *buf = data;
	ssize_t ret;
	int sockin, sockout;
	size_t data_to_send = data_size;

	gnutls_transport_get_int2(session, &sockin, &sockout);

	while (data_to_send > 0) {
		char cmsg[CMSG_SPACE(sizeof(unsigned char))];
		struct msghdr msg = { 0 };
		struct iovec msg_iov; /* Vector of data to send/receive into. */
		struct cmsghdr *hdr;

		msg.msg_control = cmsg;
		msg.msg_controllen = sizeof cmsg;

		hdr = CMSG_FIRSTHDR(&msg);
#if defined(__FreeBSD__)
		hdr->cmsg_level = IPPROTO_TCP;
#else
		hdr->cmsg_level = SOL_TLS;
#endif
		hdr->cmsg_type = TLS_SET_RECORD_TYPE;
		hdr->cmsg_len = CMSG_LEN(sizeof(unsigned char));

		// construct record header
		*CMSG_DATA(hdr) = record_type;
		msg.msg_controllen = hdr->cmsg_len;

		msg_iov.iov_base = (void *)buf;
		msg_iov.iov_len = data_to_send;

		msg.msg_iov = &msg_iov;
		msg.msg_iovlen = 1;

		ret = sendmsg(sockout, &msg, MSG_DONTWAIT);

		if (ret == -1) {
			switch (errno) {
			case EINTR:
				if (data_to_send < data_size) {
					return data_size - data_to_send;
				} else {
					return GNUTLS_E_INTERRUPTED;
				}
			case EAGAIN:
				if (data_to_send < data_size) {
					return data_size - data_to_send;
				} else {
					return GNUTLS_E_AGAIN;
				}
			default:
				return GNUTLS_E_PUSH_ERROR;
			}
		}

		buf += ret;
		data_to_send -= ret;
	}

	return data_size;
}

/*
 * This is copied from the internal gnutls function to support ktls
 * https://gitlab.com/gnutls/gnutls/-/blob/master/lib/system/ktls.c#L942
 */
int gnutls_ktls_send_handshake_msg(gnutls_session_t session,
				    gnutls_record_encryption_level_t,
				    gnutls_handshake_description_t,
				    const void *data, size_t data_size)
{
	return _gnutls_ktls_send_control_msg(session, GNUTLS_HANDSHAKE, data,
					     data_size);
}

/**
 * @brief Toggle the use of the Nagle algorithm
 * @param[in]     session  TLS session to modify
 * @param[in]     val      new setting
 */
static void tlshd_set_nagle(gnutls_session_t session, int val)
{
	int ret;

	ret = setsockopt(gnutls_transport_get_int(session),
			 IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (ret < 0)
		tlshd_log_perror("setsockopt (NODELAY)");
}

/**
 * @brief Retrieve the current Nagle algorithm setting
 * @param[in]     session  TLS session to modify
 * @param[out]    saved    where to save the current setting
 */
static void tlshd_save_nagle(gnutls_session_t session, int *saved)
{
	socklen_t len;
	int ret;


	len = sizeof(*saved);
	ret = getsockopt(gnutls_transport_get_int(session),
			 IPPROTO_TCP, TCP_NODELAY, saved, &len);
	if (ret < 0) {
		tlshd_log_perror("getsockopt (NODELAY)");
		*saved = 0;
		return;
	}

	tlshd_set_nagle(session, 1);
}

/**
 * @brief Kick off a handshake interaction
 * @param[in]     session  TLS session to initialize
 * @param[in]     parms    Handshake parameters
 */
void tlshd_start_tls_handshake(gnutls_session_t session,
			       struct tlshd_handshake_parms *parms)
{
	int saved, ret;
	char *desc;

	gnutls_handshake_set_timeout(session, parms->timeout_ms);
	tlshd_save_nagle(session, &saved);
	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));
	tlshd_set_nagle(session, saved);
	if (ret < 0) {
		/* Any errors here should default to blocking access: */
		parms->session_status = EACCES;
		switch (ret) {
		case GNUTLS_E_CERTIFICATE_ERROR:
		case GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR:
			tlshd_log_cert_verification_error(session);
			break;
		case GNUTLS_E_PREMATURE_TERMINATION:
			tlshd_log_error("Handshake timeout, retrying");
			parms->session_status = ETIMEDOUT;
			break;
		default:
			tlshd_log_gnutls_error(ret);
		}
		return;
	}

	desc = gnutls_session_get_desc(session);
	tlshd_log_debug("Session description: %s", desc);
	gnutls_free(desc);

	parms->session_status = tlshd_initialize_ktls(session, READ_WRITE);
}

/**
 * @brief Service a kernel socket needing a handshake operation
 */
void tlshd_service_socket(void)
{
	struct tlshd_handshake_parms parms;
	int ret;

	if (tlshd_genl_get_handshake_parms(&parms) != 0)
		goto out;

	ret = gnutls_global_init();
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto out;
	}

	if (tlshd_tls_debug)
		gnutls_global_set_log_level(tlshd_tls_debug);
	gnutls_global_set_log_function(tlshd_gnutls_log_func);
	gnutls_global_set_audit_log_function(tlshd_gnutls_audit_func);

#ifdef HAVE_GNUTLS_GET_SYSTEM_CONFIG_FILE
	tlshd_log_debug("System config file: %s",
			gnutls_get_system_config_file());
#endif

	switch (parms.handshake_type) {
	case HANDSHAKE_MSG_TYPE_CLIENTHELLO:
		switch (parms.ip_proto) {
		case IPPROTO_TCP:
			tlshd_tls13_clienthello_handshake(&parms);
			break;
#ifdef HAVE_GNUTLS_QUIC
		case IPPROTO_QUIC:
			tlshd_quic_clienthello_handshake(&parms);
			break;
#endif
		default:
			tlshd_log_debug("Unsupported ip_proto (%d)", parms.ip_proto);
			parms.session_status = EOPNOTSUPP;
		}
		break;
	case HANDSHAKE_MSG_TYPE_SERVERHELLO:
		switch (parms.ip_proto) {
		case IPPROTO_TCP:
			tlshd_tls13_serverhello_handshake(&parms);
			break;
#ifdef HAVE_GNUTLS_QUIC
		case IPPROTO_QUIC:
			tlshd_quic_serverhello_handshake(&parms);
			break;
#endif
		default:
			tlshd_log_debug("Unsupported ip_proto (%d)", parms.ip_proto);
			parms.session_status = EOPNOTSUPP;
		}
		break;
	default:
		tlshd_log_debug("Unrecognized handshake type (%d)",
				parms.handshake_type);
	}

	gnutls_global_deinit();

out:
	tlshd_genl_done(&parms);
	tlshd_log_completion(&parms);
	tlshd_genl_put_handshake_parms(&parms);
}
