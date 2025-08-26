/*
 * Service a request for a TLS handshake on behalf of an
 * in-kernel TLS consumer.
 *
 * Copyright (c) 2022 Oracle and/or its affiliates.
 *
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

int _gnutls_ktls_send_control_msg(gnutls_session_t session,
				  unsigned char record_type, const void *data,
				  size_t data_size)
{
	const char *buf = data;
	ssize_t ret;
	int sockin, sockout;
	size_t data_to_send = data_size;

	gnutls_transport_get_int2(session, &sockin, &sockout);

	tlshd_log_notice("_gnutls_ktls_send_control_msg: data_size: %d\n", data_size);

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

		tlshd_log_notice("_gnutls_ktls_send_control_msg: data_to_send: %d, length: %d\n", data_to_send, hdr->cmsg_len);

		for (int i = 0; i < (int) hdr->cmsg_len; i++) {
			tlshd_log_notice("hdr[%d]: %d\n", i, *(CMSG_DATA(hdr) + i));
		}

		for (int i = 0; i < (int) data_to_send; i++) {
			tlshd_log_notice("buf[%d]: %d\n", i, buf[i]);
		}

		ret = sendmsg(sockout, &msg, MSG_DONTWAIT);

		tlshd_log_notice("_gnutls_ktls_send_control_msg: sendmsg: %d\n", ret);

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

int _gnutls_ktls_send_handshake_msg(gnutls_session_t session,
				    gnutls_record_encryption_level_t,
				    gnutls_handshake_description_t,
				    const void *data, size_t data_size)
{
	return _gnutls_ktls_send_control_msg(session, GNUTLS_HANDSHAKE, data,
					     data_size);
}

static void tlshd_set_record_size(gnutls_session_t session, uint16_t val)
{
	int ret;

	ret = setsockopt(gnutls_transport_get_int(session), SOL_TLS,
			 TLS_TX_RECORD_SIZE_LIM, &val, sizeof(val));
	if (ret < 0)
		tlshd_log_perror("setsockopt (TLS_RX_RECORD_SIZE_LIM)");
}

static void tlshd_set_nagle(gnutls_session_t session, int val)
{
	int ret;

	ret = setsockopt(gnutls_transport_get_int(session),
			 IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (ret < 0)
		tlshd_log_perror("setsockopt (NODELAY)");
}

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
 * tlshd_start_tls_handshake - Drive the handshake interaction
 * @session: TLS session to initialize
 * @parms: handshake parameters
 *
 */
void tlshd_start_tls_handshake(gnutls_session_t session,
			       struct tlshd_handshake_parms *parms)
{
	uint16_t max_send_size;
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
		case -ETIMEDOUT:
			tlshd_log_gnutls_error(ret);
			parms->session_status = -ret;
			break;
		default:
			tlshd_log_notice("tlshd_start_tls_handshake unhandled error %d, returning EACCES\n", ret);
		}
		return;
	}

	desc = gnutls_session_get_desc(session);
	tlshd_log_debug("Session description: %s", desc);
	gnutls_free(desc);

	parms->session_status = tlshd_initialize_ktls(session);

	max_send_size = gnutls_record_get_max_send_size(session);
	tlshd_set_record_size(session, max_send_size);

	parms->key_serial = tlshd_keyring_put_session(session);
}

/**
 * tlshd_service_socket - Service a kernel socket needing a key operation
 *
 */
void tlshd_service_socket(void)
{
	gnutls_session_t session;
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

	tlshd_log_debug("parms.handshake_type: %d", parms.handshake_type);

	switch (parms.handshake_type) {
	case HANDSHAKE_MSG_TYPE_CLIENTHELLO:
		switch (parms.ip_proto) {
		case IPPROTO_TCP:
			tlshd_tls13_clienthello_handshake(&parms);
			tlshd_log_debug("Client Hello %d", parms.key_serial);
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
	case HANDSHAKE_MSG_TYPE_CLIENTKEYUPDATE:
		tlshd_log_debug("Calling key update!!!! %d", parms.key_serial);

		gnutls_init(&session, GNUTLS_CLIENT);

		gnutls_handshake_set_read_function(
			session, _gnutls_ktls_send_handshake_msg);

		gnutls_transport_set_int(session, parms.sockfd);
		gnutls_session_set_ptr(session, &parms);

		tlshd_log_debug("start ClientHello keyupdate");

		tlshd_keyring_get_session(parms.key_serial, session);
		tlshd_log_debug("%s - %d", __func__, __LINE__);

		ret = tlshd_restore_ktls(session);
		tlshd_log_debug("tlshd_restore_ktls: %d", ret);

		tlshd_log_debug("parms.key_update_type: %d", parms.key_update_type);

		gnutls_record_set_max_size(session, 16384);

		switch (parms.key_update_type) {
		case HANDSHAKE_KEY_UPDATE_TYPE_SEND:
			// We don't expect a KeyUpdate response
			tlshd_log_debug("don't expect a KeyUpdate response...\n");
			ret = gnutls_session_key_update(session, 0);
			break;
		case HANDSHAKE_KEY_UPDATE_TYPE_RECEIVED:
			tlshd_log_debug("HANDSHAKE_KEY_UPDATE_TYPE_RECEIVED");
			// We received a KeyUpdate and the peer doesn't
			// expect a response
			ret = gnutls_session_trigger_key_update(session);
			break;
		case HANDSHAKE_KEY_UPDATE_TYPE_RECEIVED_REQUEST_UPDATE:
			// We received a KeyUpdate and the peer does
			// expect a response
			ret = gnutls_session_key_update(session, 0);
			break;
		default:
			tlshd_log_debug("Unrecognized KeyUpdate type (%d)",
				parms.key_update_type);
		}

		tlshd_log_debug("gnutls key_update: %d", ret);

		parms.session_status = tlshd_initialize_ktls(session);
		tlshd_log_debug("tlshd_initialize_ktls: %d", parms.session_status);

		if (!parms.session_status) {
			key_serial_t peerid = g_array_index(parms.peerids, key_serial_t, 0);

			tlshd_log_debug("parms.session_status: %d, 0x%x, 0x%x",
				parms.session_status, parms.key_serial, peerid);

			g_array_append_val(parms.remote_peerids, peerid);
		}

		parms.key_serial = tlshd_keyring_put_session(session);

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
	case HANDSHAKE_MSG_TYPE_SERVERKEYUPDATE:
		tlshd_log_debug("HANDSHAKE_MSG_TYPE_SERVERKEYUPDATE");

		gnutls_init(&session, GNUTLS_SERVER);

		gnutls_handshake_set_read_function(
			session, _gnutls_ktls_send_handshake_msg);

		gnutls_transport_set_int(session, parms.sockfd);
		gnutls_session_set_ptr(session, &parms);

		tlshd_keyring_get_session(parms.key_serial, session);

		ret = tlshd_restore_ktls(session);
		tlshd_log_debug("tlshd_restore_ktls: %d", ret);

		gnutls_record_set_max_size(session, 16384);

		tlshd_log_debug("parms.key_update_type: %d", parms.key_update_type);

		switch (parms.key_update_type) {
		case HANDSHAKE_KEY_UPDATE_TYPE_SEND:
			// We don't expect a KeyUpdate response
			tlshd_log_debug("We don't expect a KeyUpdate response\n");
			ret = gnutls_session_key_update(session, 0);
			break;
		case HANDSHAKE_KEY_UPDATE_TYPE_RECEIVED:
			// We received a KeyUpdate and the peer doesn't
			// expect a response
			tlshd_log_debug("We received a KeyUpdate and the peer doesn't\n");
			ret = gnutls_session_trigger_key_update(session);
			break;
		case HANDSHAKE_KEY_UPDATE_TYPE_RECEIVED_REQUEST_UPDATE:
			// We received a KeyUpdate and the peer does
			// expect a response
			tlshd_log_debug("We received a KeyUpdate and the peer does\n");
			ret = gnutls_session_key_update(session, 0);
			break;
		default:
			tlshd_log_debug("Unrecognized KeyUpdate type (%d)",
				parms.key_update_type);
		}

		tlshd_log_debug("gnutls key_update: %d", ret);

		gnutls_datum_t username, psk_key;
		gnutls_psk_server_get_username2(session, &username);

		tlshd_server_psk_cb(session, (const char *)username.data, &psk_key);

		parms.session_status = tlshd_initialize_ktls(session);
		key_serial_t remote_peerid = g_array_index(parms.remote_peerids, key_serial_t, 0);

		tlshd_log_debug("parms.session_status: %d, %x, %x",
			parms.session_status, remote_peerid, psk_key);

		parms.key_serial = tlshd_keyring_put_session(session);

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
