C{
	#include <stdio.h>
	#include <stdlib.h>
	#include <fcntl.h>
	#include <unistd.h>
	#include <string.h>
	#include <strings.h>
	#include <sys/mman.h>
	#include <sys/types.h>
	#include <bin/varnishd/cache.h>
}C

sub vcl_recv {
	if (req.request == "POST") {
		call vfw_load_post;
	}
}

sub vcl_deliver {
	if (req.request == "POST") {
		call vfw_cleanup_post;
	}
}

sub vfw_load_post {
	C{
		/*
		** Please read:
                ** -- bin/varnishd/cache_fetch.c: FetchReqBody()
                ** -- bin/varnishd/cache_httpconn.c: HTC_Read()
		**
		** -- http://sourceforge.net/projects/libdynamic/ (Cal Heldenbrand)
		*/

		char buf[3], body[8192];
		unsigned long content_length;
		char *h_clen_ptr, *h_ctype_ptr, shmem_fname[64];
		int buf_size, rsize, wsize, shmem_htc_fd;

		body[0] = 0;

		syslog(LOG_INFO, "vfw_load_post - initiating...");

		h_ctype_ptr = VRT_GetHdr(sp, HDR_REQ, "\015Content-Type:");

		if (strcmp(h_ctype_ptr, "application/x-www-form-urlencoded")) {
			syslog(LOG_INFO, "vfw_load_post - Not Supported Content-Type: %s", h_ctype_ptr);
			return(0);
		}

		h_clen_ptr = VRT_GetHdr(sp, HDR_REQ, "\017Content-Length:");

		if (!h_clen_ptr) {
			syslog(LOG_INFO, "vfw_load_post - Empty Content-Length Header");
			return(0);
		}

		content_length = strtoul(h_clen_ptr, NULL, 10);

		if (content_length <= 0) {
			syslog(LOG_INFO, "vfw_load_post - Empty Content-Length Header");
			return(0);
		}

		// Open/Create shared memory file
		snprintf(shmem_fname, sizeof(shmem_fname), "varnish.httpbody.%d.%d", sp->id, sp->xid);
		shmem_htc_fd = shm_open(shmem_fname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
		syslog(LOG_INFO, "vfw_load_post - shm_open()/%s: %s", shmem_fname, strerror(errno));

		if (shmem_htc_fd == -1) {
			return(0);
		}

		while (content_length) {
			if (content_length > sizeof(buf)) {
				buf_size = sizeof(buf) - 1;
			}
			else {
				buf_size = content_length;
			}

			// read body data into 'buf'
			rsize = HTC_Read(sp->htc, buf, buf_size);

			if (rsize <= 0) {
				syslog(LOG_INFO, "vfw_load_post - HTC_Read(): %d - %s", rsize, strerror(errno));
				return(0);
			}

			content_length -= rsize;

			// write body data to the shared memory file
			wsize = write(shmem_htc_fd, buf, buf_size);

			if (wsize <= 0) {
				syslog(LOG_INFO, "vfw_load_post - write(): %d - %s", wsize, strerror(errno));
				return(0);
			}

			// copy body data to header buffer
			strncat(body, buf, buf_size);
		}

		lseek(shmem_htc_fd, 0, SEEK_SET);
		syslog(LOG_INFO, "vfw_load_post - lseek(): %s", strerror(errno));
		sp->htc->fd = shmem_htc_fd;

		syslog(LOG_INFO, "vfw_load_post - DATA: Content-Length: %s, Content: %s", h_clen_ptr, body);

		VRT_SetHdr(sp, HDR_REQ, "\013X-VFW-Body:", body, vrt_magic_string_end);
	}C
}

sub vfw_cleanup_post {
	C{
		if (VRT_GetHdr(sp, HDR_REQ, "\013X-VFW-Body:")) {
			syslog(LOG_INFO, "vfw_load_post - cleaning up...");
			close(sp->htc->fd);
			syslog(LOG_INFO, "vfw_cleanup_post - close(): %s", strerror(errno));
		}
	}C
}
