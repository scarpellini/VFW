C{
	#include <syslog.h>
}C

sub vcl_recv {
	set req.http.X-VFW-ClientIP = client.ip;
	set req.http.X-VFW-Method = req.request;
	set req.http.X-VFW-Proto = req.proto;
	set req.http.X-VFW-URL = req.http.host + req.url;
	set req.http.X-VFW-UA = req.http.user-agent;

	if (req.url ~ "(i)^/[^?]+\.(css|js|jp(e)?g|ico|png|gif|txt|gz(ip)?|zip|rar|iso|lzma|bz(2)?|t(ar\.)?gz|t(ar\.)?bz)(\?.*)?$") {
		set req.http.X-VFW-Static = "y";
	}
}

sub vcl_deliver {
	unset resp.http.Server;
	unset resp.http.X-Varnish;
	unset resp.http.Via;
}

sub vfw_main {
	if (req.http.X-VFW-Threat) {
		call vfw_block;
	}
}

sub vfw_block {
	call vfw_log;
	error 403 "VFW: " + req.http.X-VFW-Threat;
	# For production
	#error 404;
}

sub vfw_log {
	C{
		syslog(LOG_INFO, "<VFW> %f [%s/ruleid:%s]: %s - %s http://%s %s - %s", VRT_r_now(sp), VRT_GetHdr(sp, HDR_REQ, "\015X-VFW-Threat:"), VRT_GetHdr(sp, HDR_REQ, "\015X-VFW-RuleID:"), VRT_GetHdr(sp, HDR_REQ, "\017X-VFW-ClientIP:"), VRT_GetHdr(sp, HDR_REQ, "\015X-VFW-Method:"), VRT_GetHdr(sp, HDR_REQ, "\012X-VFW-URL:"), VRT_GetHdr(sp, HDR_REQ, "\014X-VFW-Proto:"), VRT_GetHdr(sp, HDR_REQ, "\011X-VFW-UA:"));
	}C
}

include "/opt/varnish-3/etc/varnish/vfw/config.vcl";

sub vcl_recv {
	unset req.http.X-VFW-ClientIP;
	unset req.http.X-VFW-Method;
	unset req.http.X-VFW-Proto;
	unset req.http.X-VFW-URL;
	unset req.http.X-VFW-UA;
	// vfw_post_cleanup doesn't work if v-vfw-body is unset
	//unset req.http.X-VFW-Body;

	if (req.request == "POST") {
		return(pass);
	}
}
