sub vcl_recv {
	# Allowed methods
	if (req.request != "GET" && req.request != "HEAD" && req.request != "PUT" &&
	    req.request != "POST" && req.request != "DELETE") {
		set req.http.X-VFW-Threat = "Method Not Allowed";
		set req.http.X-VFW-RuleID = "protocol.method-1";
		call vfw_main;
	}

	# Empty Host Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_21_protocol_anomalies.conf)
	if (!req.http.host) {
		set req.http.X-VFW-Threat = "Empty Host Header";
		set req.http.X-VFW-RuleID = "protocol.host-1";
		call vfw_main;
	}

	# Empty Accept Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_21_protocol_anomalies.conf)
	if (!req.http.Accept) {
		set req.http.X-VFW-Threat = "Empty Accept Header";
		set req.http.X-VFW-RuleID = "protocol.accpt-1";
		call vfw_main;
	}

	# Empty User-Agent Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_21_protocol_anomalies.conf)
	if (!req.http.user-agent) {
		set req.http.X-VFW-Threat = "Empty User-Agent Header";
		set req.http.X-VFW-RuleID = "protocol.ua-1";
		call vfw_main;
	}

	# Invalid Connection Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.bad-behavior.ioerror.us/documentation/how-it-works/ 
	if (req.http.Connection && req.http.Connection !~ "^(keep-alive|close)$") {
		set req.http.X-VFW-Threat = "Invalid Connection Header";
		set req.http.X-VFW-RuleID = "protocol.conn-1";
		call vfw_main;
	}

	# POST without Content-Length Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.5
	if (req.request == "POST" && (!req.http.Content-Length || req.http.Content-Length ~ "^0+$")) {
		set req.http.X-VFW-Threat = "Empty Content-Length Header";
		set req.http.X-VFW-RuleID = "protocol.clen-1";
		call vfw_main;
	}

	# Non numeric Content-Length Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.13 
	if (req.request == "POST" && req.http.Content-Length !~ "^[0-9]+$") {
		set req.http.X-VFW-Threat = "Non numeric Content-Length Header";
		set req.http.X-VFW-RuleID = "protocol.clen-2";
		call vfw_main;
	}

	# POST without Content-Type Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	if (req.request == "POST" && !req.http.Content-Type) {
		set req.http.X-VFW-Threat = "Empty Content-Type Header";
		set req.http.X-VFW-RuleID = "protocol.ctype-1";
		call vfw_main;
	}

	# Expected Header on HTTP < 1.1
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.bad-behavior.ioerror.us/documentation/how-it-works/
	if (req.http.Expect && req.proto != "HTTP/1.1") {
		set req.http.X-VFW-Threat = "Expect Header is Allowed Only on HTTP/1.1";
		set req.http.X-VFW-RuleID = "protocol.expctd-1";
		call vfw_main;
	}

	# Pragma without Cache-Control Header on HTTP/1.1
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.bad-behavior.ioerror.us/documentation/how-it-works/
	if (req.http.Pragma && req.proto == "HTTP/1.1" && !req.http.Cache-Control) {
		set req.http.X-VFW-Threat = "Pragma requires Cache-Control on HTTP/1.1";
		set req.http.X-VFW-RuleID = "protocol.cache-1";
		call vfw_main;
	}

	# Normalize
	if (req.http.Accept-Encoding ~ "gzip") {
		set req.http.Accept-Encoding = "gzip";
	}
	elsif (req.http.Accept-Encoding ~ "deflate") {
		set req.http.Accept-Encoding = "deflate";
	}

	if (req.http.X-VFW-Static) { 
		unset req.http.cookie;
		set req.url = regsub(req.url, "\?.*$", "");
	}
}
