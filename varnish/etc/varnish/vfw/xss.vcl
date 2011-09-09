sub vcl_recv {
	if (!req.http.X-VFW-Static) {
		if (req.url ~ "(?i)(<|&#x3C;|&#60)?(\s*|/)?(vb|java)?script(\s*)?(>|&#x3E;|&#62)") {
			set req.http.X-VFW-Threat = "XSS - Reflected";
			set req.http.X-VFW-RuleID = "xss.xss-1";
			call vfw_main;
		}

		if (req.url ~ "(?i)(<|&#x3C;|&#60)?(\s*)?(object|applet|embed|form|img)(\s*)?(>|&#x3E;|&#62)") {
			set req.http.X-VFW-Threat = "XSS - Reflected";
			set req.http.X-VFW-RuleID = "xss.xss-2";
			call vfw_main;
		}

		if (req.http.X-VFW-Body) {
			if (req.http.X-VFW-Body ~ "(?i)(<|&#x3C;|&#60)?(\s*|/)?(vb|java)?script(\s*)?(>|&#x3E;|&#62)") {
				set req.http.X-VFW-Threat = "XSS - Stored";
				set req.http.X-VFW-RuleID = "xss.xss-3";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(<|&#x3C;|&#60)?(\s*)?(object|applet|embed|form|img)(\s*)?(>|&#x3E;|&#62)") {
				set req.http.X-VFW-Threat = "XSS - Stored";
				set req.http.X-VFW-RuleID = "xss.xss-4";
				call vfw_main;
			}
		}
	}
}
