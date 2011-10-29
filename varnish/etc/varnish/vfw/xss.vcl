sub vcl_recv {
	if (!req.http.X-VFW-Static) {
		if (req.url ~ "(?i)(<|%3C|)(\s|%20|\t|%09|\+)*/?(vb|java)?script(\s|%20|\t|%09|\+)*(>|%3E)") {
			set req.http.X-VFW-Threat = "XSS - Reflected";
			set req.http.X-VFW-RuleID = "xss.xss-1";
			call vfw_main;
		}

		//if (req.url ~ "(?i)(<|%3C|&#\d+)(\s|%20|\t|%09|\+)*/?(vb|java)?script:") {
		//	set req.http.X-VFW-Threat = "XSS - Reflected";
		//	set req.http.X-VFW-RuleID = "xss.xss-2";
		//	call vfw_main;
		//}

		if (req.url ~ "(?i)(<|%3C|)(\s|%20|\t|%09|\+)*/?(object|applet|embed|form|img)") {
			set req.http.X-VFW-Threat = "XSS - Reflected";
			set req.http.X-VFW-RuleID = "xss.xss-3";
			call vfw_main;
		}

		if (req.http.X-VFW-Body) {
			if (req.http.X-VFW-Body ~ "(?i)(<|%3C|)(\s|%20|\t|%09|\+)*/?(vb|java)?script(\s|%20|\t|%09|\+)*(>|%3E)") {
				set req.http.X-VFW-Threat = "XSS - Stored";
				set req.http.X-VFW-RuleID = "xss.xss-4";
				call vfw_main;
			}

			//if (req.http.X-VFW-Body ~ "(?i)(<|%3C|&#\d+)(\s|%20|\t|%09|\+)*/?(vb|java)?script:") {
			//	set req.http.X-VFW-Threat = "XSS - Stored";
			//	set req.http.X-VFW-RuleID = "xss.xss-5";
			//	call vfw_main;
			//}

			if (req.http.X-VFW-Body ~ "(?i)(<|%3C|)(\s|%20|\t|%09|\+)*/?(object|applet|embed|form|img)") {
				set req.http.X-VFW-Threat = "XSS - Stored";
				set req.http.X-VFW-RuleID = "xss.xss-6";
				call vfw_main;
			}
		}
	}
}
