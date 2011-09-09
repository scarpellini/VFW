sub vcl_recv {
	# Bad User-Agent - Scanners
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_35_scanners.data)
	if (req.http.User-Agent ~ "(i)(metis|bilbo|n-stealth|black widow|brutus|cgichk|webtrends security|jaascois|pmafind|\.nasl|nsauditor|paros|nessus|nikto|webinspect|blackwidow)") {
		set req.http.X-VFW-Threat = "Bad User-Agent - Scanner";
		set req.http.X-VFW-RuleID = "generic.badua-1";
		call vfw_main;
	}

	# SSI Injection
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)<!--.*?#.*?(e(cho|xec)|printenv|include|cmd)") {
		set req.http.X-VFW-Threat = "SSI Injection";
		set req.http.X-VFW-RuleID = "generic.ssi-1";
		call vfw_main;
	}

	if (req.http.X-VFW-Body) {
		# SSI Injection
		# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
		if (req.http.X-VFW-Body ~ "(?i)<!--.*?#.*?(e(cho|xec)|printenv|include|cmd)") {
			set req.http.X-VFW-Threat = "SSI Injection";
			set req.http.X-VFW-RuleID = "generic.ssi-2";
			call vfw_main;
		}
	}
}
