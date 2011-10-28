sub vcl_recv {
	# Directory traversal
	if (req.url ~ "(?i)((/|\\)\.{2}|\.{2}(/|\\))") {
		set req.http.X-VFW-Threat = "Directory Traversal";
		set req.http.X-VFW-RuleID = "path.travers-1";
		call vfw_main;
	}

	# Web server internal files
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)\.(htaccess|htpasswd)") {
		set req.http.X-VFW-Threat = "Web Server Internal File";
		set req.http.X-VFW-RuleID = "path.httpd-1";
		call vfw_main;
	}

	# CSM's internal files
	if (req.url ~ "(?i)\.(cvs|svn|git|hg)") {
		set req.http.X-VFW-Threat = "CSM Internal File";
		set req.http.X-VFW-RuleID = "path.csm-2";
		call vfw_main;
	}

	# Database files
	if (req.url ~ "(?i)\.(sql|sqlite|mdb)") {
		set req.http.X-VFW-Threat = "Database File";
		set req.http.X-VFW-RuleID = "path.sql-1";
		call vfw_main;
	}

	# Unix directories
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	#if (req.url ~ "(?i)/(etc|usr|var|tmp|local|bin|sbin|dev|boot|lib(64)?|mnt|root|boot|proc)") {
	#	set req.http.X-VFW-Threat = "Unix Directory";
	#	set req.http.X-VFW-RuleID = "path.unix-1";
	#	call vfw_main;
	#}

	# Unix files
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)(\.((bash_)?history|(vim|bash)rc|ssh)|authorized_keys)") {
		set req.http.X-VFW-Threat = "Unix File";
		set req.http.X-VFW-RuleID = "path.unix-2";
		call vfw_main;
	}

	# Windows partitions
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)[a-z]\:\\") {
		set req.http.X-VFW-Threat = "Windows Partition";
		set req.http.X-VFW-RuleID = "path.win-1";
		call vfw_main;
	}

	# Windows files
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)((cmd(32)?|nc|net|telnet|wsh|ftp|nmap)\.exe|\.(db|com|bat|reg|asa))") {
		set req.http.X-VFW-Threat = "Windows File";
		set req.http.X-VFW-RuleID = "path.win-2";
		call vfw_main;
	}

	# Bad file extensions
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)\.(inc|ini|scr)") {
		set req.http.X-VFW-Threat = "Bad File Extension";
		set req.http.X-VFW-RuleID = "path.generic-1";
		call vfw_main;
	}
}
