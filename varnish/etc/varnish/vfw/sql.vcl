sub vcl_recv {
	if (!req.http.X-VFW-Static) {
		if (req.url ~ "(?i)((SELECT|DELETE)(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+FROM|INSERT(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+INTO|UPDATE(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+SET)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-1";
			call vfw_main;
		}

		if (req.url ~ "(?i)UNION(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+(SELECT|INSERT|UPDATE|DELETE|SHOW|DROP)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-2";
			call vfw_main;
		}

		if (req.url ~ "(?i)(SHOW|DROP|CREATE)(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+(DATABASES?|TABLES?|PROCESSLIST)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-3";
			call vfw_main;
		}

		if (req.url ~ "(?i)(\s|%20|\t|%09|\+)+(OR|AND)(\s|%20|\t|%09|\+)+\d+(\s|%20|\t|%09|\+)*(=|%3D)(\s|%20|\t|%09|\+)*\d+") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-4";
			call vfw_main;
		}

		if (req.http.X-VFW-Body) {
			if (req.http.X-VFW-Body ~ "(?i)((SELECT|DELETE)(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+FROM|INSERT(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+INTO|UPDATE(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+SET)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-5";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)UNION(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+(SELECT|INSERT|UPDATE|DELETE|SHOW|DROP)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-6";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(SHOW|DROP|CREATE)(\s|%20|\t|%09|\+)+[^&]+(\s|%20|\t|%09|\+)+(DATABASES?|TABLES?|PROCESSLIST)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-7";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(\s|%20|\t|%09|\+)+(OR|AND)(\s|%20|\t|%09|\+)+\d+(\s|%20|\t|%09|\+)*(=|%3D)(\s|%20|\t|%09|\+)*\d+") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-8";
				call vfw_main;
			}

		}
	}
}
