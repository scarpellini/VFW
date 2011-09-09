sub vcl_recv {
	if (!req.http.X-VFW-Static) {
		if (req.url ~ "(?i)((SELECT|DELETE).+FROM|INSERT.+INTO|UPDATE.+SET)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-1";
			call vfw_main;
		}

		if (req.url ~ "(?i)UNION.+(SELECT|INSERT|UPDATE|DELETE|SHOW|DROP)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-2";
			call vfw_main;
		}

		if (req.url ~ "(?i)(SHOW|DROP|CREATE).+(DATABASES?|TABLES?|PROCESSLIST)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-3";
			call vfw_main;
		}

		if (req.http.X-VFW-Body) {
			if (req.http.X-VFW-Body ~ "(?i)((SELECT|DELETE).+FROM|INSERT.+INTO|UPDATE.+SET)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-4";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)UNION.+(SELECT|INSERT|UPDATE|DELETE|SHOW|DROP)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-5";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(SHOW|DROP|CREATE).+(DATABASES?|TABLES?|PROCESSLIST)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-6";
				call vfw_main;
			}
		}
	}
}
