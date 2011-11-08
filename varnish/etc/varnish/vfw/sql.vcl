sub vcl_recv {
	if (!req.http.X-VFW-Static) {
		if (req.url ~ "(?i)(S|%[57]3)(E|%[46]5)(L|%[46]C)(E|%[46]5)(C|%[46]3)(T|%[57]4)(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*(F|%[46]6)(R|%[57]2)(O|%[46]F)(M|%[46]D)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-1";
			call vfw_main;
		}

		if (req.url ~ "(?i)(I|%[46]9)(N|%[46]E)(S|%[57]3)(E|%[46]5)(R|%[57]2)(T|%[57]4)(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*(I|%[46]9)(N|%[46]E)(T|%[57]4)(O|%[46]F)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-2";
			call vfw_main;
		}

		if (req.url ~ "(?i)(U|%[57]5)(P|%[57]0)(D|%[46]4)(A|%[46]1)(T|%[57]4)(E|%[46]5)(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*(S|%[57]3)(E|%[46]5)(T|%[57]4)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-3";
			call vfw_main;
		}

		if (req.url ~ "(?i)(D|%[46]4)(E|%[46]5)(L|%[46]C)(E|%[46]5)(T|%[57]4)(E|%[46]5)(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*(F|%[46]6)(R|%[57]2)(O|%[46]F)(M|%[46]D)") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-4";
			call vfw_main;
		}

		if (req.url ~ "(?i)(U|%[57]5)(N|%[46]E)(I|%[46]9)(O|%[46]F)(N|%[46]E)(\+|%20|%09)+[^&]*((S|%[57]3)(E|%[46]5)(L|%[46]C)(E|%[46]5)(C|%[46]3)(T|%[57]4)|(I|%[46]9)(N|%[46]E)(S|%[57]3)(E|%[46]5)(R|%[57]2)(T|%[57]4)|(U|%[57]5)(P|%[57]0)(D|%[46]4)(A|%[46]1)(T|%[57]4)(E|%[46]5)|(D|%[46]4)(E|%[46]5)(L|%[46]C)(E|%[46]5)(T|%[57]4)(E|%[46]5))") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-5";
			call vfw_main;
		}

		if (req.url ~ "(?i)(U|%[57]5)(N|%[46]E)(I|%[46]9)(O|%[46]F)(N|%[46]E)(\+|%20|%09)+[^&]*((S|%[57]3)(H|%[46]8)(O|%[46]F)(W|%[57]7)|(D|%[46]4)(R|%[57]2)(O|%[46]F)(P|%[57]0))") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-6";
			call vfw_main;
		}

		if (req.url ~ "(?i)((S|%[57]3)(H|%[46]8)(O|%[46]F)(W|%[57]7)|(D|%[46]4)(R|%[57]2)(O|%[46]F)(P|%[57]0)|(C|%[46]3)(R|%[57]2)(E|%[46]5)(A|%[46]1)(T|%[57]4)(E|%[46]5))(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*((D|%[46]4)(A|%[46]1)(T|%[57]4)(A|%[46]1)(B|%[46]2)(A|%[46]1)(S|%[57]3)(E|%[46]5)(S|%[57]3)?|(T|%[57]4)(A|%[46]1)(B|%[46]2)(L|%[46]C)(E|%[46]5)(S|%[57]3)?|(P|%[57]0)(R|%[57]2)(O|%[46]F)(C|%[46]3)(E|%[46]5)(S|%[57]3)(S|%[57]3)(L|%[46]C)(I|%[46]9)(S|%[57]3)(T|%[57]4))") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-7";
			call vfw_main;
		}

		// problems with \"
		// (?i)(\s|%20|\t|%09|\+)+(OR|AND)(\s|%20|\t|%09|\+)+(\'|%27|\"|%22)?(\s|%20|\t|%09|\+)*\d+(\s|%20|\t|%09|\+)*(\'|%27|\"|%22)?(\s|%20|\t|%09|\+)*(=|%3D)(\s|%20|\t|%09|\+)*(\'|%27|\"|%22)?(\s|%20|\t|%09|\+)*\d+
		if (req.url ~ "(?i)((O|%[46]F)(R|%[57]2)|(A|%[46]1)(N|%[46]E)(D|%[46]4))(\s|%20|\t|%09|\+)+(\'|%27|%22)?(\s|%20|\t|%09|\+)*\d+(\s|%20|\t|%09|\+)*(\'|%27|%22)?(\s|%20|\t|%09|\+)*(=|%3D|>|%3e|<|%3c)+(\s|%20|\t|%09|\+)*(\'|%27|%22)?(\s|%20|\t|%09|\+)*\d+") {
			set req.http.X-VFW-Threat = "SQL Injection";
			set req.http.X-VFW-RuleID = "sql.sql-8";
			call vfw_main;
		}

		if (req.http.X-VFW-Body) {
			if (req.http.X-VFW-Body ~ "(?i)(S|%[57]3)(E|%[46]5)(L|%[46]C)(E|%[46]5)(C|%[46]3)(T|%[57]4)(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*(F|%[46]6)(R|%[57]2)(O|%[46]F)(M|%[46]D)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-9";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(I|%[46]9)(N|%[46]E)(S|%[57]3)(E|%[46]5)(R|%[57]2)(T|%[57]4)(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*(I|%[46]9)(N|%[46]E)(T|%[57]4)(O|%[46]F)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-10";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(U|%[57]5)(P|%[57]0)(D|%[46]4)(A|%[46]1)(T|%[57]4)(E|%[46]5)(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*(S|%[57]3)(E|%[46]5)(T|%[57]4)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-11";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(D|%[46]4)(E|%[46]5)(L|%[46]C)(E|%[46]5)(T|%[57]4)(E|%[46]5)(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*(F|%[46]6)(R|%[57]2)(O|%[46]F)(M|%[46]D)") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-12";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(U|%[57]5)(N|%[46]E)(I|%[46]9)(O|%[46]F)(N|%[46]E)(\+|%20|%09)+[^&]*((S|%[57]3)(E|%[46]5)(L|%[46]C)(E|%[46]5)(C|%[46]3)(T|%[57]4)|(I|%[46]9)(N|%[46]E)(S|%[57]3)(E|%[46]5)(R|%[57]2)(T|%[57]4)|(U|%[57]5)(P|%[57]0)(D|%[46]4)(A|%[46]1)(T|%[57]4)(E|%[46]5)|(D|%[46]4)(E|%[46]5)(L|%[46]C)(E|%[46]5)(T|%[57]4)(E|%[46]5))") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-13";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)(U|%[57]5)(N|%[46]E)(I|%[46]9)(O|%[46]F)(N|%[46]E)(\+|%20|%09)+[^&]*((S|%[57]3)(H|%[46]8)(O|%[46]F)(W|%[57]7)|(D|%[46]4)(R|%[57]2)(O|%[46]F)(P|%[57]0))") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-14";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)((S|%[57]3)(H|%[46]8)(O|%[46]F)(W|%[57]7)|(D|%[46]4)(R|%[57]2)(O|%[46]F)(P|%[57]0)|(C|%[46]3)(R|%[57]2)(E|%[46]5)(A|%[46]1)(T|%[57]4)(E|%[46]5))(\s|%20|\t|%09|\+)+[^&]*(\s|%20|\t|%09|\+)*((D|%[46]4)(A|%[46]1)(T|%[57]4)(A|%[46]1)(B|%[46]2)(A|%[46]1)(S|%[57]3)(E|%[46]5)(S|%[57]3)?|(T|%[57]4)(A|%[46]1)(B|%[46]2)(L|%[46]C)(E|%[46]5)(S|%[57]3)?|(P|%[57]0)(R|%[57]2)(O|%[46]F)(C|%[46]3)(E|%[46]5)(S|%[57]3)(S|%[57]3)(L|%[46]C)(I|%[46]9)(S|%[57]3)(T|%[57]4))") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-15";
				call vfw_main;
			}

			if (req.http.X-VFW-Body ~ "(?i)((O|%[46]F)(R|%[57]2)|(A|%[46]1)(N|%[46]E)(D|%[46]4))(\s|%20|\t|%09|\+)+(\'|%27|%22)?(\s|%20|\t|%09|\+)*\d+(\s|%20|\t|%09|\+)*(\'|%27|%22)?(\s|%20|\t|%09|\+)*(=|%3D|>|%3e|<|%3c)+(\s|%20|\t|%09|\+)*(\'|%27|%22)?(\s|%20|\t|%09|\+)*\d+") {
				set req.http.X-VFW-Threat = "SQL Injection";
				set req.http.X-VFW-RuleID = "sql.sql-16";
				call vfw_main;
			}
		}
	}
}
