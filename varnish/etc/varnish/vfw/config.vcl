# LOAD POST DATA (MUST BE FIST)
include "/opt/varnish-3/etc/varnish/vfw/post.vcl";

# Protocol
include "/opt/varnish-3/etc/varnish/vfw/protocol.vcl";

# Paths/Files extensions
include "/opt/varnish-3/etc/varnish/vfw/paths.vcl";

# Generic attacks
include "/opt/varnish-3/etc/varnish/vfw/generic.vcl";

# SQL Injection
include "/opt/varnish-3/etc/varnish/vfw/sql.vcl";

# XSS (Reflected / Stored if post)
include "/opt/varnish-3/etc/varnish/vfw/xss.vcl";
