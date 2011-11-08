#!/bin/bash

VRSHPREFIX="/opt/varnish-3"
VRSHUSER="root"
VRSHGROUP="varnish"
VRSHPORT=80

${VRSHPREFIX}/sbin/varnishd -F -f ${VRSHPREFIX}/varnish/default.vcl -u ${VRSHUSER} -g ${VRSHGROUP} -a :${VRSHPORT} -n debug_instance -s file,/tmp/varnish_debug_storage.bin,10M -p 'cc_command=exec gcc -std=gnu99 -DDIAGNOSTICS -pthread -fpic -shared -Wl,-x -I/root/varnish-3.0.0 -I/root/varnish-3.0.0/include -o %o %s'
