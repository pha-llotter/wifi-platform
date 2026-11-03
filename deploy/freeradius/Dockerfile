# FreeRADIUS for the school SSID: EAP-TTLS logins checked against Google Secure LDAP,
# with the VLAN decided by the WiFi platform. Settings come from radius.env.
FROM freeradius/freeradius-server:3.2.10

RUN rm -f /etc/freeradius/sites-enabled/* /etc/freeradius/mods-enabled/eap
COPY clients.conf /etc/freeradius/clients.conf
COPY mods/eap mods/ldap mods/platform /etc/freeradius/mods-enabled/
COPY sites/default sites/inner-tunnel sites/status /etc/freeradius/sites-enabled/
COPY run.sh /usr/local/bin/run-freeradius
RUN chmod 0755 /usr/local/bin/run-freeradius \
 && chown -R root:freerad /etc/freeradius/clients.conf /etc/freeradius/mods-enabled /etc/freeradius/sites-enabled

EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/usr/local/bin/run-freeradius"]
