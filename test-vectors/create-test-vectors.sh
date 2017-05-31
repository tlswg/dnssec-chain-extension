#!/bin/sh

ldns-signzone -i 20170530 -e 20170612 -o . root K.+008+04354 K.+008+08835
ldns-signzone -i 20170529 -e 20170605 -o com com  Kcom.+008+36201 Kcom.+008+50254
ldns-signzone -i 20170525 -e 20170615 -o org org  Korg.+008+44913 Korg.+008+65161
cat >example.org <<EOSOA
\$TTL 3600
example.org.	SOA sns.dns.icann.org. noc.dns.icann.org. (
		2017042720 ; serial
		7200       ; refresh (2 hours)
		3600       ; retry (1 hour)
		1209600    ; expire (2 weeks)
		3600       ; minimum (1 hour)
		)
EOSOA
ldns-dane -c www.example.com.crt create example.org. 443 3 1 1 >> example.org
ldns-dane -c www.example.com.crt create www.example.org. 443 3 1 1 >> example.org
ldns-signzone -i 20170526 -e 20170616 -o example.org example.org Kexample.org.+008+00033 Kexample.org.+008+38853

cat >example.com <<EOSOA
\$TTL 3600
example.com.	SOA sns.dns.icann.org. noc.dns.icann.org. (
		2017042720 ; serial
		7200       ; refresh (2 hours)
		3600       ; retry (1 hour)
		1209600    ; expire (2 weeks)
		3600       ; minimum (1 hour)
		)
EOSOA
ldns-dane -c www.example.com.crt create example.com. 443 3 1 1 >> example.com
ldns-dane -c www.example.com.crt create www.example.com. 443 3 1 1 >> example.com
ldns-signzone -i 20170526 -e 20170616 -o example.com example.com Kexample.com.+008+10024 Kexample.com.+008+40575

(	grep '^_443\._tcp\.www\..*	TLSA' example.com.signed
	grep '	DNSKEY' example.com.signed
	grep '^example\.com.*	DS' com.signed
	grep '	DNSKEY' com.signed
	grep '^com\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > www.example.com.chain
