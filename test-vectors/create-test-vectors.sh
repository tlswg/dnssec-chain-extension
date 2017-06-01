#!/bin/sh

ldns-signzone -i 20170530 -e 20170612 -o . root K.+013+47005
ldns-signzone -i 20170529 -e 20170605 -o com com  Kcom.+013+18931
ldns-signzone -i 20170525 -e 20170615 -o org org  Korg.+013+12651
ldns-signzone -i 20170525 -e 20170615 -o net net  Knet.+013+00485
cat >example.org <<EOSOA
\$TTL 3600
example.org.	SOA sns.dns.icann.org. noc.dns.icann.org. (
		2017042720 ; serial
		7200       ; refresh (2 hours)
		3600       ; retry (1 hour)
		1209600    ; expire (2 weeks)
		3600       ; minimum (1 hour)
		)
_443._tcp.www.example.org.	CNAME	dane311.example.org.
EOSOA
ldns-dane -c www.example.com.crt create example.org. 443 3 1 1 | sed 's/^_443._tcp/dane311/g' >> example.org
ldns-dane -c www.example.com.crt create example.org. 25 3 1 1 | sed 's/^_25/*/g' >> example.org
ldns-signzone -b -n -i 20170526 -e 20170616 -o example.org example.org Kexample.org.+013+44384

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
ldns-dane -c www.example.com.crt create example.com. 443 3 1 1 | sed 's/^_443/*/g' >> example.com
ldns-dane -c www.example.com.crt create www.example.com. 443 3 1 1 >> example.com
ldns-signzone -i 20170526 -e 20170616 -o example.com example.com Kexample.com.+013+01870

cat >example.net <<EOSOA
\$TTL 3600
example.net.	SOA sns.dns.icann.org. noc.dns.icann.org. (
		2017042720 ; serial
		7200       ; refresh (2 hours)
		3600       ; retry (1 hour)
		1209600    ; expire (2 weeks)
		3600       ; minimum (1 hour)
		)
example.net.	DNAME	example.com.
EOSOA
ldns-signzone -i 20170526 -e 20170616 -o example.net example.net Kexample.net.+013+48085


(	grep '^_443\._tcp\.www\..*	TLSA' example.com.signed
	grep '	DNSKEY' example.com.signed
	grep '^example\.com.*	DS' com.signed
	grep '	DNSKEY' com.signed
	grep '^com\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > www.example.com.chain
./verify-chain root.ds www.example.com.chain www.example.com 443 > www.example.com.wireformat && echo "straight forward successful"


(	grep '^\*\._tcp\..*	TLSA'  example.com.signed | sed 's/^\*/_25/g'
	grep '^\*\._tcp\..*	NSEC'  example.com.signed
	grep '	DNSKEY' example.com.signed
	grep '^example\.com.*	DS' com.signed
	grep '	DNSKEY' com.signed
	grep '^com\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > example.com.chain
./verify-chain root.ds example.com.chain example.com 25 > /dev/null && echo "Wildcard case successful"

(	grep '^\*\._tcp\..*	TLSA'  example.org.signed | sed 's/^\*/_25/g'
	grep '^dlm7rss9pejqnh0ev6h7k1ikqqcl5mae.example.org.' example.org.signed
	grep '	DNSKEY' example.org.signed
	grep '^example\.org.*	DS' org.signed
	grep '	DNSKEY' org.signed
	grep '^org\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > example.org.chain
./verify-chain root.ds example.org.chain example.org 25 > /dev/null && echo "NSEC3 wildcard case successful"

(	grep '^_443\._tcp\..*	CNAME'  example.org.signed
	grep '^dane311\..*	TLSA'  example.org.signed
	grep '	DNSKEY' example.org.signed
	grep '^example\.org.*	DS' org.signed
	grep '	DNSKEY' org.signed
	grep '^org\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > www.example.org.chain
./verify-chain root.ds www.example.org.chain www.example.org 443 > /dev/null && echo "CNAME case successful"

(	grep '^example\.net.*	DNAME'  example.net.signed
	printf "_443._tcp.www.example.net.\t3600\tIN\tCNAME\t_443._tcp.www.example.com.\n"
	grep '^_443\._tcp\.www\..*	TLSA' example.com.signed

	grep '	DNSKEY' example.net.signed
	grep '^example\.net.*	DS' net.signed
	grep '	DNSKEY' net.signed
	grep '^net\..*	DS' root.signed
	grep '	DNSKEY' root.signed

	grep '	DNSKEY' example.com.signed
	grep '^example\.com.*	DS' com.signed
	grep '	DNSKEY' com.signed
	grep '^com\..*	DS' root.signed
	#grep '	DNSKEY' root.signed

) > www.example.net.chain
./verify-chain root.ds www.example.net.chain www.example.net 443 > /dev/null && echo "DNAME case successful"

