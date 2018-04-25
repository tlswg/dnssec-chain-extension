#!/bin/sh

#
# root and org roll their ZSK
#  com and org roll their KSK
# example.com and example.net use a CSK (combined signing key)
# 
INCEPTION="20151103"
EXPIRATION="20181128"

ldns-signzone -i $INCEPTION -e $EXPIRATION -o . root K.+013+47005 K.+013+31918 K.+013+02635 && \
	grep -v '	RRSIG	.* 2635 \. ' root.signed > root.signed.2 && \
	mv root.signed.2 root.signed
ldns-signzone -i $INCEPTION -e $EXPIRATION -o com com  Kcom.+013+18931 Kcom.+013+28809 Kcom.+013+34327
ldns-signzone -i $INCEPTION -e $EXPIRATION -o org org  Korg.+013+12651 Korg.+013+49352 Korg.+013+09523 Korg.+013+47417 && \
	grep -v '	RRSIG	.* 47417 org\. ' org.signed > org.signed.2 && \
	mv org.signed.2 org.signed
ldns-signzone -i $INCEPTION -e $EXPIRATION -o net net  Knet.+013+00485 Knet.+013+10713
ldns-signzone -b -i $INCEPTION -e $EXPIRATION -n -p -o example example Kexample.+013+15903
cat >>example.signed <<EOINSECURE
insecure.example.	NS	ns.secure.example.
ns-servers.example.	NS	ns.ns-servers.example.
EOINSECURE
cat >example.org <<EOSOA
\$TTL 3600
example.org.	SOA sns.dns.icann.org. noc.dns.icann.org. (
		2017042720 ; serial
		7200       ; refresh (2 hours)
		3600       ; retry (1 hour)
		1209600    ; expire (2 weeks)
		3600       ; minimum (1 hour)
		)
example.org.	NS	a.iana-servers.net.
example.org.	NS	b.iana-servers.net.
example.org.	MX	10 smtp.example.org.
www.example.org.	A	192.0.2.1
www.example.org.	AAAA	2001:DB8::1
smtp.example.org.	A	192.0.2.2
smtp.example.org.	AAAA	2001:DB8::2
_443._tcp.www.example.org.	CNAME	dane311.example.org.
EOSOA
ldns-dane -c www.example.com.crt create example.org. 443 3 1 1 | sed 's/^_443._tcp/dane311/g' >> example.org
ldns-dane -c www.example.com.crt create example.org. 666 3 1 1 | sed 's/^_666/*/g' >> example.org
ldns-signzone -b -n -i $INCEPTION -e $EXPIRATION -o example.org example.org Kexample.org.+013+44384 Kexample.org.+013+56566

cat >example.com <<EOSOA
\$TTL 3600
example.com.	SOA sns.dns.icann.org. noc.dns.icann.org. (
		2017042720 ; serial
		7200       ; refresh (2 hours)
		3600       ; retry (1 hour)
		1209600    ; expire (2 weeks)
		3600       ; minimum (1 hour)
		)
example.com.	NS	a.iana-servers.net.
example.com.	NS	b.iana-servers.net.
example.com.	MX	10 smtp.example.com.
www.example.com.	A	192.0.2.3
www.example.com.	AAAA	2001:DB8::3
smtp.example.com.	A	192.0.2.4
smtp.example.com.	AAAA	2001:DB8::5
EOSOA
ldns-dane -c www.example.com.crt create example.com. 443 3 1 1 | sed 's/^_443/*/g' >> example.com
ldns-dane -c www.example.com.crt create www.example.com. 443 3 1 1 >> example.com
ldns-signzone -i $INCEPTION -e $EXPIRATION -o example.com example.com Kexample.com.+013+01870

cat >example.net <<EOSOA
\$TTL 3600
example.net.	SOA sns.dns.icann.org. noc.dns.icann.org. (
		2017042720 ; serial
		7200       ; refresh (2 hours)
		3600       ; retry (1 hour)
		1209600    ; expire (2 weeks)
		3600       ; minimum (1 hour)
		)
example.net.	NS	a.iana-servers.net.
example.net.	NS	b.iana-servers.net.
example.net.	MX	10 smtp.example.com.
example.net.	DNAME	example.com.
EOSOA
ldns-signzone -i $INCEPTION -e $EXPIRATION -o example.net example.net Kexample.net.+013+48085


(	grep '^_443\._tcp\.www\..*	TLSA' example.com.signed
	grep '	DNSKEY' example.com.signed
	grep '^example\.com.*	DS' com.signed
	grep '	DNSKEY' com.signed
	grep '^com\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > 00-straight-www.example.com.chain
./verify-chain root.ds 00-straight-www.example.com.chain www.example.com 443 > www.example.com.wireformat && echo "straight forward successful"


(	grep '^\*\._tcp\..*	TLSA'  example.com.signed | sed 's/^\*/_25/g'
	grep '^\*\._tcp\..*	NSEC'  example.com.signed
	grep '	DNSKEY' example.com.signed
	grep '^example\.com.*	DS' com.signed
	grep '	DNSKEY' com.signed
	grep '^com\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > 10-wildcard-nsec-example.com.chain
./verify-chain root.ds 10-wildcard-nsec-example.com.chain example.com 25 > /dev/null && echo "Wildcard case successful"

(	grep '^\*\._tcp\..*	TLSA'  example.org.signed | sed 's/^\*/_25/g'
	grep '^dlm7rss9pejqnh0ev6h7k1ikqqcl5mae.example.org.' example.org.signed
	grep '	DNSKEY' example.org.signed
	grep '^example\.org.*	DS' org.signed
	grep '	DNSKEY' org.signed
	grep '^org\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > 15-wildcard-nsec3-example.org.chain
./verify-chain root.ds 15-wildcard-nsec3-example.org.chain example.org 25 > /dev/null && echo "NSEC3 wildcard case successful"

(	grep '^_443\._tcp\..*	CNAME'  example.org.signed
	grep '^dane311\..*	TLSA'  example.org.signed
	grep '	DNSKEY' example.org.signed
	grep '^example\.org.*	DS' org.signed
	grep '	DNSKEY' org.signed
	grep '^org\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > 20-cname-www.example.org.chain
./verify-chain root.ds 20-cname-www.example.org.chain www.example.org 443 > /dev/null && echo "CNAME case successful"

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

) > 30-dname-www.example.net.chain
./verify-chain root.ds 30-dname-www.example.net.chain www.example.net 443 > /dev/null && echo "DNAME case successful"

(
	grep '	SOA' example.com.signed # Minimum used as NX ttl 
	grep '^smtp\.example\.com\..*	NSEC' example.com.signed # Closest encloser & cover smtp.example.com
	grep '	DNSKEY' example.com.signed
	grep '^example\.com.*	DS' com.signed
	grep '	DNSKEY' com.signed
	grep '^com\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > 40-denial-nsec-example.com.chain
./verify-chain root.ds 40-denial-nsec-example.com.chain smtp.example.com 25 > /dev/null && echo "NSEC denial of existance case successful"

(
	grep '	SOA' example.org.signed # Minimum used as NX ttl 
	grep '^vkv62jbv85822q8rtmfnbhfnmnat9ve3.example.org.' example.org.signed # Closest encloser smtp.example.org
	grep '^dlm7rss9pejqnh0ev6h7k1ikqqcl5mae.example.org.' example.org.signed # Covers _tcp.smtp.example.org
	grep '^a73bi8coh6dvf1arqdeuogf95r0828mk.example.org.' example.org.signed # Covers *.smtp.example.org
	grep '	DNSKEY' example.org.signed
	grep '^example\.org.*	DS' org.signed
	grep '	DNSKEY' org.signed
	grep '^org\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > 45-denial-nsec3-example.org.chain
./verify-chain root.ds 45-denial-nsec3-example.org.chain smtp.example.org 25 > /dev/null && echo "NSEC3 denial of existance case successful"

(
	grep '	SOA' example.signed # Minimum used as NX ttl 
	grep '^c1kgc91hrn9nqi2qjh1ms78ki8p7s75o.example.' example.signed # Closest encloser example + cover insecure.example
	grep '^shn05itmoa45mmnv74lc4p0nnfmimtjt.example.' example.signed # Covers *.example (by wrapping around)
	grep '	DNSKEY' example.signed
	grep '^example\..*	DS' root.signed
	grep '	DNSKEY' root.signed
) > 50-insecure-nsec3-optout-example.chain
./verify-chain root.ds 50-insecure-nsec3-optout-example.chain www.insecure.example 443 403 > /dev/null && echo "NSEC3 opt-out insecure delegation case successful"


