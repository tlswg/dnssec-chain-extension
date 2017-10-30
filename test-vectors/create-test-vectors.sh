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
example.net.	DNAME	example.com.
EOSOA
ldns-signzone -i $INCEPTION -e $EXPIRATION -o example.net example.net Kexample.net.+013+48085


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

