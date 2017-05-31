#include <stdio.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

int main(int argc, const char **argv)
{
	FILE *ta_file = NULL;
	getdns_list *tas = NULL;
	getdns_return_t r = GETDNS_RETURN_GENERIC_ERROR;
	FILE *chain_file = NULL;
	getdns_list *chain = NULL;
	getdns_list *support = NULL;
	getdns_list *to_validate = NULL;
	size_t chain_len, i;
	getdns_return_t dnssec_status;

	if (argc != 3)
		fprintf(stderr, "usage: %s <trust anchor file> <chain file>\n"
		              , argv[0]);

	else if (!(to_validate = getdns_list_create()))
		fprintf(stderr, "Error creating list\n");

	else if (!(support = getdns_list_create()))
		fprintf(stderr, "Error creating list\n");

	else if (!(ta_file = fopen(argv[1], "r")))
		perror("Error opening trust anchor file");

	else if ((r = getdns_fp2rr_list(ta_file, &tas, NULL, 0))) 
		fprintf(stderr, "Error reading trust anchor file");

	else if (!(chain_file = fopen(argv[2], "r")))
		perror("Error opening chain file");

	else if ((r = getdns_fp2rr_list(chain_file, &chain, NULL, 0))) 
		fprintf(stderr, "Error reading chain file");

	else if ((r = getdns_list_get_length(chain, &chain_len))) 
		fprintf(stderr, "Error getting length of chain");

	else for (i = 0; i < chain_len; i++) {
		getdns_dict *rr;
		uint32_t rr_type;
		getdns_list *append = NULL;
		size_t a;

		if ((r = getdns_list_get_dict(chain, i, &rr)) ||
		    (r = getdns_dict_get_int(rr, "type", &rr_type))) {
			fprintf(stderr, "Error getting RR type");
			break;
		}
		if (rr_type == GETDNS_RRTYPE_RRSIG &&
		    (r = getdns_dict_get_int(rr, "/rdata/type_covered"
		                               , &rr_type))) {
			fprintf(stderr, "Error getting covered RR type");
			break;
		}
		append = (rr_type == GETDNS_RRTYPE_DNSKEY ||
		          rr_type == GETDNS_RRTYPE_DS) ? support : to_validate;
	
		if ((r = getdns_list_get_length(append, &a)) ||
		    (r = getdns_list_set_dict(append, a, rr))) {
			fprintf(stderr, "Error appending RR");
			break;
		}
	}
	if (r == GETDNS_RETURN_GOOD &&
	    (dnssec_status = getdns_validate_dnssec2(to_validate, support, tas,
	     1496233729, 0) != GETDNS_DNSSEC_SECURE)) {
		fprintf(stderr, "Chain did not validate");
		r = dnssec_status;

	} else if (r == GETDNS_RETURN_GOOD) {
		uint8_t buf[8192], *ptr = buf;
		int buf_sz = sizeof(buf);

		for (i = 0; i < chain_len; i++) {
			getdns_dict  *rr;

			(void) getdns_list_get_dict(chain, i, &rr);
			if ((r = getdns_rr_dict2wire_scan(rr, &ptr, &buf_sz))) {
				fprintf(stderr, "Error converting to writeformat");
				break;
			}
		}
		if (!r) for (i = 0; i < ptr - buf; i++) {
			if (i % 16 == 0) {
				if (i > 0)
					printf("\n");
				printf("%.4x: ", (int)i);
			} else if (i % 8 == 0)
				printf(" ");
			printf(" %.2x", (int)buf[i]);
		}
		printf("\n");
	}
	if (support) getdns_list_destroy(support);
	if (chain_file) fclose(chain_file);
	if (tas) getdns_list_destroy(tas);
	if (ta_file) fclose(ta_file);
	if (to_validate) getdns_list_destroy(to_validate);
	if (r) {
		if (r != GETDNS_RETURN_GENERIC_ERROR)
			fprintf(stderr, ": %s\n", getdns_get_errorstr_by_id(r));
		exit(EXIT_FAILURE);
	}
	return 0;
}
