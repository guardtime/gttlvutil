#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include "fast_tlv.h"
#include "desc.h"
#include "common.h"
#include "dir.h"

#ifdef _WIN32
#	include <io.h>
#	include <fcntl.h>
#endif

#define INDENT_LEN 2

enum out_enc_en { ENCODE_HEX, ENCODE_BASE64 };

struct conf_st {
	const char *file_name;
	size_t hdr_len;
	size_t max_depth;
	bool print_off;
	bool wrap;
	bool print_len;
	bool convert;
	bool use_desc;
	bool type_strict;
	bool pretty_val;
	bool pretty_key;
	struct desc_st desc;
	enum out_enc_en out_enc;
};

static char *hash_alg[] = {
	"sha-1", "sha2-256", "ripemd-160", "sha2-224", "sha2-384", "sha2-512", "ripemd-256", "sha3-224", "sha3-256", "sha3-512", "sm3"
};

static char descriptionDir[2048];

static const char *getDescriptionFileDir(void) {
	if (descriptionDir[0] == '\0') {
		return ".";
	} else {
		return descriptionDir;
	}
}

void setDescriptionFileDir(const char *dir) {
	if (dir == NULL) {
		descriptionDir[0] = '\0';
		return;
	}

	strncpy(descriptionDir, dir, sizeof(descriptionDir));
	descriptionDir[sizeof(descriptionDir) - 1] = '\0';
}



static uint64_t get_uint64(unsigned char *buf, size_t len) {
	uint64_t val = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		val = (val << 8) | buf[i];
	}

	return val;
}

#define wrap_line(p) if (conf->wrap && line_len > 0 && line_len % 64 == 0 ) { printf("\n%*s", prefix_len, ""); len = 0; } line_len += p
static void print_hex(unsigned char *buf, size_t len, int prefix_len, struct conf_st *conf) {
	size_t i;
	size_t line_len = 0;

	for (i = 0; i < len; i++) {
		wrap_line(printf("%02x", buf[i]));
	}

	if (conf->convert && len <= 8) {
		printf(" (dec = %llu)", (unsigned long long) get_uint64(buf, len));
	}
	putchar('\n');
}

static void print_base64(unsigned char *buf, size_t len, int prefix_len, struct conf_st *conf) {
	size_t i;
	size_t line_len = 0;
	static char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for (i = 0; i < len; i += 3) {
		unsigned char a = buf[i] >> 2;

		wrap_line(printf("%c", tab[a]));
		if (i + 1 < len) {
			unsigned char b = ((buf[i] & 0x03) << 4) | (buf[i + 1] >> 4);

			wrap_line(printf("%c", tab[b]));
			if (i + 2 < len) {
				unsigned char c = ((buf[i + 1] & 0x0f) << 2) | (buf[i + 2] >> 6);
				unsigned char d = buf[i + 2] & 0x3f;
				wrap_line(printf("%c", tab[c]));
				wrap_line(printf("%c", tab[d]));
			} else {
				wrap_line(printf("="));
			}
		} else {
			wrap_line(printf("=="));
		}
	}

	if (conf->convert && len <= 8) {
		printf(" (dec = %llu)", (unsigned long long)get_uint64(buf, len));
	}
	putchar('\n');
}



static void print_raw_data(unsigned char *buf, size_t len, int prefix_len, struct conf_st *conf) {
	switch (conf->out_enc) {
		case ENCODE_BASE64:
			print_base64(buf, len, prefix_len, conf);
			break;
		case ENCODE_HEX:
		default:
			print_hex(buf, len, prefix_len, conf);
	}
}

static int get_payload_type(unsigned char *buf, size_t buf_len, struct conf_st *conf, struct desc_st *desc) {
	int res = GT_UNKNOWN_ERROR;
	int type = TLV_RAW;
	size_t len = buf_len;
	unsigned char *ptr = buf;

	if (desc != NULL) {
		if (desc->type == TLV_COMPOSITE) {
			/* Make sure the content is actually parsable. */
			res = GT_FTLV_memReadN(ptr, len, NULL, 0, NULL);
			if (res != GT_OK) {
				type = TLV_NO_COMPOSITE;
				goto cleanup;
			}
		}
		type = desc->type;
		goto cleanup;
	}

	res = GT_FTLV_memReadN(ptr, len, NULL, 0, NULL);
	if (res != GT_OK) goto cleanup;

	if (conf->type_strict) {
		while (len > 0) {
			GT_FTLV n;
			struct desc_st *d = NULL;

			res = GT_FTLV_memRead(ptr, len, &n);
			if (res != GT_OK) goto cleanup;

			/* Try to find sub type. */
			if (desc != NULL) {
				desc_find(desc, n.tag, &d);
			}

			/* Try to find top-level type, if sub type not found. */
			if (d == NULL) {
				desc_find(&conf->desc, n.tag, &d);
			}

			/* If still not found, mark as raw. */
			if (d == NULL) goto cleanup;

			len -= n.hdr_len + n.dat_len;
			ptr += n.hdr_len + n.dat_len;
		}
	}

	type = TLV_COMPOSITE;

cleanup:

	return type;
}

static void print_int(unsigned char *buf, size_t len, int prefix_len, struct conf_st *conf) {

	if (len > 8) {
		printf("0x");
		print_raw_data(buf, len, prefix_len, conf);
	} else {
		printf("%llu\n", (unsigned long long)get_uint64(buf, len));
	}
}

static void print_str(unsigned char *buf, size_t len, size_t prefix_len, struct conf_st *conf) {
	size_t i;
	char special[] = "\\\"";
	putchar('"');
	for (i = 0; i < len; i++) {
		if (isprint(buf[i])) {
			if (strchr(special, buf[i])) {
				putchar('\\');
			}
			putchar(buf[i]);
		} else {
			printf("\\%u", buf[i]);
		}
	}
	putchar('"');
	putchar('\n');
}

static void print_imprint(unsigned char *buf, size_t len, int prefix_len, struct conf_st *conf) {
	if (len > 0) {
		if (buf[0] < sizeof(hash_alg) / sizeof(char *)) {
			printf("%s:", hash_alg[buf[0]]);
			print_raw_data(buf + 1, len - 1, prefix_len, conf);
		} else {
			print_raw_data(buf, len, prefix_len, conf);
		}
	}
}

static void print_time(unsigned char *buf, size_t len, int prefix_len, int type, struct conf_st *conf) {
	if (len > 8) {
		print_raw_data(buf, len, prefix_len, conf);
	} else {
		char tmp[0xff];
		char fract[0x1f];
		struct tm *tm_info;
		uint64_t t = get_uint64(buf, len);
		time_t seconds;
		size_t len;

		fract[0] = '\0';
		tmp[0] = '\0';

		switch (type) {
			case TLV_MTIME:
				seconds = (time_t) t / 1000;
				snprintf(fract, sizeof(fract), "%03llu", (unsigned long long)(t % 1000));
				break;
			case TLV_UTIME:
				seconds = (time_t) t / 1000 / 1000;
				snprintf(fract, sizeof(fract), "%06llu", (unsigned long long)(t % (1000 * 1000)));
				break;
			case TLV_TIME:
			default:
				seconds = (time_t) t;
				break;
		}

		if (seconds >= 0xffffffff) {
			fprintf(stderr, "Invalid time value.\n");
		} else {
			tm_info = gmtime(&seconds);
			len = strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", tm_info);
			if (fract[0] != '\0') {
				len += snprintf(tmp + len, sizeof(tmp) - len, ".%s", fract);
			}

			strftime(tmp + len, sizeof(tmp) - len, " %Z", tm_info);
		}
		printf("(%llu) %s\n", (unsigned long long)t, tmp);
	}
}


static void printTlv(unsigned char *buf, size_t buf_len, GT_FTLV *t, int level, struct conf_st *conf, struct desc_st *desc) {
	unsigned char *ptr = buf + t->hdr_len;
	size_t len = t->dat_len;
	int prefix_len = 0;
	struct desc_st *sub = NULL;
	int type;
	bool limited = false;

	/* Find the description. */
	if (desc == NULL) {
		desc_find(&conf->desc, t->tag, &desc);
	}

	/* Print annotations? */
	if (conf->use_desc) {
		if (desc != NULL && desc->val != NULL) {
			printf("%*s# %s.\n", level * INDENT_LEN, "", desc->val);
		}
	}

	/* Print offset? */
	if (conf->print_off) {
		prefix_len += printf("%4llu:", (unsigned long long)t->off);
	}

	limited = conf->max_depth != 0 && level + 1 >= (int)conf->max_depth;
	type = get_payload_type(ptr, len, conf, desc);
	if (!limited && type == TLV_NO_COMPOSITE && len != 0) {
		printf("%*s### NOT A COMPOSITE TLV ###\n", level * INDENT_LEN, "");
	}


	/* Print only the indent. */
	prefix_len += printf("%*s", level * INDENT_LEN, "");

	if (t->tag > 31 || t->dat_len > 255) {
		prefix_len += printf("TLV[%04x%s%s]:", t->tag, (t->is_fwd ? ",F" : ""), (t->is_nc ? ",N" : ""));
	} else {
		prefix_len += printf("TLV%s[%02x%s%s]: ", t->force16 ? "16" : "", t->tag, (t->is_fwd ? ",F" : ""), (t->is_nc ? ",N" : ""));
	}

	if (conf->print_len) {
		prefix_len += printf("(L = %llu) ", (unsigned long long)t->dat_len);
	}

	if (conf->pretty_key && desc != NULL && desc->val != NULL && *desc->val) {
		prefix_len += printf("%s: ", desc->val);
	}

	if (type == TLV_COMPOSITE && !limited) {
		size_t off = t->off + t->hdr_len;
		GT_FTLV n;

		putchar('\n');
		while (len > 0) {
			size_t consumed;

			GT_FTLV_memRead(ptr, len, &n);
			n.off = off;

			desc_find(desc, n.tag, &sub);

			consumed = n.hdr_len + n.dat_len;

			printTlv(ptr, consumed, &n, level + 1, conf, sub);

			off += consumed;

			ptr += consumed;
			len -= consumed;
		}
	} else if (type != TLV_RAW && type != TLV_NO_COMPOSITE && conf->pretty_val && !limited) {
		switch (type) {
			case TLV_INT:
				print_int(ptr, len, prefix_len, conf);
				break;
			case TLV_STR:
				print_str(ptr, len, prefix_len, conf);
				break;
			case TLV_TIME:
			case TLV_MTIME:
			case TLV_UTIME:
				print_time(ptr, len, prefix_len, type, conf);
				break;
			case TLV_IMPRINT:
				print_imprint(ptr, len, prefix_len, conf);
				break;
		}
	} else {
		print_raw_data(ptr, len, prefix_len, conf);
	}
}

static int read_from(FILE *f, struct conf_st *conf) {
	int res;
	unsigned char *header = NULL;
	GT_FTLV t;
	unsigned char buf[0xffff + 4];
	size_t len;
	size_t off = 0;

	if (conf->hdr_len > 0) {
		header = calloc(conf->hdr_len, 1);
		if (header == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}
		if (fread(header, conf->hdr_len, 1, f) != 1) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}

		for (len = 0; len < conf->hdr_len; len++) {
			printf("%02x", header[len]);
		}
		printf("\n");
	}

	while (1) {
		res = GT_FTLV_fileRead(f, buf, sizeof(buf), &len, &t);
		if (res != GT_OK) {
			if (len == 0) break;
			fprintf(stderr, "%s: Failed to parse %llu bytes.\n", conf->file_name, (unsigned long long) len);
			break;
		}

		t.off = off;

		printTlv(buf, len, &t, 0, conf, NULL);
		off += len;
	}

	res = GT_OK;

cleanup:

	if (header != NULL) free(header);

	return res;
}

static int read_desc_dir(struct desc_st *desc, const char *dir_name) {
	int res = GT_UNKNOWN_ERROR;
	DIRECTORY *dir = NULL;
	ENTITY *ent;

	memset(desc, 0, sizeof(struct desc_st));

	if (DIRECTORY_open(dir_name, &dir) != DIR_OK) {
		fprintf(stderr, "%s:Unable to access description directory.\n", dir_name);
		res = GT_OK;
		goto cleanup;
	}


	while (DIRECTORY_getNextEntity(dir, &ent) == DIR_OK) {
		size_t len;
		const char *name = NULL;
		if(ENTITY_getType(ent) == DIR_DIR) continue;
		name = ENTITY_getName(ent);
		len = strlen(name);

		if (len > 5 && !strcmp(name + len - 5, ".desc")) {
			char buf[1024];

			snprintf(buf, sizeof(buf), "%s/%s", getDescriptionFileDir(), name);

			res = desc_add_file(desc, buf);
			if (res != GT_OK) {
				fprintf(stderr, "%s/%s: Unable to read description file.\n", dir_name, name);
			}
		}
	}

cleanup:

	DIRECTORY_close(dir);

	return res;
}

int main(int argc, char **argv) {
	int res;
	int c;
	FILE *input = NULL;
	struct conf_st conf;
	bool desc_free = false;

#ifdef DATA_DIR
	setDescriptionFileDir(DATA_DIR);
#else
	char buf[1024];

	if(DIRECTORY_getMyPath(buf, sizeof(buf)) != GT_OK) {
		fprintf(stderr, "Unable to get path to gttlvdump.\n");
	}

	setDescriptionFileDir(buf);
#endif

	memset(&conf, 0, sizeof(conf));

	while ((c = getopt(argc, argv, "hH:d:xwyzaspPe:v")) != -1) {
		switch(c) {
			case 'H':
				conf.hdr_len = atoi(optarg);
				break;
			case 'h':
				printf("Usage:\n"
						"  gttlvdump [-h] [options] tlvfile\n"
						"    -h       This help message.\n"
						"    -H <num> Constant header length.\n"
						"    -d <num> Max depth of nested elements.\n"
						"    -x       Display file offset for every TLV.\n"
						"    -w       Wrap the output.\n"
						"    -y       Show content length.\n"
						"    -z       Convert payload with length les than 8 bytes to decimal.\n"
						"    -a       Annotate known KSI elements.\n"
						"    -s       Strict types - do not parse TLV's with unknown types.\n"
						"    -p       Pretty print values.\n"
						"    -P       Pretty print keys.\n"
						"    -e <enc> Encoding of binary payload. Available encodings: 'hex' (default),\n"
						"             'base64'.\n"
						"    -v       TLV utility package version.\n"
				);
				res = GT_OK;
				goto cleanup;
			case 'd':
				conf.max_depth = atoi(optarg);
				break;
			case 'x':
				conf.print_off = true;
				break;
			case 'w':
				conf.wrap = true;
				break;
			case 'y':
				conf.print_len = true;
				break;
			case 'z':
				conf.convert = true;
				break;
			case 'a':
				conf.use_desc = true;
				break;
			case 's':
				conf.type_strict = true;
				break;
			case 'p':
				conf.pretty_val = true;
				break;
			case 'P':
				conf.pretty_key = true;
				break;
			case 'e': {
				struct {
					const char *alias;
					enum out_enc_en enc;
				} enc_map[] = {
					{"hex", ENCODE_HEX },
					{"base16", ENCODE_HEX },
					{"16", ENCODE_HEX },
					{"base64", ENCODE_BASE64 },
					{"64", ENCODE_BASE64 },
					{ NULL, 0 }
				};
				size_t i = 0;
				while (enc_map[i].alias != NULL) {
					if (!strcmp(enc_map[i].alias, optarg)) {
						conf.out_enc = enc_map[i].enc;
						break;
					}
					++i;
				}
				if (enc_map[i].alias == NULL) {
					fprintf(stderr, "Unknown encoding '%s', defaulting to 'hex'.\n", optarg);
					conf.out_enc = ENCODE_HEX;
				}
				break;
			}
			case 'v':
				printf("%s\n", TLV_UTIL_VERSION_STRING);
				res = GT_OK;
				goto cleanup;
				break;
			default:
				fprintf(stderr, "Unknown parameter, try -h.");
				goto cleanup;
		}
	}

	/* Initialize the description structure. */
	res = read_desc_dir(&conf.desc, getDescriptionFileDir());
	if (res != GT_OK) {
		fprintf(stderr, "Unable to read description directory '%s'.\n", getDescriptionFileDir());
	} else {
		desc_free = true;
	}

	/* If there are no input files, read from the standard in. */
	if (optind >= argc) {
#ifdef _WIN32
		_setmode(_fileno(stdin), _O_TEXT);
#endif
		res = read_from(stdin, &conf);
		if (res != GT_OK) goto cleanup;
	} else {
		int i;

		/* Loop over all the inputfiles. */
		for (i = 0; optind + i < argc; i++) {
			conf.file_name = argv[optind + i];

			input = fopen(conf.file_name, "rb");
			if (input == NULL) {
				fprintf(stderr, "%s: Unable to open file.\n", argv[optind + i]);
				continue;
			}

			res = read_from(input, &conf);
			fclose(input);
			input = NULL;
			if (res != GT_OK) goto cleanup;
		}
	}

cleanup:

	if (input != NULL) fclose(input);
	if (desc_free) desc_cleanup(&conf.desc);


	return 0;
}
