#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include "tlvdump.h"
#include "fast_tlv.h"
#include "desc.h"
#include "common.h"
#include "dir.h"


#define INDENT_LEN 2

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
};

static char *hash_alg[] = {
	"sha-1", "sha2-256", "ripemd-160", "sha2-224", "sha2-384", "sha2-512", "ripemd-256", "sha3-224", "sha3-256", "sha3-512", "sm3"
};



static const char *path_removeFile(const char *origPath, char *buf, size_t buf_len) {
	char *beginingOfFile = NULL;
	size_t path_len;
	char *ret = NULL;

#ifdef _WIN32
	beginingOfFile = strrchr(origPath, '\\');
	if (beginingOfFile == NULL) {
		beginingOfFile = strrchr(origPath, '/');
	}
#else
	beginingOfFile = strrchr(origPath, '/');
#endif

	if (beginingOfFile ==  NULL) {
		buf[0] = '\0';
		return buf;
	}

	path_len = beginingOfFile - origPath;
	if (path_len + 1 > buf_len) return NULL;

	ret = strncpy(buf, origPath, path_len + 1);
	buf[path_len + 1] = 0;
	return  ret;
}

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


static void print_raw_data(unsigned char *buf, size_t len, size_t prefix_len, struct conf_st *conf) {
	size_t i;

	for (i = 0; i < len; i++) {
		if (conf->wrap &&  i > 0 && i % 64 == 0 ) {
			printf("\n%*s", prefix_len, "");
		}
		printf("%02x", buf[i]);
	}

	if (conf->convert && len <= 8) {
		size_t val = 0;
		printf(" (dec = %llu)", (unsigned long long)get_uint64(buf, len));
	}
	putchar('\n');
}

static int get_payload_type(unsigned char *buf, size_t buf_len, struct conf_st *conf, struct desc_st *desc) {
	int res = KSI_UNKNOWN_ERROR;
	int type = TLV_RAW;
	size_t len = buf_len;
	unsigned char *ptr = buf;

	if (desc != NULL) {
		type = desc->type;
		goto cleanup;
	}

	res = KSI_FTLV_memReadN(ptr, len, NULL, 0, NULL);
	if (res != KSI_OK) goto cleanup;

	if (conf->type_strict) {
		while (len > 0) {
			KSI_FTLV n;
			struct desc_st *d = NULL;

			res = KSI_FTLV_memRead(ptr, len, &n);
			if (res != KSI_OK) goto cleanup;

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

static void print_int(unsigned char *buf, size_t len, size_t prefix_len, struct conf_st *conf) {

	if (len > 8) {
		printf("0x");
		print_raw_data(buf, len, prefix_len, conf);
	} else {
		printf("%llu\n", get_uint64(buf, len));
	}
}

static void print_str(unsigned char *buf, size_t len, size_t prefix_len, struct conf_st *conf) {
	size_t i;
	putchar('"');
	for (i = 0; i < len; i++) {
		if (isprint(buf[i])) putchar(buf[i]);
		else printf("\\%u", buf[i]);
	}
	putchar('"');
	putchar('\n');
}

static void print_imprint(unsigned char *buf, size_t len, size_t prefix_len, struct conf_st *conf) {
	if (len > 0) {
		if (buf[0] < sizeof(hash_alg) / sizeof(char *)) {
			printf("%s:", hash_alg[buf[0]]);
			print_raw_data(buf + 1, len - 1, prefix_len, conf);
		} else {
			print_raw_data(buf, len, prefix_len, conf);
		}
	}
}

static void print_time(unsigned char *buf, size_t len, size_t prefix_len, int type, struct conf_st *conf) {
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

		switch (type) {
			case TLV_MTIME:
				seconds = (time_t) t / 1000;
				snprintf(fract, sizeof(fract), "%03u", t % 1000);
				break;
			case TLV_UTIME:
				seconds = (time_t) t / 1000 / 1000;
				snprintf(fract, sizeof(fract), "%06u", t % (1000 * 1000));
				break;
			case TLV_TIME:
			default:
				seconds = (time_t) t;
				break;
		}

		tm_info = gmtime(&seconds);
		len = strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", tm_info);
		if (fract[0] != '\0') {
			len += snprintf(tmp + len, sizeof(tmp) - len, ".%s", fract);
		}

		strftime(tmp + len, sizeof(tmp) - len, " %Z", tm_info);

		printf("(%llu) %s\n", t, tmp);
	}
}


static void printTlv(unsigned char *buf, size_t buf_len, KSI_FTLV *t, int level, struct conf_st *conf, struct desc_st *desc) {
	unsigned char *ptr = buf + t->hdr_len;
	size_t len = t->dat_len;
	size_t prefix_len = 0;
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

	/* Print only the indent. */
	prefix_len += printf("%*s", level * INDENT_LEN, "");

	if (t->tag > 32 || t->dat_len > 255) {
		prefix_len += printf("TLV[%04x%s%s]:", t->tag, (t->is_fwd ? ",F" : ""), (t->is_nc ? ",N" : ""));
	} else {
		prefix_len += printf("TLV[%02x%s%s]: ", t->tag, (t->is_fwd ? ",F" : ""), (t->is_nc ? ",N" : ""));
	}

	if (conf->print_len) {
		prefix_len += printf("(L = %llu) ", (unsigned long long)t->dat_len);
	}

	if (conf->pretty_key && desc != NULL && desc->val != NULL && *desc->val) {
		prefix_len += printf("%s: ", desc->val);
	}

	limited = conf->max_depth != 0 && level + 1 >= conf->max_depth;

	type = get_payload_type(ptr, len, conf, desc);

	if (type == TLV_COMPOSITE && !limited) {
		size_t off = t->off + t->hdr_len;
		KSI_FTLV n;

		putchar('\n');
		while (len > 0) {
			size_t consumed;
			KSI_FTLV_memRead(ptr, len, &n);
			n.off = off;

			desc_find(desc, n.tag, &sub);

			consumed = n.hdr_len + n.dat_len;

			printTlv(ptr, consumed, &n, level + 1, conf, sub);

			off += consumed;

			ptr += consumed;
			len -= consumed;
		}
	} else if (type != TLV_RAW && conf->pretty_val && !limited) {
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
	char *header = NULL;
	KSI_FTLV t;
	unsigned char buf[0xffff + 4];
	size_t len;
	size_t off = 0;

	if (conf->hdr_len > 0) {
		header = calloc(conf->hdr_len, 1);
		if (header == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}
		if (fread(header, conf->hdr_len, 1, f) != 1) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}

		for (len = 0; len < conf->hdr_len; len++) {
			printf("%02x", header[len]);
		}
		printf("\n");
	}

	while (1) {
		res = KSI_FTLV_fileRead(f, buf, sizeof(buf), &len, &t);
		if (res != KSI_OK) {
			if (len == 0) break;
			fprintf(stderr, "%s: Failed to parse %llu bytes\n", conf->file_name, (unsigned long long) len);
			break;
		}

		t.off = off;

		printTlv(buf, len, &t, 0, conf, NULL);
		off += len;
	}

	res = KSI_OK;

cleanup:

	if (header != NULL) free(header);

	return res;
}

static int read_desc_dir(struct desc_st *desc, const char *dir_name) {
	int res = KSI_UNKNOWN_ERROR;
	DIRECTORY *dir = NULL;
	ENTITY *ent;

	memset(desc, 0, sizeof(struct desc_st));

	if (DIRECTORY_open(dir_name, &dir) != DIR_OK) {
		fprintf(stderr, "%s:Unable to access description directory.\n", dir_name);
		res = KSI_OK;
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
			if (res != KSI_OK) {
				fprintf(stderr, "%s/%s: Unable to read description file\n", dir_name, name);
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
	if (path_removeFile(argv[0], buf, sizeof(buf)) == NULL) {
		fprintf(stderr, "Unable to set description file dir.\n");
	}

	setDescriptionFileDir(buf);
#endif

	memset(&conf, 0, sizeof(conf));

	while ((c = getopt(argc, argv, "hH:d:xwyzaspP")) != -1) {
		switch(c) {
			case 'H':
				conf.hdr_len = atoi(optarg);
				break;
			case 'h':
				printf("Usage:\n"
						"  gttlvdump [-h] [options] tlvfile\n"
						"    -h       This help message\n"
						"    -H num   Constant header lenght.\n"
						"    -d num   Max depth of nested elements\n"
						"    -x       Display file offset for every TLV\n"
						"    -w       Wrap the output.\n"
						"    -y       Show content length.\n"
						"    -z       Convert payload with length les than 8 bytes to decimal.\n"
						"    -a       Annotate known KSI elements.\n"
						"    -s       Strict types - do not parse TLV's with unknown types.\n"
						"    -p       Pretty print values.\n"
						"    -P       Pretty print keys.\n"
				);
				res = KSI_OK;
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
			default:
				fprintf(stderr, "Unknown parameter, try -h.");
				goto cleanup;
		}
	}

	/* Initialize the description structure. */
	res = read_desc_dir(&conf.desc, getDescriptionFileDir());
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to read description directory '%s'.\n", getDescriptionFileDir());
	} else {
		desc_free = true;
	}

	/* If there are no input files, read from the standard in. */
	if (optind >= argc) {
		res = read_from(stdin, &conf);
		if (res != KSI_OK) goto cleanup;
	} else {
		size_t i;

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
			if (res != KSI_OK) goto cleanup;
		}
	}

cleanup:

	if (input != NULL) fclose(input);
	if (desc_free) desc_cleanup(&conf.desc);


	return 0;
}
