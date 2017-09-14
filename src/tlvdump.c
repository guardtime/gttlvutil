#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#ifdef _WIN32
#	include <io.h>
#	include <fcntl.h>
#endif

#include "common.h"
#include "fast_tlv.h"
#include "desc.h"
#include "dir.h"
#include "file_io.h"


#define INDENT_LEN 2
#define DEFAULT_WRAP 32
#define PATH_SIZE 2048

struct conf_st {
	const char *file_name;
	bool auto_hdr;
	size_t hdr_len;
	size_t max_depth;
	bool print_off;
	bool wrap;
	size_t wrap_width;
	bool print_len;
	bool convert;
	bool use_desc;
	bool type_strict;
	bool pretty_val;
	bool pretty_key;
	bool timezone;
	struct desc_st desc;
	GT_Encoding out_enc;
	GT_Encoding in_enc;
	long (*consume_stream)(unsigned char **buf, size_t consumed, FILE *file);
};

static char *hash_alg[] = {
	"sha-1", "sha2-256", "ripemd-160", "sha2-224", "sha2-384", "sha2-512", "ripemd-256", "sha3-224", "sha3-256", "sha3-512", "sm3"
};

static char descriptionDir[PATH_SIZE];

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

	GT_strncpy(descriptionDir, dir, sizeof(descriptionDir));
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


#define wrap_offset(l)	printf("\n%*s", (l), "")
#define wrap_line(p)                                   \
	if (conf->wrap_width && line_len > 0 &&            \
			line_len % (conf->wrap_width * 2) == 0 ) { \
		wrap_offset(prefix_len);                       \
		line_len = 0;                                  \
	}                                                  \
	line_len += p


static void print_hex(unsigned char *buf, size_t len, int prefix_len, bool enable_convert, struct conf_st *conf) {
	size_t i;
	size_t line_len = 0;

	for (i = 0; i < len; i++) {
		wrap_line(printf("%02x", buf[i]));
	}

	if (enable_convert && conf->convert && len <= 8) {
		printf(" (dec = %llu)", (unsigned long long) get_uint64(buf, len));
	}
	putchar('\n');
}

static void print_base64(unsigned char *buf, size_t len, int prefix_len, bool enable_convert, struct conf_st *conf) {
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

	if (enable_convert && conf->convert && len <= 8) {
		printf(" (dec = %llu)", (unsigned long long)get_uint64(buf, len));
	}
	putchar('\n');
}

static void print_raw_data(unsigned char *buf, size_t len, int prefix_len, bool enable_convert, struct conf_st *conf) {
	switch (conf->out_enc) {
		case GT_BASE_64:
			print_base64(buf, len, prefix_len, enable_convert, conf);
			break;
		case GT_BASE_16:
		default:
			print_hex(buf, len, prefix_len, enable_convert, conf);
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
				type = TLV_UNKNOWN;
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
			if (res == GT_OK && len < n.hdr_len + n.dat_len) {
				res = GT_INVALID_FORMAT;
			}
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
		print_raw_data(buf, len, prefix_len, true, conf);
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
		if (conf->pretty_val) {
			if (buf[0] < sizeof(hash_alg) / sizeof(char *)) {
				printf("%s:", hash_alg[buf[0]]);
			} else {
				printf("%02x:", buf[0]);
			}
			if (conf->wrap_width) {
				wrap_offset(prefix_len);
			}
			print_raw_data(buf + 1, len - 1, prefix_len, true, conf);
		} else if (conf->wrap_width && conf->out_enc == GT_BASE_16) {
			printf("%02x", buf[0]);
			wrap_offset(prefix_len);
			print_raw_data(buf + 1, len - 1, prefix_len, true, conf);
		} else {
			print_raw_data(buf, len, prefix_len, true, conf);
		}
	}
}

static void print_time(unsigned char *buf, size_t len, int prefix_len, int type, struct conf_st *conf) {
	if (len > 8) {
		print_raw_data(buf, len, prefix_len, true, conf);
	} else {
		char fract[0x1f];
		struct tm *tm_info;
		uint64_t t = get_uint64(buf, len);
		time_t seconds;
		size_t len;

		fract[0] = '\0';

		switch (type) {
			case TLV_MTIME:
				seconds = (time_t) t / 1000;
				GT_snprintf(fract, sizeof(fract), "%03llu", (unsigned long long)(t % 1000));
				break;
			case TLV_UTIME:
				seconds = (time_t) t / 1000 / 1000;
				GT_snprintf(fract, sizeof(fract), "%06llu", (unsigned long long)(t % (1000 * 1000)));
				break;
			case TLV_TIME:
			default:
				seconds = (time_t) t;
				break;
		}

		if (seconds >= 0xffffffff) {
			printf("%llu\n", (unsigned long long)t);
		} else {
			char tmp[0xff];
			tmp[0] = '\0';
			tm_info = (conf->timezone) ? localtime(&seconds) : gmtime(&seconds);
			len = strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", tm_info);
			if (fract[0] != '\0') {
				len += GT_snprintf(tmp + len, sizeof(tmp) - len, ".%s", fract);
			}

			if (conf->timezone) {
				strftime(tmp + len, sizeof(tmp) - len, " %Z", tm_info);
			} else {
				GT_snprintf(tmp + len, sizeof(tmp) - len, " UTC+00");
			}
			printf("(%llu) %s\n", (unsigned long long)t, tmp);
		}
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
	if (!limited && type == TLV_UNKNOWN && len != 0) {
		printf("%*s### NOT PARSEABLE TLV ###\n", level * INDENT_LEN, "");
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
	} else if (type != TLV_RAW && type != TLV_UNKNOWN && conf->pretty_val && !limited) {
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
		if (type == TLV_IMPRINT && conf->wrap_width) {
			print_imprint(ptr, len, prefix_len, conf);
		} else {
			print_raw_data(ptr, len, prefix_len, true, conf);
		}
	}
}

static int read_from(FILE *f, struct conf_st *conf) {
	int res;
	GT_FTLV t;
	size_t len = 0;
	size_t off = 0;
	size_t global_off = 0;
	struct file_magic_st *pMagic = NULL;
	size_t hdr_len = 0;
	unsigned char *ptr = NULL;
	long read_len;

	read_len = conf->consume_stream(&ptr, 0, f);
	if (read_len < 0 || (read_len == 0 && !feof(f))) {
		res = GT_IO_ERROR;
		goto cleanup;
	}
	len = read_len;

	if (conf->auto_hdr) {
		size_t i;
		for (i = 0; i < conf->desc.magics_len; i++) {
			size_t hdr_len = conf->desc.magics[i].len;
			if (hdr_len < len && !memcmp(conf->desc.magics[i].val, ptr, hdr_len)) {
				pMagic = conf->desc.magics + i;
				break;
			}
		}
	}

	hdr_len = pMagic != NULL ? pMagic->len : conf->hdr_len;

	if (hdr_len > 0) {
		if (conf->pretty_key && pMagic != NULL) {
			printf("%s: ", pMagic->desc);
		}
		print_raw_data(ptr, hdr_len, 0, false, conf);

		len -= hdr_len;
		off += hdr_len;
	}

	while (len > off) {
		size_t consumed;

		/* Try to read the next TLV. */
		res = GT_FTLV_memRead(ptr + off, len - off, &t);
		consumed = t.hdr_len + t.dat_len;
		t.off = global_off + off;

		if ((len - off < 2 && off != 0) || (res == GT_OK && consumed > len - off && off != 0)) {
			/* We have reached the end of the buffer, we need to shift. */
			read_len = conf->consume_stream(&ptr, off, f);
			if (read_len < 0 || (read_len == 0 && !feof(f))) {
				res = GT_IO_ERROR;
				goto cleanup;
			}
			len = read_len;
			global_off += off;
			off = 0;

			continue;
		}

		if (res != GT_OK) {
			if (consumed == 0) {
				if (feof(f)) break;
				continue;
			}
			print_error("%s: Failed to parse %llu bytes.\n", conf->file_name, (unsigned long long) len - off);
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}

		printTlv(ptr + off, len - off, &t, 0, conf, NULL);
		off += consumed;
	}

	res = GT_OK;

cleanup:

	return res;
}

static int read_desc_dir(struct desc_st *desc, const char *dir_name, bool override) {
	int res = GT_UNKNOWN_ERROR;
	DIRECTORY *dir = NULL;
	ENTITY *ent;

	if (DIRECTORY_open(dir_name, &dir) != DIR_OK) {
		print_error("%s:Unable to access description directory.\n", dir_name);
		res = GT_IO_ERROR;
		goto cleanup;
	}

	while (DIRECTORY_getNextEntity(dir, &ent) == DIR_OK) {
		size_t len;
		const char *name = NULL;
		if(ENTITY_getType(ent) == DIR_DIR) continue;
		name = ENTITY_getName(ent);
		len = strlen(name);

		if (len > 5 && !strcmp(name + len - 5, ".desc")) {
			char buf[PATH_SIZE];

			GT_snprintf(buf, sizeof(buf), "%s/%s", dir_name, name);

			res = desc_add_file(desc, buf, override);
			if (res != GT_OK) {
				print_error("%s/%s: Unable to read description file.\n", dir_name, name);
			}
		}
	}

cleanup:

	DIRECTORY_close(dir);

	return res;
}

static void initDefaultDescriptionFileDir(char *arg0) {
	bool set = false;

	if (strlen(DATA_DIR)) {
		setDescriptionFileDir(DATA_DIR);
		set = true;
	}

	/* If the description files have not been found in package directory,
	 * fallback to the executable dir. */
	if (!set) {
		char buf[PATH_SIZE];

		if (DIRECTORY_getMyPath(buf, sizeof(buf), arg0) != GT_OK) {
			print_error("Unable to get path to gttlvdump.\n");
		}
		setDescriptionFileDir(buf);
	}
}

static int loadDescriptions(struct desc_st *desc, const char *path, bool override) {
	int res = GT_UNKNOWN_ERROR;

	/* Read user description files. */
	res = read_desc_dir(desc, path, override);
	if (res != GT_OK) {
		print_error("Unable to load descriptions from '%s'.\n", path);
	}

	return res;
}

static int getOptionDecValue(char opt, char *arg, size_t *val, char *excstr, size_t excval) {
	int res = GT_INVALID_ARGUMENT;
	char *endptr = NULL;
	long int li = strtol(arg, &endptr, 10);
	size_t tmp = 0;

	if (errno == ERANGE) {
		print_error("Option %c is out of range.\n", opt);
		goto cleanup;
	} else if (li < 0) {
		print_error("Option %c cannot be negative.\n", opt);
		goto cleanup;
	} else if (li == 0 && endptr != NULL && *endptr != '\0') {
		if (excstr && strcmp(endptr, excstr) == 0) {
			tmp = excval;
		} else {
			print_error("Option %c must be a decimal integer.\n", opt);
			goto cleanup;
		}
	} else {
		tmp = (size_t)li;
	}

	*val = tmp;
	res = GT_OK;
cleanup:
	return res;
}

int main(int argc, char **argv) {
	int res = GT_UNKNOWN_ERROR;
	int c;
	FILE *input = NULL;
	struct conf_st conf;
	bool desc_loaded = false;
	char *usr_desc_path = NULL;

	/* Change the output and cache mode. */
	setvbuf(stdout, NULL, _IOFBF, 0xffff);

	memset(&conf, 0, sizeof(conf));

	conf.consume_stream = GT_consume_raw;

	/* Set the auto header value to true. */
	conf.auto_hdr = true;
	/* Set default output encoding. */
	conf.out_enc = GT_BASE_16;

	initDefaultDescriptionFileDir(argv[0]);

	while ((c = getopt(argc, argv, "hH:d:xw:yzaspPte:E:vD:oi")) != -1) {
		switch(c) {
			case 'H': {
				if (!strcmp(optarg, "auto")) {
					conf.auto_hdr = true;
				} else {
					conf.auto_hdr = false;
					res = getOptionDecValue((char)c, optarg, &conf.hdr_len, NULL, 0);
					if (res != GT_OK) goto cleanup;
				}
				break;
			case 'd':
				res = getOptionDecValue((char)c, optarg, &conf.max_depth, NULL, 0);
				if (res != GT_OK) goto cleanup;
				break;
			}
			case 'x':
				conf.print_off = true;
				break;
			case 'w': {
				res = getOptionDecValue((char)c, optarg, &conf.wrap_width, "-", DEFAULT_WRAP);
				if (res != GT_OK) goto cleanup;
				break;
			}
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
			case 't':
				conf.timezone = true;
				break;
			case 'e': {
				conf.out_enc = GT_ParseEncoding(optarg);
				if (conf.out_enc == GT_BASE_NA) {
					print_error("Unknown encoding '%s', defaulting to 'hex'.\n", optarg);
					conf.out_enc = GT_BASE_16;
				}
				break;
			}
			case 'E':
				switch(GT_ParseEncoding(optarg)) {
					case GT_BASE_2:
						conf.consume_stream = GT_consume_raw;
						break;
					case GT_BASE_16:
						conf.consume_stream = GT_consume_hex;
						break;
					case GT_BASE_64:
						conf.consume_stream = GT_consume_b64;
						break;
					default:
						print_error("Unknown input data encoding: '%s'\n", optarg);
						res = GT_INVALID_CMD_PARAM;
						goto cleanup;
				}
				break;
			case 'D':
				usr_desc_path = calloc(PATH_SIZE, sizeof(char));
				if (!usr_desc_path) {
					res = GT_OUT_OF_MEMORY;
					goto cleanup;
				}
				strcpy(usr_desc_path, optarg);
				break;

			case 'h':
				printf("Usage:\n"
						"  gttlvdump [-h] [-v] [options] tlvfile\n"
						"\n"
						"Options:\n"
						"    -h       This help text.\n"
						"    -H int   Ignore specified number of bytes in the beginning of input while\n"
						"             parsing TLV.\n"
						"    -d int   Max depth of nested TLV elements to parse.\n"
						"    -x       Display the TLV offset in bytes.\n"
						"    -w arg   Wrap the output. Specify maximum line length in bytes. Use '-' for\n"
						"             default width (%d bytes).\n"
						"    -y       Show the length of the TLV value in bytes.\n"
						"    -z       Show the decimal value for TLV value less than or equal to 8 bytes.\n"
						"    -s       Strict types - do not parse unknown TLVs elements.\n"
						"    -a       Annotate known TLV elements with their names.\n"
						"    -P       Print known TLV element names.\n"
						"    -p       Format known TLV element values according to the data type (will\n"
						"             override -z).\n"
						"    -t       Print time in local timezone (valid with -p).\n"
						"    -e enc   Output format of binary value. Available: 'hex', 'base64'.\n"
						"    -E enc   Input data encoding. Available: 'bin', 'hex', 'base64'.\n"
						"    -D <pth> Set TLV description files directory.\n"
						"    -v       Print TLV utility version..\n"
						"\n"
						"Default description files directory:\n"
						"  %s\n"
						"\n",
						DEFAULT_WRAP,
						getDescriptionFileDir()
						);
				res = GT_OK;
				goto cleanup;
			case 'v':
				printf("%s\n", TLV_UTIL_VERSION_STRING);
				res = GT_OK;
				goto cleanup;
				break;
			default:
				print_error("Unknown parameter, try -h.\n");
				res = GT_INVALID_CMD_PARAM;
				goto cleanup;
		}
	}

	/* Read descriptions from default files. */
	{
		const char *descDir = NULL;

		if (usr_desc_path != NULL) {
			descDir = usr_desc_path;
		} else {
			descDir = getDescriptionFileDir();
		}

		res = loadDescriptions(&conf.desc, descDir, false);
		if (res != GT_OK) {
			/* As there was an error in loading data, clear all descriptions. */
			desc_cleanup(&conf.desc);
		} else {
			desc_loaded = true;
		}
	}

	/* If there are no input files, read from the standard in. */
	if (optind >= argc) {
		if (conf.in_enc == GT_BASE_2) setBinaryMode(stdin);
		res = read_from(stdin, &conf);
		if (res != GT_OK) goto cleanup;
	} else {
		int i;

		/* Loop over all the input files. */
		for (i = 0; optind + i < argc; i++) {
			conf.file_name = argv[optind + i];

			input = fopen(conf.file_name, "rb");
			if (input == NULL) {
				print_error("%s: Unable to open file.\n", argv[optind + i]);
				res = GT_IO_ERROR;
				goto cleanup;
			}

			res = read_from(input, &conf);
			fclose(input);
			input = NULL;
			if (res != GT_OK) goto cleanup;
		}
	}

cleanup:

	fflush(stdout);

	if (input != NULL) fclose(input);
	if (desc_loaded) desc_cleanup(&conf.desc);
	if (usr_desc_path) free(usr_desc_path);

	return res;
}
