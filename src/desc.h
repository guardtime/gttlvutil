#ifndef DESC_H_
#define DESC_H_

enum {
	TLV_COMPOSITE,
	TLV_INT,
	TLV_RAW,
	TLV_STR,
	TLV_TIME,
	TLV_IMPRINT	
};

/**
 * Container for nested structure descriptions.
 */
struct desc_st {
	/** Textual value. */
	char *val;

	/** Key value */
	unsigned key;

	/** Type of the tlv. */
	int type;

	/** Sparse table of pointers. */
	struct desc_st *map[0xff];
};


/**
 * Initialize the description with the contents of the file.
 */
int desc_init(struct desc_st *desc, const char *descFile);

/**
 * Find the given key in the description.
 */
int desc_find(struct desc_st *in, unsigned tag, struct desc_st **out);

/**
 * Pefrorms a cleanup of the object, but won't free it.
 */	
void desc_cleanup(struct desc_st *desc);
	
#endif