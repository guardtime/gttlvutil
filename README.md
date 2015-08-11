# gttlvdump

## Help

	gttlvdump [-h] [options] tlvfile
		-h       This help message
		-H num   Constant header lenght.
		-d num   Max depth of nested elements
		-x       Display file offset for every TLV
		-w       Wrap the output.
		-y       Show content length.
		-z       Convert payload with length les than 8 bytes to decimal.
		-a       Annotate known KSI elements.
		-s       Strict types - do not parse TLV's with unknown types.
		-p       Pretty print values.
		-P       Pretty print keys.

## Useful commands

	* Dump publications file
		gttlvdump -H 8 publicationsfile
    * Dump tlv in hex format
        echo "tlvhex" | xxd -r -p | gttlvdump