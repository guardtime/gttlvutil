var fs = require('fs');

var createTlv = function(dat) {
	var buf = null;
	var tag = "tag" in dat ? parseInt(dat.tag): 0;

	if (tag < 0 || tag > 0x03ff) {
		throw "Invalid tag: " + dat.tag;
	}

	if ("nested" in dat) {
		var nested = [];
		for (var i = 0; i < dat.nested.length; i++) {
			nested.push(createTlv(dat.nested[i]));
		}
		buf = Buffer.concat(nested);
	} else if ("strVal" in dat) {
		buf = new Buffer(dat.strVal, "utf8");
	} else if ("hexVal" in dat) {
		buf = new Buffer(dat.hexVal, "hex");
	} else {
		throw "Unable to serialize TLV";
	}

	/* Create header */
	var hdr = new Buffer([0, 0]);
	if (dat.lenient) hdr[0] |= 0x40;
	if (dat.forward) hdr[0] |= 0x02;
	
	if (tag > 0x3f || buf.length > 0xff) {
		hdr = Buffer.concat([hdr, new Buffer([0, 0])]);
		hdr[0] |= 0x80;
		hdr[0] |= (tag >> 8) & 0x3f;
		hdr[1] = tag & 0xff;
		hdr[2] = buf.length >> 8;
		hdr[3] = buf.length & 0xff;
	} else {
		hdr[0] |= tag & 0x3f;
		hdr[1] = buf.length & 0xff;	
	}

	return Buffer.concat([hdr,buf]);
		 
}

var processFile = function(fnam) {
	try {
		var inp = fs.readFileSync(fnam);
	} catch (e) {
		console.error("Unable to open file " + fnam);
		return;
	}
	try {
		var dat = JSON.parse(inp);
	} catch (e) {
		console.error("Invalid JSON format");
		return;
	}
	try {
		var buf = createTlv(dat);
	} catch (e) {
		console.error("Unable to create TLV object");
		return;
	}
	try {
		var outFnam = fnam + ".tlv";
		fs.writeFileSync(outFnam, buf);
		console.log("Wrote " + outFnam + ".");
	} catch (e) {
		console.error("Unable to write TLV file");
		return;
	}
}	

if (process.argv.length != 3) {
	console.log("Usage:\n  " + process.argv[0] + " " + process.argv[1] + " [json-file]\n");
	return 1;
}

processFile(process.argv[2]);

