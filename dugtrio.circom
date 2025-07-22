pragma circom 2.1.3;

include "helpers/sha256.circom";
include "helpers/misc.circom";
include "helpers/strings.circom";
include "helpers/hasher.circom";
include "helpers/jwtchecks.circom";
include "helpers/rsa/rsa.circom";

/*
input:
    - padded_unsigned_jwt[inCount]: X in bytes where X is the padded unsigned JWT + zeroes
    - payload_start_index:      The index of the first byte of the payload in the padded unsigned JWT
*/

template Dugtrio(maxHeaderLen, maxPaddedUnsignedJWTLen) {

    var inCount = maxPaddedUnsignedJWTLen;

    // 1. parse out the JWT header
    signal input padded_unsigned_jwt[inCount];
    signal input payload_start_index;

    // Extract the header
    var header_length = payload_start_index - 1;
    signal header[maxHeaderLen] <== SliceFromStart(inCount, maxHeaderLen)(
        padded_unsigned_jwt, header_length
    );

    // Hash value of header
    // signal header_F <== HashBytesToField(maxHeaderLen)(header);

    // Check that there is a dot after header
    var dot = SingleMultiplexer(inCount)(padded_unsigned_jwt, header_length);
    dot === 46; // 46 is the ASCII code for '.'

    // 2. SHA2 operations over padded_unsigned_jwt
}