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

template Dugtrio(maxPaddedUnsignedJWTLen, maxIssLen_b64) {

    var inWidth = 8; // input is in bytes
    var inCount = maxPaddedUnsignedJWTLen;

    signal input padded_unsigned_jwt[inCount];

    // 1. SHA256 over padded_unsigned_jwt
    signal input num_sha2_blocks;
    signal input sha2pad_index;
    var padded_unsigned_jwt_len = 64 * num_sha2_blocks; // 64 bytes per SHA2 block

    // Check the validity of the SHA2 padding
    SHA2PadVerifier(inCount)(padded_unsigned_jwt, padded_unsigned_jwt_len, sha2pad_index);

    var hashCount = 4;
    var hashWidth = 64; // 256 / hashCount
    // Calculates the SHA2 hash of an arbitrarily shaped input using SHA256_varlen
    signal output jwt_sha2_hash[hashCount] <== Sha2_wrapper(inWidth, inCount, hashWidth, hashCount)(padded_unsigned_jwt, num_sha2_blocks);

    // 2. Extract the iss field from the JWT in base64 format
    signal input iss_index_b64;
    signal input iss_length_b64;
    signal output iss_b64[maxIssLen_b64] <== SliceEfficient(inCount, maxIssLen_b64)(padded_unsigned_jwt, iss_index_b64, iss_length_b64);
}