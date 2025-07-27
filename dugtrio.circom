pragma circom 2.1.3;

include "helpers/sha256.circom";
include "helpers/misc.circom";
include "helpers/strings.circom";
include "helpers/hasher.circom";
include "helpers/jwtchecks.circom";
include "helpers/rsa/rsa.circom";
include "./merkleTree.circom";

/*
input:
    - padded_unsigned_jwt[inCount]: X in bytes where X is the padded unsigned JWT + zeroes
    - payload_start_index:      The index of the first byte of the payload in the padded unsigned JWT
*/

template Dugtrio(maxPaddedUnsignedJWTLen, maxIssLen_b64, maxAudValueLen, maxSubValueLen, maxWhiteSpaceLen) {

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

    // 3. id in merkle tree
    signal input payload_start_index;

    // iss是可以公开的，直接把处理后的iss用input传入并公开
    // 假设iss字符串最大长度为32，我没有调研过jwt标准中最大长度是多少
    // iss的每16字节转换为一个int
    signal input iss[2];

    // aud
    var aud_name_length = 3 + 2; // 5, "aud"
    var maxAudValueLenWithQuotes = maxAudValueLen + 2; // 147, 2 for quotes
    // 1 for colon, 1 for comma / brace
    var maxExtAudLength = aud_name_length + maxAudValueLenWithQuotes + 2 + maxWhiteSpaceLen; // 160

    signal input aud[maxExtAudLength];
    signal input aud_length;
    signal input aud_index_b64;
    signal input aud_length_b64;
    signal input aud_colon_index;
    signal input aud_value_index;
    signal input aud_value_length; // with quotes
    signal aud_name_with_quotes[aud_name_length];
    signal aud_value_with_quotes[maxAudValueLenWithQuotes];

    component AudExtClaim = ExtClaimOps(
        inCount, maxExtAudLength, aud_name_length, maxAudValueLenWithQuotes, maxWhiteSpaceLen
    );
    AudExtClaim.content <== padded_unsigned_jwt;
    AudExtClaim.index_b64 <== aud_index_b64;
    AudExtClaim.length_b64 <== aud_length_b64;
    AudExtClaim.ext_claim <== aud;
    AudExtClaim.ext_claim_length <== aud_length;
    AudExtClaim.name_length <== aud_name_length;
    AudExtClaim.colon_index <== aud_colon_index;
    AudExtClaim.value_index <== aud_value_index;
    AudExtClaim.value_length <== aud_value_length;
    AudExtClaim.payload_start_index <== payload_start_index;

    aud_name_with_quotes <== AudExtClaim.claim_name;
    aud_value_with_quotes <== AudExtClaim.claim_value;

    // Check if aud_name_with_quotes == "aud"
    var expected_aud_name[aud_name_length] = [34, 97, 117, 100, 34];
    for (var i = 0; i < aud_name_length; i++) {
        aud_name_with_quotes[i] === expected_aud_name[i];
    }

    // HashBytesToField for later use
    signal aud_value[maxAudValueLen] <== QuoteRemover(maxAudValueLen + 2)(
        aud_value_with_quotes, aud_value_length
    );
    signal aud_value_F <== HashBytesToField(maxAudValueLen)(aud_value);

    // sub
    var sub_name_length = 3 + 2; // 5, "sub"
    var maxSubValueLenWithQuotes = maxSubValueLen + 2; // 147, 2 for quotes
    // 1 for colon, 1 for comma / brace
    var maxExtSubLength = sub_name_length + maxSubValueLenWithQuotes + 2 + maxWhiteSpaceLen; // 160

    signal input sub[maxExtSubLength];
    signal input sub_length;
    signal input sub_index_b64;
    signal input sub_length_b64;
    signal input sub_colon_index;
    signal input sub_value_index;
    signal input sub_value_length; // with quotes
    signal sub_name_with_quotes[sub_name_length];
    signal sub_value_with_quotes[maxSubValueLenWithQuotes];

    component SubExtClaim = ExtClaimOps(
        inCount, maxExtSubLength, sub_name_length, maxSubValueLenWithQuotes, maxWhiteSpaceLen
    );
    SubExtClaim.content <== padded_unsigned_jwt;
    SubExtClaim.index_b64 <== sub_index_b64;
    SubExtClaim.length_b64 <== sub_length_b64;
    SubExtClaim.ext_claim <== sub;
    SubExtClaim.ext_claim_length <== sub_length;
    SubExtClaim.name_length <== sub_name_length;
    SubExtClaim.colon_index <== sub_colon_index;
    SubExtClaim.value_index <== sub_value_index;
    SubExtClaim.value_length <== sub_value_length;
    SubExtClaim.payload_start_index <== payload_start_index;

    sub_name_with_quotes <== SubExtClaim.claim_name;
    sub_value_with_quotes <== SubExtClaim.claim_value;

    // Check if sub_name_with_quotes == "sub"
    var expected_sub_name[sub_name_length] = [34, 115, 117, 98, 34];
    for (var i = 0; i < sub_name_length; i++) {
        sub_name_with_quotes[i] === expected_sub_name[i];
    }

    // HashBytesToField for later use
    signal sub_value[maxSubValueLen] <== QuoteRemover(maxSubValueLen + 2)(
        sub_value_with_quotes, sub_value_length
    );
    signal sub_value_F <== HashBytesToField(maxSubValueLen)(sub_value);

    // calculate hash_id
    signal hash_id <== Hasher(4)([sub_value_F, aud_value_F, iss[0], iss[1]]);

    // check hash_id is in Merkle Tree
    // calculate Merkle Tree root with hash_id and path
    signal input path[4];
    signal output addr <== MerkleTree()(hash_id, path);
}