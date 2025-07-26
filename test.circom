pragma circom 2.1.3;

include "helpers/jwtchecks.circom";
include "helpers/hasher.circom";
include "./merkleTree.circom";

template checkAud(maxPaddedUnsignedJWTLen, maxAudValueLen, maxWhiteSpaceLen) {
    var inCount = maxPaddedUnsignedJWTLen;

    signal input padded_unsigned_jwt[inCount];
    signal input payload_start_index;

    // iss是可以公开的，直接把处理后的iss用input传入并公开
    // 假设iss字符串最大长度为32，我没有调研过jwt标准中最大长度是多少
    // iss的每16字节转换为一个int
    // signal input iss[2];

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


    // signal input path[4];

    // signal hash_id;
    // hash_id <== Hasher(3)([sub, aud, iss]);

    // signal addr <== MerkleTree()(hash_id, path);
}

// component main {public [iss]} = checkAud(1600, 145);\
component main = checkAud(1600, 145, 6);