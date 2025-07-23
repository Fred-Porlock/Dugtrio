pragma circom 2.1.3;

include "dugtrio.circom";

// maxHeaderLen = 248
// maxPaddedUnsignedJWTLen = 64 * 25; // 1600
// maxKCNameLen = 32
// maxKCValueLen = 115
// maxExtKCLen = 126
// maxAudValueLen = 145
// maxWhiteSpaceLen = 6
// maxExtIssLength = 165
component main = Dugtrio(64 * 25, 224);