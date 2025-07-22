# input格式

## 参数
* maxHeaderLen = 248
* maxPaddedUnsignedJWTLen = 64 * 25; 1600
* maxKCNameLen = 32
* maxKCValueLen = 115
* maxExtKCLen = 126
* maxAudValueLen = 145
* maxWhiteSpaceLen = 6
* maxExtIssLength = 165

## input.json

### padded_unsigned_jwt
类型：长度为maxPaddedUnsignedJWTLen的byte数组
内容：header || '.' || payload || sha2pad || zeroes (optional)
计算方式：先把jwt切出header || '.' || payload，然后对其进行SHA256 padding，最后添加全0字节补齐到maxPaddedUnsignedJWTLen长度。

### payload_start_index
类型：int
内容：payload的起始位置
计算方式：从padded_unsigned_jwt中找到'.'的索引位置，返回该位置加1。

