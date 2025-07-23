# 输入输出格式

## 参数
* maxPaddedUnsignedJWTLen = 64 * 25; 1600
* maxIssLen_b64 = 224



## input.json

### padded_unsigned_jwt
类型：长度为maxPaddedUnsignedJWTLen的byte数组
内容：header || '.' || payload || sha2pad || zeroes (optional)
计算方式：先把jwt切出header || '.' || payload，然后对其进行SHA256 padding，最后添加全0字节补齐到maxPaddedUnsignedJWTLen长度。

### num_sha2_blocks
类型：int
内容：padded_unsigned_jwt的SHA256 block数量
计算方式：末尾填充全0字节前的padded_unsigned_jwt的长度除以64。

### sha2pad_index
类型：int
内容：padded_unsigned_jwt中SHA256 padding的起始位置
计算方式：payload结束的位置

### iss_index_b64
类型：int
内容：padded_unsigned_jwt中iss字段在base64编码后的起始位置

### iss_length_b64
类型：int
内容：padded_unsigned_jwt中iss字段在base64编码后的长度

## public.json

### jwt_sha2_hash
类型：长度为4的数组
内容：unsigned_jwt的SHA256哈希值

### iss_b64
类型：长度为maxIssLen_b64的byte数组
内容：padded_unsigned_jwt中iss字段的base64编码，末尾填充全0字节补齐到maxIssLen_b64长度。