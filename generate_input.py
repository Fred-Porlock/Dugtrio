import json
import base64

# base64url解码，并转换为字符串
def base64url_decode(str):
    # 补充base64末尾的=
    str += '=' * (-len(str) % 4)
    # base64url解码
    str = base64.urlsafe_b64decode(str)
    # 转换为字符串
    str = str.decode('utf-8')
    return str

# SHA256 padding函数
def sha256_padding(message):
    # 将输入字符串转换为字节序列
    data = message.encode('utf-8')

    L = len(data)  # 原始消息字节长度
    bit_length = L * 8  # 原始消息比特长度

    # 1. 添加比特"1"：用字节0x80表示 (10000000)
    padded = bytearray(data)
    padded.append(0x80)

    # 2. 计算需要填充的0字节数量
    # 公式：(L + 1 + k + 8) ≡ 0 (mod 64)
    # 可以简化为：k = (55 - L) % 64
    k = (55 - L) % 64
    if k == 0:
        k = 64

    # 添加k个0x00字节
    padded.extend([0] * k)

    # 3. 添加64位大端序的原始比特长度
    padded.extend(bit_length.to_bytes(8, 'big'))

    return bytes(padded)

# claimName包含引号
def claimOperations(payload, claimName, offset = 0):
    # claim起始位置
    claim_index = payload.index(claimName)
    # claim的结束位置
    claim_value_index_payload = payload.index('"', claim_index + len(claimName))
    quote_index = payload.index('"', claim_value_index_payload + 1)
    comma_index = payload.index(',', claim_value_index_payload + 1)
    # 截取claim，包括claimName和claimValue和逗号
    claim = payload[claim_index : comma_index + 1]
    length = len(claim)
    # 冒号的下标
    colon_index = claim.index(':')
    # claimValue的起始位置
    claim_value_index = claim.index('"', colon_index + 1)
    # 截取claimValue
    claim_value = payload[claim_value_index_payload : quote_index + 1]
    # claimValue的长度
    claim_value_length = len(claim_value)

    # 根据claim起始位置计算base64编码后的payload中的起始位置
    # 注意这里要精确计算。比如“1234”编码了“abc”，“b”的base64的index是1，而不是0，因为“23”包含了“b"的编码；同理，“c”的index是2
    # 这样从中间切割的坏处是不能直接base64解码
    claim_index_b64 = (claim_index % 3) + (claim_index // 3) * 4 + offset
    # 根据claim结束位置计算base64编码后的payload中的结束位置
    # TODO: 可能是对的，我想不清楚了
    claim_end_index_b64 = ((quote_index+1) // 3) * 4 + 2 + ((quote_index+1)%3) + offset
    # base64编码后的claim的长度
    length_b64 = claim_end_index_b64 - claim_index_b64

    return (claim, length, claim_index_b64, length_b64, colon_index, claim_value_index, claim_value_length, claim_value)

jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImI1MDljNTEzODc2OGY3Y2YyZTgyN2UwNGIyN2U3ZTRjYmM3YmI5MTkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTIwMzc1OTAzMjI2MzMwMTYzNTAiLCJub25jZSI6IkpXbTdpZEN0OXN2U2pKR0VxSnZnTHNBV3dqZyIsIm5iZiI6MTc1MzA3NzkzMiwiaWF0IjoxNzUzMDc4MjMyLCJleHAiOjE3NTMwODE4MzIsImp0aSI6IjJmYmM4NWJkMGRiZGJlNWUzYmY5NDQ4YTBiNzY1MDg2MzkxZjI1OGYifQ.O16GaZdNpFphpmFSbzNpWQd7xjjYd9E8Tic4tr0Rkt1DYC0BRSiAg2aD-m8X1cWKHQVgzfMgQy8jacdXmzQPyy6DuilE03Y_3Z4xNj9jBhQWKDO9Z-q6MgFuL0mM3WYhGA2Q5DAXBvSU-dnTrLyT2ELMvTufOFyI4zxwg1eHxEcqZNXXZluCnZDxHA7RUP0uxnuFR-VGoQyUehGFzlaZ4fmfqOH8KjZkoQgYZxcVtHV0oZ8VlMdfFqd6TKWvKDgnoIQXr3ZYaP7fawu8nJa3Cqb86JgaMszGtKkY3mKugm06AVm71VmcKQihhxx-B4bv6nxAOAx10B3QcUr3OAzGRQ"

pk = {
  "e": "AQAB",
  "kty": "RSA",
  "n": "rHz-FQE9gjFJR_FhnzhBMPpa8NJ2nCfnXLr5LWDJOOaiGqI__Nrm6HHUCpMi52_pLqqVkCihR9xbscZ6UKr9wjp-7YTDN6A9i7QqQAJyNRIMCkJR1z6D95_pam_mIkBVnYjJ_LskOyOHI65Yvuaw6oA9iFlSyucn4B-jZRmp7JyGyU8UMohaOvJB7_boaIoEx_QY8YdoANKrp0WGawEkW6RgopgiHB7D0CXU-c_GDp0TjWCZegQzoV_fDD5eH5mc2Ai3dBylZxgQ-ZxMakYS01nmVr1atkpHT1L9W7PiCP60C8WG1aLIzZTLcABK3BWCmZ3-wBZtHZ0y9kSP35aowQ"
}

# jwt中第一个点的index
first_dot_index = jwt.index('.')
# jwt中第二个点的index
second_dot_index = jwt.index('.', first_dot_index + 1)
# 去掉jwt的签名和dot
unsigned_jwt = jwt[:second_dot_index]

# 对unsigned_jwt进行SHA256 padding
padded_unsigned_jwt = sha256_padding(unsigned_jwt)
# 计算sha2块的个数
num_sha2_blocks = len(padded_unsigned_jwt) // 64
# 将jwt_payload填充全0byte到maxPaddedUnsignedJWTLen长度
maxPaddedUnsignedJWTLen = 64 * 25
padded_unsigned_jwt = padded_unsigned_jwt.ljust(maxPaddedUnsignedJWTLen, b'\0')
# 将jwt_payload转换为byte数组
padded_unsigned_jwt = list(padded_unsigned_jwt)

# 截取payload
payload = jwt.split('.')[1]
# base64url解码
payload = base64url_decode(payload)

# # 处理iss
# (iss, iss_length, iss_start_index_b64, iss_length_b64, iss_colon_index, iss_value_index, iss_value_length, iss_value) = claimOperations(payload, '"iss"', offset = first_dot_index + 1)

# # 把iss每16字节转换为一个int
# iss_value_ints = [int.from_bytes(iss_value.encode('utf-8')[i:i+16], 'big') for i in range(0, len(iss_value.encode('utf-8')), 16)]

# 处理aud
(aud, aud_length, aud_index_b64, aud_length_b64, aud_colon_index, aud_value_index, aud_value_length, aud_value) = claimOperations(payload, '"aud"', offset = first_dot_index + 1)

# 把aud逐字符转换为int数组
aud_int = [ord(c) for c in aud]
maxAudValueLen = 160
# 把aud_int填充全0到maxAudValueLen长度
aud_int = aud_int + [0] * (maxAudValueLen - len(aud_int))

# 处理sub
(sub, sub_length, sub_index_b64, sub_length_b64, sub_colon_index, sub_value_index, sub_value_length, sub_value) = claimOperations(payload, '"sub"', offset = first_dot_index + 1)
# 把sub逐字符转换为int数组
sub_int = [ord(c) for c in sub]
maxSubValueLen = 130
# 把sub_int填充全0到maxSubValueLen长度
sub_int = sub_int + [0] * (maxSubValueLen - len(sub_int))

output = {
    "padded_unsigned_jwt": padded_unsigned_jwt,
    "payload_start_index": first_dot_index + 1,
    # "num_sha2_blocks": num_sha2_blocks,
    # "sha2pad_index": second_dot_index,
    # "iss_index_b64": first_dot_index + 1 + iss_start_index_base64,
    # "iss_length_b64": iss_end_index_base64 - iss_start_index_base64,
    # "iss": iss_value_ints,
    "aud": aud_int,
    "aud_length": aud_length,
    "aud_index_b64": aud_index_b64,
    "aud_length_b64": aud_length_b64,
    "aud_colon_index": aud_colon_index,
    "aud_value_index": aud_value_index,
    "aud_value_length": aud_value_length,
    "sub": sub_int,
    "sub_length": sub_length,
    "sub_index_b64": sub_index_b64,
    "sub_length_b64": sub_length_b64,
    "sub_colon_index": sub_colon_index,
    "sub_value_index": sub_value_index,
    "sub_value_length": sub_value_length
}

with open('input.json', 'w') as f:
    json.dump(output, f, indent=4)