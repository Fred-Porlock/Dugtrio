import json
import base64

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

# jwt的header和payload的长度
header_payload_length = len(unsigned_jwt)

# 将jwt_payload转换为byte数组
padded_unsigned_jwt = list(padded_unsigned_jwt)

# jwt的签名
signature = jwt.split('.')[2]
# 把签名base64解码
signature_bytes = base64.urlsafe_b64decode(signature + '==')  # 补齐等号
# 将解码后的字节用小端法转换为8字节整数列表
# 8字节
signature_ints = [int.from_bytes(signature_bytes[i:i + 8], 'little') for i in range(0, len(signature_bytes), 8)]

# 把pk的n用小端法转换为8字节整数列表
modulus_bytes = base64.urlsafe_b64decode(pk['n'] + '==')  # 补齐等号
modulus_ints = [int.from_bytes(modulus_bytes[i:i + 8], 'little') for i in range(0, len(modulus_bytes), 8)]

output = {
    "padded_unsigned_jwt": padded_unsigned_jwt,
    "payload_start_index": first_dot_index + 1,
    "num_sha2_blocks": num_sha2_blocks,
    "payload_len": second_dot_index - first_dot_index - 1,
    "signature": signature_ints,
    "modulus": modulus_ints
}

with open('input.json', 'w') as f:
    json.dump(output, f, indent=4)