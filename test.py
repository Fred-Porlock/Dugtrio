import base64
import hashlib

jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImI1MDljNTEzODc2OGY3Y2YyZTgyN2UwNGIyN2U3ZTRjYmM3YmI5MTkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTIwMzc1OTAzMjI2MzMwMTYzNTAiLCJub25jZSI6IkpXbTdpZEN0OXN2U2pKR0VxSnZnTHNBV3dqZyIsIm5iZiI6MTc1MzA3NzkzMiwiaWF0IjoxNzUzMDc4MjMyLCJleHAiOjE3NTMwODE4MzIsImp0aSI6IjJmYmM4NWJkMGRiZGJlNWUzYmY5NDQ4YTBiNzY1MDg2MzkxZjI1OGYifQ.O16GaZdNpFphpmFSbzNpWQd7xjjYd9E8Tic4tr0Rkt1DYC0BRSiAg2aD-m8X1cWKHQVgzfMgQy8jacdXmzQPyy6DuilE03Y_3Z4xNj9jBhQWKDO9Z-q6MgFuL0mM3WYhGA2Q5DAXBvSU-dnTrLyT2ELMvTufOFyI4zxwg1eHxEcqZNXXZluCnZDxHA7RUP0uxnuFR-VGoQyUehGFzlaZ4fmfqOH8KjZkoQgYZxcVtHV0oZ8VlMdfFqd6TKWvKDgnoIQXr3ZYaP7fawu8nJa3Cqb86JgaMszGtKkY3mKugm06AVm71VmcKQihhxx-B4bv6nxAOAx10B3QcUr3OAzGRQ"

pk = {
  "e": "AQAB",
  "kty": "RSA",
  "n": "rHz-FQE9gjFJR_FhnzhBMPpa8NJ2nCfnXLr5LWDJOOaiGqI__Nrm6HHUCpMi52_pLqqVkCihR9xbscZ6UKr9wjp-7YTDN6A9i7QqQAJyNRIMCkJR1z6D95_pam_mIkBVnYjJ_LskOyOHI65Yvuaw6oA9iFlSyucn4B-jZRmp7JyGyU8UMohaOvJB7_boaIoEx_QY8YdoANKrp0WGawEkW6RgopgiHB7D0CXU-c_GDp0TjWCZegQzoV_fDD5eH5mc2Ai3dBylZxgQ-ZxMakYS01nmVr1atkpHT1L9W7PiCP60C8WG1aLIzZTLcABK3BWCmZ3-wBZtHZ0y9kSP35aowQ"
}

'''
# 验证circom生成的hash值

# 把jwt的header||.||payload部分分离出来
first_dot_index = jwt.index('.')
second_dot_index = jwt.index('.', first_dot_index + 1)
unsigned_jwt = jwt[:second_dot_index]

# 对unsigned_jwt计算SHA256哈希值
hash_jwt = hashlib.sha256(unsigned_jwt.encode('utf-8')).digest()

print(f"Hash of unsigned JWT: {base64.urlsafe_b64encode(hash_jwt).decode('utf-8')}")

# 将哈希值转换为整数列表
hash_ints = [int.from_bytes(hash_jwt[i:i+8], 'big') for i in range(0, len(hash_jwt), 8)]
print(f"Hash integers: {hash_ints}")

# circom电路生成的哈希值
hash_proof = [
 "8966685315110275058",
 "1636509426883196743",
 "408772202622701031",
 "12807911352096587460"
]
# 将circom电路生成的哈希值转换为整数列表
hash_proof_ints = [int(x) for x in hash_proof]
print(f"Hash proof integers: {hash_proof_ints}")
'''

'''
# 从jwt中提取iss字段

# 截取payload
payload = jwt.split('.')[1]
# 补充=
payload = payload + '=' * (-len(payload) % 4)
# base64url解码
payload_bytes = base64.urlsafe_b64decode(payload)
# 转换为字符串
payload_str = payload_bytes.decode('utf-8')
# print(f"Decoded payload: {payload_str}")

# 找到iss字段起始位置
iss_start_index = payload_str.index('"iss":"')
# 找到iss字段结束位置
iss_end_index = payload_str.index('"', iss_start_index + 7)
# 截取iss字段
iss = payload_str[iss_start_index : iss_end_index+1]
# print(iss)

# 根据iss字段起始位置计算base64编码后的payload中的起始位置
iss_start_index_base64 = (iss_start_index // 3) * 4
# 根据iss字段结束位置计算base64编码后的payload中的结束位置
iss_end_index_base64 = (iss_end_index // 3) * 4 + 4
# 截取base64编码后的iss字段
iss_base64 = payload[iss_start_index_base64 : iss_end_index_base64]
# 解码为字符串
iss_decoded = base64.urlsafe_b64decode(iss_base64).decode('utf-8')
print(f"Decoded iss: {iss_decoded}")
'''

'''
# 验证电路切的iss字段

iss_cut=["101", "121", "74", "112", "99", "51", "77", "105", "79", "105", "74", "111", "100", "72", "82", "119", "99", "122", "111", "118", "76", "50", "70", "106", "89", "50", "57", "49", "98", "110", "82", "122", "76", "109", "100", "118", "98", "50", "100", "115", "90", "83", "53", "106", "98", "50", "48", "105", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"
]

# 把iss_cut转换为byte数组
iss_cut_bytes = bytes(int(x) for x in iss_cut)
# 去除末尾填充的全0字节
iss_cut_bytes = iss_cut_bytes.rstrip(b'\0')
# base64解码
iss_decoded = base64.urlsafe_b64decode(iss_cut_bytes)
# 打印解码后的iss
print(f"Decoded iss from cut: {iss_decoded.decode('utf-8')}")
'''

# # 计算并验证nonce

# jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImI1MDljNTEzODc2OGY3Y2YyZTgyN2UwNGIyN2U3ZTRjYmM3YmI5MTkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTIwMzc1OTAzMjI2MzMwMTYzNTAiLCJub25jZSI6InE0S20yR25tZlpSOE85UE5BNjJ5SWoyeHMwZyIsIm5iZiI6MTc1MzMzNTM0NiwiaWF0IjoxNzUzMzM1NjQ2LCJleHAiOjE3NTMzMzkyNDYsImp0aSI6ImJmODk4MDMyYjkyMTExYWY1MWQxYTEwN2I1MGUzMGZjMTIwZTllOWMifQ.kDBYGO0Hy_sfW7xp4AmTHCjCAw85FWvAj1jcSiprHE0pYQDk2zVE6UJwlOV1573mFku4Yl_AF8JPC7jUCMEpuKbQ0c3Xi5Rj2oGSzcugXIOB592MVfcZ-gQrWosPyga1-4ZI-VnHfZAQp5vU9sDbpOVblgBMUAXXgyUpkeRMI_PS8raFwc-JqsY6wKUonT48Abd9zDyrwwz7NTs2BkjA5Q2x7GQ5nhY1S6T2ieJhBTiEJsSkK5TEGJjxzViCy4JpRsfzVHLqt6Ioqo_mot5uXaPnPAHbIfv-6GAUxAHICuR4gSs1qIHigGGtaV3bM85AJgrbb36DmWsCBBeUNP-r4Q"

# # 临时公钥
# epk = "APUHWWEf9ItwRwB51EmPp1vDQwxktlDCUJ0mRz3cBno="
# # maxEpoch
# maxEpoch = 66
# # randomness
# randomness = 129755896008919731799400095156330387789
# # nonce
# nonce = "q4Km2GnmfZR8O9PNA62yIj2xs0g"


# 把公钥数组转换为ed25519公钥
import struct

epk = ["10576117717713998887337681800052029205259032", "83929355055751352554831714950413032872"]

# 将字符串转换为整数
epk_ints = [int(x) for x in epk]
print(f"EPK integers: {epk_ints}")

# Ed25519公钥是32字节，我们需要将这两个大整数转换为字节
# 假设这两个整数代表公钥的两个部分，需要将它们打包成32字节
pubkey_bytes = bytearray(32)

# 将第一个整数转换为字节（前16字节）
first_int = epk_ints[0]
for i in range(16):
    pubkey_bytes[i] = (first_int >> (8 * i)) & 0xFF

# 将第二个整数转换为字节（后16字节）
second_int = epk_ints[1]
for i in range(16):
    pubkey_bytes[16 + i] = (second_int >> (8 * i)) & 0xFF

# 转换为base64编码
epk_base64 = base64.b64encode(bytes(pubkey_bytes)).decode('utf-8')
print(f"Ed25519 public key (base64): {epk_base64}")

# 把ed25519公钥转换为整数
# epk_base64 = "APUHWWEf9ItwRwB51EmPp1vDQwxktlDCUJ0mRz3cBno="


# 将base64编码的ed25519公钥解码为字节
pubkey_bytes_decoded = base64.b64decode(epk_base64)
print(f"Decoded public key bytes length: {len(pubkey_bytes_decoded)}")
print(f"Decoded public key bytes: {pubkey_bytes_decoded.hex()}")

# 方法1：将32字节分为两个16字节的整数（小端序）
first_int_decoded = int.from_bytes(pubkey_bytes_decoded[:16], byteorder='little')
second_int_decoded = int.from_bytes(pubkey_bytes_decoded[16:], byteorder='little')
epk_array_method1 = [str(first_int_decoded), str(second_int_decoded)]
print(f"Method 1 - EPK array: {epk_array_method1}")

# 方法2：将整个32字节作为一个大整数，然后分解为两个128位的部分
combined_int_decoded = int.from_bytes(pubkey_bytes_decoded, byteorder='little')
# 提取低128位和高128位
low_128_bits = combined_int_decoded & ((1 << 128) - 1)
high_128_bits = combined_int_decoded >> 128
epk_array_method2 = [str(low_128_bits), str(high_128_bits)]
print(f"Method 2 - EPK array: {epk_array_method2}")

# 验证：比较原始的epk数组和解码后的数组
print(f"Original EPK: {epk}")
print(f"Does method 1 match original? {epk_array_method1 == epk}")
print(f"Does method 2 match original? {epk_array_method2 == epk}")