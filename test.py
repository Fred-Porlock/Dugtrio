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