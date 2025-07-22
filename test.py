def sha256_padding(message):
    """实现SHA-256填充规则，处理任意长度消息"""
    # 将输入转换为字节序列
    if isinstance(message, str):
        data = message.encode('utf-8')
    else:
        data = message
    
    L = len(data)  # 原始消息字节长度
    bit_length = L * 8  # 原始消息比特长度
    
    # 1. 添加比特"1"：用字节0x80表示 (10000000)
    padded = bytearray(data)
    padded.append(0x80)
    
    # 2. 计算需要填充的0字节数量
    # 公式：(L + 1 + k + 8) ≡ 0 (mod 64)
    # 可以简化为：k = (55 - L) % 64
    k = (55 - L) % 64
    
    # 添加k个0x00字节
    padded.extend([0] * k)
    
    # 3. 添加64位大端序的原始比特长度
    padded.extend(bit_length.to_bytes(8, 'big'))
    
    return bytes(padded)

def sha256_chunked_padding(message):
    """处理长消息的分块填充"""
    # 将输入转换为字节序列
    if isinstance(message, str):
        data = message.encode('utf-8')
    else:
        data = message
    
    L = len(data)  # 原始消息字节长度
    bit_length = L * 8  # 原始消息比特长度
    
    # 计算需要填充的总字节数
    total_padded_length = ((L + 8) // 64 + 1) * 64
    if (L % 64) >= 56:
        total_padded_length += 64  # 需要额外一个块
    
    # 创建填充后的字节数组
    padded = bytearray(data)
    
    # 1. 添加比特"1"：0x80
    padded.append(0x80)
    
    # 2. 填充0字节直到最后8字节之前
    current_length = len(padded)
    padding_needed = total_padded_length - current_length - 8
    padded.extend([0] * padding_needed)
    
    # 3. 添加64位大端序的原始比特长度
    padded.extend(bit_length.to_bytes(8, 'big'))
    
    return bytes(padded)

# 测试不同长度的消息
if __name__ == "__main__":
    import hashlib
    import os
    
    def validate_padding(message):
        """验证填充结果是否正确"""
        # 使用标准库计算填充后的哈希
        h_std = hashlib.sha256(message.encode() if isinstance(message, str) else message).hexdigest()
        
        # 使用我们的填充函数
        padded = sha256_padding(message)
        h_custom = hashlib.sha256(padded).hexdigest()
        
        # 验证长度是否为64的倍数
        valid_length = len(padded) % 64 == 0
        
        # 验证哈希是否匹配
        valid_hash = h_std == h_custom
        
        return valid_length and valid_hash
    
    # 测试不同长度的消息
    test_cases = [
        "",                      # 空消息
        "a",                     # 短消息
        "abc",                   # 刚好需要填充
        "a" * 55,                # 55字节（填充后为64字节）
        "a" * 56,                # 56字节（填充后为128字节）
        "a" * 63,                # 63字节（填充后为128字节）
        "a" * 64,                # 64字节（填充后为128字节）
        "a" * 100,               # 100字节
        "a" * 1000,              # 1000字节
        os.urandom(1024),        # 1024字节随机数据
        "The quick brown fox jumps over the lazy dog"  # 著名测试用例
    ]
    
    for i, message in enumerate(test_cases):
        result = validate_padding(message)
        length = len(message) if isinstance(message, str) else len(message)
        print(f"测试 {i+1}: {length}字节消息 - {'通过' if result else '失败'}")
    
    # 测试非常长的消息
    long_msg = "a" * 1000000  # 1百万字节
    print(f"\n测试长消息: {len(long_msg)}字节消息 - {'通过' if validate_padding(long_msg) else '失败'}")