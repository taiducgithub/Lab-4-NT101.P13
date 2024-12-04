import hashlib

def generate_hashes(input_data):
    md5_hash = hashlib.md5(input_data.encode()).hexdigest()
    sha1_hash = hashlib.sha1(input_data.encode()).hexdigest()
    sha256_hash = hashlib.sha256(input_data.encode()).hexdigest()
    return md5_hash, sha1_hash, sha256_hash

def hash_file(file_path):
    hasher_md5 = hashlib.md5()
    hasher_sha1 = hashlib.sha1()
    hasher_sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        # Đọc tệp theo khối
        while chunk := f.read(8192):  # Đọc từng 8192 byte
            hasher_md5.update(chunk)
            hasher_sha1.update(chunk)
            hasher_sha256.update(chunk)

    return hasher_md5.hexdigest(), hasher_sha1.hexdigest(), hasher_sha256.hexdigest()

# Nhập dữ liệu
input_text = "UIT Cryptography" 

input_hex = "5568697461726f757465726578616d706c6575"  # Đường dẫn hex hợp lệ

# Tính toán giá trị băm cho chuỗi văn bản
md5_text, sha1_text, sha256_text = generate_hashes(input_text)

# Tính toán giá trị băm cho chuỗi hex
# Chuyển đổi hex thành byte trước khi băm
md5_hex, sha1_hex, sha256_hex = generate_hashes(bytes.fromhex(input_hex).decode())

# Tính toán giá trị băm cho tệp
file_path = r'C:\py\md5.txt'  # Đường dẫn tới tệp
md5_file, sha1_file, sha256_file = hash_file(file_path)

# In kết quả
print("Hash values for text string:")
print(f"MD5: {md5_text}")
print(f"SHA-1: {sha1_text}")
print(f"SHA-256: {sha256_text}")

print("\nHash values for hex string:")
print(f"MD5: {md5_hex}")
print(f"SHA-1: {sha1_hex}")
print(f"SHA-256: {sha256_hex}")

print("\nHash values for file:")
print(f"MD5: {md5_file}")
print(f"SHA-1: {sha1_file}")
print(f"SHA-256: {sha256_file}")