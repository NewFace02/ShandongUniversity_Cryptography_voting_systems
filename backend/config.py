"密钥配置"

import os
import json
from Crypto.PublicKey import ElGamal
from Crypto import Random
""" 
    elgamal_params
"""
PARAM_BITS = 1024
CACHE_FILE = f"elgamal_params_{PARAM_BITS}.json"

def generate_and_cache_elgamal_keys(bits=PARAM_BITS):
    """使用 PyCryptodome 生成 ElGamal 密钥，并缓存参数"""
    key = ElGamal.generate(bits, Random.new().read)
    params = {
        "p": str(key.p),
        "g": str(key.g),
        "y": str(key.y),  # 公钥部分
        "x": str(key.x)   # 私钥部分
    }
    with open(CACHE_FILE, "w") as f:
        json.dump(params, f)
    print(f"已生成并缓存 ElGamal 参数到 {CACHE_FILE}")
    return int(key.p), int(key.g), int(key.y), int(key.x)

def load_elgamal_keys():
    """从缓存加载 ElGamal 参数（不存在则自动生成）"""
    if not os.path.exists(CACHE_FILE):
        return generate_and_cache_elgamal_keys()

    with open(CACHE_FILE, "r") as f:
        data = json.load(f)
        return (
            int(data["p"]),
            int(data["g"]),
            int(data["y"]),
            int(data["x"])
        )
    

from Crypto.PublicKey import RSA
RSA_BITS = 2048
RSA_CACHE_FILE = f"rsa_params_{RSA_BITS}.json"

def generate_and_cache_rsa_keys(bits=2048, save_to_file=False, public_key_file="rsa_public.pem", private_key_file="rsa_private.pem"):
    """
    生成 RSA 密钥对

    参数:
        bits (int): 密钥长度，通常是 2048 bit
        save_to_file (bool): 是否将密钥保存为文件（默认 False）
        public_key_file (str): 公钥保存路径（默认 'rsa_public.pem'）
        private_key_file (str): 私钥保存路径（默认 'rsa_private.pem'）

    返回:
        (public_key_pem: str, private_key_pem: str)
    """
    # 生成密钥对
    key = RSA.generate(bits,Random.new().read)

    # 导出为 PEM 格式字符串
    rsa_params = {
        "n": str(key.n),  # modulus
        "e": str(key.e),  # public exponent
        "d": str(key.d)   # private exponent
    }

    # 可选保存为文件
    if save_to_file:
        with open(RSA_CACHE_FILE, "w") as f:
            json.dump(rsa_params, f)
        print(f"已生成并缓存 RSA 参数到 {RSA_CACHE_FILE}")
        return int(rsa_params["n"]), int(rsa_params["e"]), int(rsa_params["d"])

    return int(rsa_params["n"]), int(rsa_params["e"]), int(rsa_params["d"])

def load_rsa_keys():
    """
    从缓存加载 RSA 参数（如果不存在则生成）
    返回：n, e, d
    """
    if not os.path.exists(RSA_CACHE_FILE):
        return generate_and_cache_rsa_keys()

    with open(RSA_CACHE_FILE, "r") as f:
        data = json.load(f)
        return int(data["n"]), int(data["e"]), int(data["d"])
