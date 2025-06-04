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