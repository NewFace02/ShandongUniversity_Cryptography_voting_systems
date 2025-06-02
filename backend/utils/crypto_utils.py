import random
from random import randint

def inverse_mod(a, p):
    """计算a在模p下的逆元"""
    return pow(a, p - 2, p)

def mod_exp(base, exponent, modulus):
    """
    快速模幂运算：计算 (base ** exponent) % modulus
    支持大整数计算，时间复杂度 O(log exponent)
    """
    result = 1
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:  # 如果当前位是1
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus

    return result