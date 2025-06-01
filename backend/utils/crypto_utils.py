import random
from random import randint

def inverse_mod(a, p):
    """计算a在模p下的逆元"""
    return pow(a, p - 2, p)