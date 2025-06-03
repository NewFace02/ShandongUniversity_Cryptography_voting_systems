#此模块内含使用OR_Proof来证明单次的投票有效果：即使用r来进行加密并且投票落在0或者1
# backend/crypto/single_ballot.py

from ..utils import crypto_utils
from typing import Tuple
from dataclasses import dataclass
#零知识证明类，用于后面的vote结构体使用
@dataclass
class ZKProof_01:
    com1: Tuple[int, int]  # A1, B1
    com2: Tuple[int, int]  # A2, B2
    cha1: int
    cha2: int
    resp1: int
    resp2: int
    verified: bool= False


class ORProof:
    def __init__(self, p, g, y):
        self.p = p
        self.g = g
        self.y = y
    ##验证第一步，客户生成com1和com2
    def generate_proof_step1(self, m, c):
        self.w = crypto_utils.randint(0, self.p)
        A1 = pow(self.g, self.w, self.p)
        B1 = pow(self.y, self.w, self.p)
        self.com1 = (A1, B1) 

        alpha, beta = c
        m2 = (1 - m) % self.p
        self.cha2 = crypto_utils.randint(0, self.p)
        self.resp2 = crypto_utils.randint(0, self.p)

        A2 = pow(self.g, self.resp2, self.p) * crypto_utils.inverse_mod(pow(alpha, self.cha2, self.p), self.p) % self.p
        temp = beta * crypto_utils.inverse_mod(pow(self.g, m2, self.p), self.p) % self.p
        B2 = pow(self.y, self.resp2, self.p) * crypto_utils.inverse_mod(pow(temp, self.cha2, self.p), self.p) % self.p
        self.com2 = (A2, B2)

        return self.com1, self.com2
    
    ##验证第三步，客户生成cha1和resp1、发送cha1、resp1、cha2、resp2给计票中心
    def generate_proof_step2(self, cha, r):
        self.cha1 = (cha - self.cha2) % self.p
        self.resp1 = r * self.cha1 + self.w
        return self.cha1, self.resp1, self.cha2, self.resp2

#V方开始检验：投票者需要向V方发送cha2、cha1、resp1、resp2；V方检验com1和com2的有效性（当m=0的时候，必须有一个通过；m=1的时候，也必须有一个通过），并验证cha1和cha2的关系
    @staticmethod
    def verify_proof(c, com1, com2, cha, cha1, cha2, resp1, resp2, pk_v):
        zkproof=ZKProof_01(com1=com1, com2=com2, cha1=cha1, cha2=cha2, resp1=resp1, resp2=resp2)
        alpha, beta = c
        p, _, g, y = pk_v
        A1, B1 = com1
        A2, B2 = com2

        if (cha1 + cha2) % p != cha % p:
            return False

        left_A1 = pow(g, resp1, p)
        right_A1 = A1 * pow(alpha, cha1, p) % p

        left_B1 = pow(y, resp1, p)
        right_B1 = B1 * pow(beta, cha1, p) % p

        left_A2 = pow(g, resp2, p)
        right_A2 = A2 * pow(alpha, cha2, p) % p

        left_B2 = pow(y, resp2, p)
        right_B2 = B2 * pow(beta, cha2, p) % p

        # try both paths
        ###当m=0时，beta=beta，com1和com2必须有一个通过检验
        if (left_A1 == right_A1 and left_B1 == right_B1) or (left_A2 == right_A2 and left_B2 == right_B2):
            ###当m=1时，beta=beta/g，com1和com2必须有一个通过检验
            temp = beta * crypto_utils.inverse_mod(g, p) % p
            right_B1 = B1 * pow(temp, cha1, p) % p
            right_B2 = B2 * pow(temp, cha2, p) % p

            if (left_A1 == right_A1 and left_B1 == right_B1) or (left_A2 == right_A2 and left_B2 == right_B2):
                zkproof.verified = True

        return zkproof



