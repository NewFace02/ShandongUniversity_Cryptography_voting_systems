#此模块内含使用OR_Proof来证明单次的投票有效果：即使用r来进行加密并且投票落在0或者1
from ..utils import crypto_utils

# OR_Proof_P_1(m,c,pk_v)函数为投票者向计票中心验证的第一步，生成com1、com2、cha2和resp2，但只向验证者发送com1和com2
def OR_Proof_P_1(m,c,pk_v):#pk_v为投票公钥

    #创建w、com（A1,B1）
    w=crypto_utils.randint(0,p)
    A1=pow(g,w,p)
    B1=pow(y,w,p)
    com1=(A1,B1)

    #创建com2

    ##创建cha2和resp2
    m2=(1-m)%p
    alpha,beta= c
    p,q,g,y= pk_v
    resp2=crypto_utils.randint(0,p)
    cha2=crypto_utils.randint(0,p)
    
    ##计算A2和B2
    A2=pow(g,resp2,p)*crypto_utils.inverse_mod(pow(alpha,cha2,p),p)
    temp=beta*crypto_utils.inverse_mod(pow(g,m2,p),p) ###beta=beta/g^m2
    B2=pow(y,resp2,p)*crypto_utils.inverse_mod(pow(temp,cha2,p),p)
    com2=(A2,B2)

    return com1, com2,cha2,resp2

# OR_Proof_V_1函数为计票中心验证投票者的第一步，生成随机数cha，并向投票者发送
def OR_Proof_V_1(p):
    cha=crypto_utils.randint(0, p)
    return cha

# OR_Proof_P_2函数为投票者向计票中心验证的第二步，生成resp1和cha1

def OR_Proof_P_2(cha,w,cha2,r,p):
    cha1=(cha-cha2)%p
    resp1=r*cha1+w

    return cha1,resp1

#V方开始检验：投票者需要向V方发送cha2、cha1、resp1、resp2；V方检验com1和com2的有效性（当m=0的时候，必须有一个通过；m=1的时候，也必须有一个通过），并验证cha1和cha2的关系
def OR_Proof_V_2(c,com1, com2,cha,cha1,cha2, resp1, resp2,pk_v):
    if((cha2+cha1-cha)%p != 0):
        return False
    else:
        alpha,beta=c
        p,k,g,y=pk_v
        A1,B1=com1
        A2,B2=com2

        left_A1=pow(g,resp1,p)
        right_A1=A1*pow(alpha,cha1,p)

        left_A2=pow(g,resp2,p)
        right_A2=A2*pow(alpha,cha2,p)

        left_B1=pow(y,resp1,p)
        left_B2=pow(y,resp2,p)
###当m=0时，beta=beta，com1和com2必须有一个通过检验
        right_B1=B1*pow(beta,cha1,p)
        right_B2=B2*pow(beta,cha2,p)
        if ((left_A1 == right_A1 and left_B1 == right_B1) or( left_A2 == right_A2 and left_B2 == right_B2)):
            ###当m=1时，beta=beta/g，com1和com2必须有一个通过检验
            temp=beta*crypto_utils.inverse_mod(g,p)
            right_B1=B1*pow(temp,cha1,p)
            right_B2=B2*pow(temp,cha2,p)          
            if ((left_A1 == right_A1 and left_B1 == right_B1) or( left_A2 == right_A2 and left_B2 == right_B2)):
                return True
    return False