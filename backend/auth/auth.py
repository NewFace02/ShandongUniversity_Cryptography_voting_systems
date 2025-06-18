"""### **资格认证核心方法**
1. **序列号生成**  
   - **匿名获取**：选民通过公开的随机序列号生成网站（无需身份认证）获取唯一的随机序列号 `m_i`（采用梅森旋转算法 MT19937 保证唯一性）。  
   - **防追踪**：网站通过验证码或耗时任务防止批量请求，确保序列号与选民身份无关联。

2. **盲化序列号**  
   - 选民使用**盲签名辅助平台**：  
     - 输入序列号 `m_i` 和认证机构提供的临时变量 `P_i`（椭圆曲线上的点）。  
     - 计算盲化值：  
       - 生成随机数 `α, β`，计算盲化消息 `r' = α⁻¹(H(m_i) + β)` （具体公式见原文第121页）。  
     - 输出盲化后的序列号 `r'`。

3. **官方签名认证**  
   - 选民向**认证机构**提交盲化序列号 `r'` 和真实身份 `ID_i`。  
   - 认证机构验证身份合法性后：  
     - 使用私钥 `x` 计算盲签名 `s' = (1 + x)⁻¹(k - r'x) mod n`（`k`为临时随机数）。  
   - **关键点**：机构仅知盲化值 `r'`，无法关联原始序列号 `m_i`，保障匿名性。

4. **脱盲生成资格证**  
   - 选民再次使用辅助平台：  
     - 输入盲签名 `s'`，通过脱盲计算 `s = α·s' + β`，得到原始签名 `(r, s)`。  
   - 资格证组成：`{m_i, (r, s)}`（序列号+官方签名）。

5. **投票验证**  
   - 计票机构验证资格证：  
     1. 检查序列号 `m_i` 是否首次使用（防重复投票）。  
     2. 用认证机构公钥验证签名有效性（椭圆曲线验证算法）。  
   - **双重保障**：唯一序列号防重投，数字签名防伪造。"""
from .blind_signature import BlindClient, BlindSigner
import random
from ..config import load_rsa_keys
#第一步和第二步，客户生成盲化的序列号
def first_step_second_step(n,e):
    
    m_i = random.getrandbits(256) # 此 m_i 直接作为消息 M



    client = BlindClient(n, e)

    blinded_msg, r = client.blind(m_i)
    return blinded_msg, r, m_i
# 发送 blinded_msg 给认证机构

def third_step(blinded_msg):
    signer = BlindSigner()

    signed_blinded = signer.sign(blinded_msg)
    return signed_blinded
# 返回 signed_blinded 给选民
def forth_step(n,e,signed_blinded, r, m_i):
    client = BlindClient(n,e)
    # 选民脱盲
    # 注意这里的 r 是在第一步生成的随机数
    # m_i 是原始的随机序列号
    # signed_blinded 是认证机构签名后的盲化序列号
    signature = client.unblind(signed_blinded, r)

    credential = {
        'serial_number': m_i,   # 原始随机序列号
        'signature': signature  # 对 m_i 的 RSA 签名
    }

    return credential
#此函数仅用于验证签名
def verify(n,e,serial_number: int, signature: int) -> bool:
    return pow(signature, e, n) == serial_number

