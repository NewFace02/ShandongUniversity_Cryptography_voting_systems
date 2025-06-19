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
     2. 用认证机构公钥验证签名有效性 
   - **双重保障**：唯一序列号防重投，数字签名防伪造。"""
from typing import Dict, Set, Tuple
import json
import os
import random
from ..config import load_rsa_keys
from .blind_signature import BlindClient, BlindSigner

class CredentialVerifier:
    """投票资格验证器"""
    
    def __init__(self):
        """初始化验证器"""
        self.used_serials: Set[int] = set()  # 已使用的序列号集合
        self.n, self.e, _ = load_rsa_keys()  # 只需要公钥(n,e)
        self._load_used_serials()  # 从文件加载已使用序列号
        self.signer = BlindSigner()  # 初始化签名者
    
    def _load_used_serials(self):
        """从文件加载已使用的序列号"""
        try:
            # 存储在auth目录下的used_serials.json
            path = os.path.join(os.path.dirname(__file__), "used_serials.json")
            if os.path.exists(path):
                with open(path, "r") as f:
                    data = json.load(f)
                    self.used_serials = set(map(int, data["used_serials"]))
            else:
                self.used_serials = set()
        except Exception as e:
            print(f"加载已用序列号失败: {e}")
            self.used_serials = set()   
    def _save_used_serials(self):
        """保存已使用的序列号到文件"""
        try:
            path = os.path.join(os.path.dirname(__file__), "used_serials.json")
            with open(path, "w") as f:
                json.dump({
                    "used_serials": list(map(str, self.used_serials))
                }, f, indent=2)
        except Exception as e:
            print(f"保存已用序列号失败: {e}")
            
    def generate_credential(self) -> Dict:
        """
        生成投票资格证书（包含所有步骤）
        返回: 完整的资格证书
        """
        # 步骤1&2: 生成盲化序列号
        blinded_msg, r, m_i = self.generate_blinded_serial()
        
        # 步骤3: 签名机构签名
        signed_blinded = self.sign_blinded_message(blinded_msg)
        
        # 步骤4: 生成最终凭证
        return self.create_credential(signed_blinded, r, m_i)

    def generate_blinded_serial(self) -> Tuple[int, int, int]:
        """
        生成盲化的序列号（步骤1&2）
        返回: (blinded_msg, r, m_i)
        """
        m_i = random.getrandbits(256)  # 生成随机序列号
        client = BlindClient(self.n, self.e)
        blinded_msg, r = client.blind(m_i)
        return blinded_msg, r, m_i

    def sign_blinded_message(self, blinded_msg: int) -> int:
        """
        对盲化消息进行签名（步骤3）
        """
        return self.signer.sign(blinded_msg)

    def create_credential(self, signed_blinded: int, r: int, m_i: int) -> Dict:
        """
        创建最终凭证（步骤4）
        """
        client = BlindClient(self.n, self.e)
        signature = client.unblind(signed_blinded, r)
        
        return {
            'serial_number': m_i,
            'signature': signature
        }

    def verify_credential(self, credential: Dict) -> bool:
        """验证投票资格证明（步骤5）"""
        try:
            serial_number = credential["serial_number"]
            signature = credential["signature"]
            
            # 1. 检查序列号是否已被使用
            if serial_number in self.used_serials:
                print(f"序列号 {serial_number} 已被使用")
                return False
                
            # 2. 验证签名
            if not self._verify_signature(serial_number, signature):
                print(f"签名验证失败")
                return False
                
            # 3. 验证通过，记录已使用
            self.used_serials.add(serial_number)
            self._save_used_serials()
            
            return True
            
        except Exception as e:
            print(f"验证过程发生错误: {e}")
            return False

    def _verify_signature(self, serial_number: int, signature: int) -> bool:
        """验证RSA签名"""
        return pow(signature, self.e, self.n) == serial_number
    
    def clear_used_serials(self):
        """清空已使用序列号(仅用于测试)"""
        self.used_serials.clear()
        self._save_used_serials()