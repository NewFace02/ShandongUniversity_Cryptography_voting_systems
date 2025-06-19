"主应用"
import requests
import json
import time
from typing import Dict
import os
from .config import SHAREHOLDERS_FILE
from backend.models.vote import Voter

class VoterClient:
    def __init__(self):
        """初始化客户端"""
        self.auth_url = "http://localhost:5001"  # 认证服务器
        self.vote_url = "http://localhost:5000"  # 投票服务器
        self.tally_url = "http://localhost:5002"  # 计票服务器
        self.credential = None
        self.voter_info = None
        self.shareholders_file = SHAREHOLDERS_FILE
        
    def login(self, voter_id: str) -> bool:
        """股东登录"""
        try:
            if not os.path.exists(self.shareholders_file):
                print(f"股东信息文件不存在: {self.shareholders_file}")
                return False
                
            with open(self.shareholders_file, "r") as f:
                shareholders = json.load(f)
            
            if voter_id not in shareholders["shareholders"]:
                print("无效的股东ID")
                return False
                
            # 将JSON数据转换为Voter对象
            data = shareholders["shareholders"][voter_id]
            self.voter_info = Voter(
                name=data["name"],
                uuid=data["uuid"],
                voter_id=data["voter_id"],
                voter_type=data["voter_type"],
                weight=data["weight"]
            )
            print(f"欢迎, {self.voter_info.name}!")
            return True
            
        except Exception as e:
            print(f"登录失败: {e}")
            return False
    
    def request_credential(self) -> bool:
        """请求投票凭证"""
        try:
            # 1. 生成盲化序列号
            serial_number = int.from_bytes(os.urandom(32), 'big')
            
            # 2. 构建请求数据
            request_data = {
                "voter_id": self.voter_info.voter_id,
                "blinded_serial": str(serial_number),
                "voter_info": {
                    "name": self.voter_info.name,
                    "uuid": self.voter_info.uuid,
                    "voter_type": "shareholder",  # 确保类型正确
                    "weight": self.voter_info.weight
                }
            }
            
            print(f"请求凭证数据: {request_data}")
            
            # 3. 发送请求
            response = requests.post(
                f"{self.auth_url}/auth/request_credential",
                json=request_data
            )
            
            if response.status_code == 200:
                self.credential = response.json()
                print(f"获取到凭证: {self.credential}")
                return True
            else:
                error_msg = response.json().get('error', '未知错误')
                print(f"请求凭证失败: {error_msg}")
                return False
                
        except Exception as e:
            print(f"请求凭证失败: {e}")
            return False
    
    def cast_vote(self, vote: int) -> bool:
        """提交投票"""
        if vote not in (0, 1):
            print("投票值必须是0或1")
            return False
            
        if not self.credential:
            print("未获取投票凭证，请先登录并获取凭证")
            return False
            
        try:
            print("正在加密投票...")
            print(f"投票值: {vote}, 权重: {self.voter_info.weight}")
            
            # 1. 加密投票数据
            encrypt_request = {
                "vote": vote,
                "weight": self.voter_info.weight
            }
            print(f"发送加密请求: {encrypt_request}")
            
            response = requests.post(
                f"{self.tally_url}/encrypt",
                json=encrypt_request
            )
            
            if response.status_code != 200:
                error_msg = response.json().get('error', '未知错误')
                print(f"投票加密失败: {error_msg}")
                print(f"服务器响应: {response.text}")
                return False
                
            encrypted_vote = response.json()
            print(f"投票已加密: {encrypted_vote}")
            
            # 2. 构建完整的投票请求
            vote_request = {
                "encrypted_vote": encrypted_vote,
                "credential": self.credential,
                "voter_id": self.voter_info.voter_id
            }
            print(f"准备提交投票请求: {vote_request}")
            
            # 3. 发送投票请求
            response = requests.post(
                f"{self.tally_url}/submit",
                json=vote_request,
                headers={'Content-Type': 'application/json'}
            )
            
            print(f"服务器响应状态码: {response.status_code}")
            print(f"服务器响应内容: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                print("投票成功!")
                print(f"投票索引: {result.get('vote_index')}")
                return True
            else:
                error_msg = response.json().get('error', '未知错误')
                print(f"投票提交失败: {error_msg}")
                return False
                
        except Exception as e:
            print(f"投票过程出错: {e}")
            import traceback
            print(f"详细错误信息:\n{traceback.format_exc()}")
            return False

def main():
    """主程序"""
    client = VoterClient()
    
    while True:
        print("\n=== 股东投票系统 ===")
        print("1. 登录")
        print("2. 投票")
        print("3. 验证投票")
        print("4. 查看结果")
        print("0. 退出")
        
        choice = input("请选择操作: ")
        
        if choice == "1":
            voter_id = input("请输入股东ID: ")
            if client.login(voter_id):
                client.request_credential()
        
        elif choice == "2":
            if not client.voter_info:
                print("请先登录!")
                continue
                
            try:
                vote = int(input("请输入投票(0/1): "))
                client.cast_vote(vote)
            except ValueError:
                print("无效的输入")
        
        elif choice == "3":
            try:
                vote_index = int(input("请输入投票索引: "))
                client.verify_vote(vote_index)
            except ValueError:
                print("无效的输入")
        
        elif choice == "4":
            client.get_result()
        
        elif choice == "0":
            break
        
        else:
            print("无效的选择")

if __name__ == "__main__":
    main()