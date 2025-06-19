from flask import Flask, request, jsonify
from backend.tally.controller import TallyController 
from backend.storage.vote_db import store_vote, get_all_votes
from backend.verify.controller import VerifyController
from backend.auth.auth import CredentialVerifier
from backend.audit.logger import AuditLogger
from backend.vote.controller import VoteController

app = Flask(__name__)
tally_controller = TallyController()
verify_controller = VerifyController()
credential_verifier = CredentialVerifier()
vote_controller = VoteController()
audit_logger = AuditLogger()

@app.route('/encrypt', methods=['POST'])
def encrypt_vote():
    """加密投票"""
    try:
        data = request.get_json()
        if not all(k in data for k in ['vote', 'weight']):
            return jsonify({"error": "Missing required fields"}), 400
            
        # 使用VoteController加密投票
        vote_data = vote_controller.create_vote(
            plaintext=int(data['vote']),
            weight=int(data['weight'])
        )
        
        return jsonify(vote_data)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

import logging

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/submit', methods=['POST'])
def submit_vote():
    """提交投票"""
    try:
        data = request.get_json()
        logger.debug(f"接收到投票请求数据: {data}")
        
        if not all(k in data for k in ['encrypted_vote', 'credential', 'voter_id']):
            logger.error(f"缺少必要字段，收到的字段: {list(data.keys())}")
            return jsonify({"error": "Missing required fields"}), 400
            
        # 1. 验证凭证
        logger.debug(f"开始验证凭证: {data['credential']}")
        if not credential_verifier.verify_credential(data['credential']):
            logger.error("凭证验证失败")
            return jsonify({"error": "Invalid credential"}), 403
            
        encrypted_vote = data['encrypted_vote']
        logger.debug(f"加密投票数据: {encrypted_vote}")
        
        if not all(k in encrypted_vote for k in ['ciphertext', 'zkp', 'weight_signature']):
            logger.error(f"无效的加密投票格式，缺少必要字段")
            return jsonify({"error": "Invalid encrypted vote format"}), 400
            
        # 2. 存储投票
        try:
            logger.debug("开始存储投票...")
            result = store_vote(
                ciphertext=encrypted_vote['ciphertext'],
                zkp=encrypted_vote['zkp'],
                weight_signature=encrypted_vote['weight_signature']
            )
            logger.debug(f"投票存储成功，结果: {result}")
            
            # 3. 记录审计日志
            audit_logger.log_vote_operation("submit", {
                "voter_id": data['voter_id'],
                "vote_index": result['index']
            })
            
            return jsonify({
                "success": True,
                "vote_index": result['index'],
                "merkle_proof": result['merkle_proof']
            })
            
        except Exception as e:
            logger.error(f"存储投票失败: {str(e)}", exc_info=True)
            return jsonify({"error": f"Failed to store vote: {str(e)}"}), 500
            
    except Exception as e:
        logger.error(f"处理投票请求失败: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/tally/result', methods=['GET'])
def get_tally_result():
    """获取计票结果"""
    try:
        result = tally_controller.tally_votes()
        
        # 记录审计日志
        audit_logger.log_tally_result(result)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verify/<int:vote_index>', methods=['GET'])
def verify_vote(vote_index):
    """验证投票"""
    result = verify_controller.verify_vote(vote_index)
    return jsonify(result)

if __name__ == '__main__':
    from backend.storage.vote_db import init_vote_db
    init_vote_db()  # 初始化投票数据库
    app.run(host='0.0.0.0', port=5002)