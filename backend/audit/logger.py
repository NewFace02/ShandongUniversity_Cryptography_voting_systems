from typing import Dict
import json
import os
from datetime import datetime

class AuditLogger:
    def __init__(self):
        self.log_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        
    def log_tally_result(self, result: Dict):
        """记录计票结果"""
        timestamp = datetime.now().isoformat()
        log_file = os.path.join(self.log_dir, f"tally_{timestamp}.json")
        
        audit_data = {
            "timestamp": timestamp,
            "total_votes": result["total_votes"],
            "total_weight": result["total_weight"],
            "result": result["result"],
            "proof": result["proof"],
            "merkle_root": result.get("merkle_root")
        }
        
        with open(log_file, "w") as f:
            json.dump(audit_data, f, indent=2)
            
        return log_file
    
    def log_vote_operation(self, operation: str, vote_data: Dict):
        """记录投票操作
        
        Args:
            operation: 操作类型 ("submit", "verify", etc.)
            vote_data: 投票相关数据
        """
        timestamp = datetime.now().isoformat()
        log_file = os.path.join(self.log_dir, f"vote_{operation}_{timestamp}.json")
        
        audit_data = {
            "timestamp": timestamp,
            "operation": operation,
            "voter_id": vote_data.get("voter_id"),
            "vote_index": vote_data.get("vote_index"),
            "status": "success"
        }
        
        with open(log_file, "w") as f:
            json.dump(audit_data, f, indent=2)