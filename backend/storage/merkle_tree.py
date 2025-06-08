import hashlib
from typing import List


def sha256(data: bytes) -> str:
    """对数据进行 SHA256 哈希"""
    return hashlib.sha256(data).hexdigest()


class MerkleTree:
    def __init__(self, leaves: List[str]):
        """
        初始化 Merkle 树
        :param leaves: 原始数据列表，每个元素为已哈希（或需哈希）字符串
        """
        self.leaves = [sha256(leaf.encode()) for leaf in leaves]
        self.levels = []
        if self.leaves:
            self.build_tree()

    def build_tree(self):
        """构建 Merkle 树结构，保存在 levels 中"""
        current_level = self.leaves
        self.levels.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left  # 如果是奇数个节点，重复最后一个
                combined = sha256((left + right).encode())
                next_level.append(combined)
            current_level = next_level
            self.levels.append(current_level)

    def get_root(self) -> str:
        """获取 Merkle 根（根哈希）"""
        if not self.levels:
            return ""
        return self.levels[-1][0]

    def get_proof(self, index: int) -> List[tuple]:
        """
        获取给定索引叶子节点的 Merkle Proof
        :return: [(sibling_hash, is_left)]
        """
        proof = []
        for level in self.levels[:-1]:
            level_len = len(level)
            is_right_node = index % 2
            sibling_index = index - 1 if is_right_node else index + 1

            if sibling_index >= level_len:
                sibling_hash = level[index]  # 重复节点
            else:
                sibling_hash = level[sibling_index]

            proof.append((sibling_hash, not is_right_node))
            index = index // 2
        return proof

    @staticmethod
    def verify_proof(leaf: str, proof: List[tuple], root: str) -> bool:
        """
        验证某叶子节点的 Merkle Proof 是否对应某个 Merkle 根
        :param leaf: 原始数据（字符串）
        :param proof: [(sibling_hash, is_left)]
        :param root: Merkle 根
        """
        current_hash = sha256(leaf.encode())
        for sibling_hash, is_left in proof:
            if is_left:
                current_hash = sha256((sibling_hash + current_hash).encode())
            else:
                current_hash = sha256((current_hash + sibling_hash).encode())
        return current_hash == root
