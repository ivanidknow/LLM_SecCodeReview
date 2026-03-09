import os
import re

class ProtocolParser:
    def __init__(self, base_path: str):
        self.base_path = base_path

    def parse_file(self, file_path: str):
        """Парсит .protocol файл и извлекает метаданные и контент"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Извлечение метаданных через регулярные выражения
            id_match = re.search(r'@ID:\s*([^\n\r]*)', content)
            goal_match = re.search(r'@GOAL:\s*([^\n\r]*)', content)

            return {
                "id": id_match.group(1).strip() if id_match else os.path.basename(file_path),
                "goal": goal_match.group(1).strip() if goal_match else "No goal defined",
                "content": content,
                "file_path": file_path,
                "category": os.path.basename(os.path.dirname(file_path))
            }
        except Exception as e:
            return {"id": "Error", "goal": str(e), "content": ""}

    def get_methodology_tree(self):
        """Собирает дерево всех протоколов по папкам"""
        tree = {}
        if not os.path.exists(self.base_path):
            return tree

        for root, _, files in os.walk(self.base_path):
            rel_path = os.path.relpath(root, self.base_path)
            if rel_path == "." or rel_path.startswith("__"):
                continue

            protocols = []
            for file in files:
                if file.endswith(".protocol"):
                    protocols.append(self.parse_file(os.path.join(root, file)))
            
            if protocols:
                tree[rel_path] = protocols
        return tree