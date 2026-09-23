"""独立参考的隔离性测试：reference.py 不得 import 被测核心 ec17。

用 AST 精确检查真实导入语句（而非子串匹配，避免误判文档字符串），
并扫描源码文本中可能的动态加载（importlib / __import__）。
往返一致只允许作为补充，期望值来源始终是 reference。
"""

import ast
import pathlib
import unittest

import reference

HERE = pathlib.Path(__file__).resolve().parent
REF_PATH = HERE / "reference.py"
REF_SOURCE = REF_PATH.read_text(encoding="utf-8")


def imported_module_names(source):
    tree = ast.parse(source)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


class ReferenceIndependenceTests(unittest.TestCase):
    def test_reference_module_does_not_link_ec17(self):
        self.assertFalse(
            hasattr(reference, "ec17"),
            "reference 模块运行后不应持有 ec17 引用",
        )

    def test_reference_imports_neither_ec17_nor_dynamic_loaders(self):
        names = imported_module_names(REF_SOURCE)
        self.assertTrue(names, "reference.py 至少应导入 hashlib")
        self.assertEqual(
            {n for n in names if n.split(".")[0] != "hashlib"},
            set(),
            f"参考实现只允许标准库 hashlib，发现：{sorted(names)}",
        )
        for token in ("__import__", "importlib"):
            self.assertNotIn(token, REF_SOURCE, f"reference.py 中禁止出现 {token!r}")


if __name__ == "__main__":
    unittest.main()
