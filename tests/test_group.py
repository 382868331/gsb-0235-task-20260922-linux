"""群运算测试：独立穷举群表 + 与被测核心全量交叉比对。

期望值全部来自 tests/reference.py（独立枚举/教材公式），
被测核心只负责“被检查”，不参与产生期望值。
"""

from __future__ import annotations

import unittest

from ecc_teach import core

import reference as ref


class TestIndependentGroupTable(unittest.TestCase):
    """独立参考自身的穷举群公理证明（19^3 结合律等）。"""

    def test_exhaustive_group_axioms(self) -> None:
        notes = ref.exhaustive_group_checks()
        self.assertEqual(len(notes), 9)
        for note in notes:
            self.assertIsInstance(note, str)
            self.assertTrue(note)

    def test_independent_point_count(self) -> None:
        affine = ref.all_affine_points()
        self.assertEqual(len(affine), 18)
        # 逐点独立代入方程，确保枚举本身可信。
        for x, y in affine:
            self.assertEqual((y * y - (x ** 3 + 2 * x + 2)) % 17, 0)


class TestCoreAgainstGroupTable(unittest.TestCase):
    """把被测核心的每个结果与独立加法表逐项对照。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.elements, cls.table, cls.dlog = ref.build_group()

    def test_addition_table_all_pairs(self) -> None:
        for q in self.elements:
            for r in self.elements:
                self.assertEqual(
                    core.point_add(q, r),
                    self.table[(q, r)],
                    msg=f"point_add({q!r},{r!r})",
                )

    def test_double_matches_table(self) -> None:
        for q in self.elements:
            self.assertEqual(core.point_double(q), self.table[(q, q)])

    def test_scalar_mult_all_multiples(self) -> None:
        for q in self.elements:
            for k in range(0, ref.N):
                expected = self.elements[(self.dlog[q] * k) % ref.N]
                self.assertEqual(core.scalar_mult(k, q), expected, msg=f"{k}*{q!r}")

    def test_negation_all_points(self) -> None:
        for q in self.elements:
            nq = core.point_neg(q)
            if q is None:
                self.assertIsNone(nq)
            else:
                x, y = q
                self.assertEqual(nq, (x, (-y) % 17))
            self.assertEqual(self.table[(q, nq)], None)  # Q + (-Q) = O

    def test_generator_doubling_sequence(self) -> None:
        """固定序列 1G..19G（手写期望值取自独立枚举，硬编码）。"""
        hardcoded = [
            (5, 1), (6, 3), (10, 6), (3, 1), (9, 16),
            (16, 13), (0, 6), (13, 7), (7, 6), (7, 11),
            (13, 10), (0, 11), (16, 4), (9, 1), (3, 16),
            (10, 11), (6, 14), (5, 16), None,
        ]
        q = None
        for i, want in enumerate(hardcoded, start=1):
            q = core.point_add(q, core.GENERATOR)
            self.assertEqual(q, want, msg=f"{i}G")
        self.assertIsNone(q)

    def test_affine_point_count_matches_core_predicate(self) -> None:
        counted = [
            (x, y)
            for x in range(17)
            for y in range(17)
            if core.is_on_curve((x, y))
        ]
        self.assertEqual(counted, ref.all_affine_points())
        self.assertTrue(core.is_on_curve(None))

    def test_infinity_is_singleton_semantics(self) -> None:
        self.assertIsNone(core.point_add(None, None))
        self.assertIsNone(core.point_double(None))
        self.assertIsNone(core.scalar_mult(0, core.GENERATOR))
        self.assertIsNone(core.scalar_mult(19, core.GENERATOR))

    def test_point_ops_reject_invalid_inputs(self) -> None:
        bad_points = [(5, 2), (17, 1), (-1, 1), (5, 1, 0), ("5", 1), (5.0, 1.0), 7]
        for bad in bad_points:
            with self.subTest(bad=bad):
                with self.assertRaises((core.InvalidPointError, core.StrictTypeError)):
                    core.point_add(bad, core.GENERATOR)
                with self.assertRaises((core.InvalidPointError, core.StrictTypeError)):
                    core.point_add(core.GENERATOR, bad)
                with self.assertRaises((core.InvalidPointError, core.StrictTypeError)):
                    core.point_double(bad)
        # None 与非法点组合也必须报错，不能吞掉。
        with self.assertRaises(core.InvalidPointError):
            core.point_add(None, (5, 2))
        with self.assertRaises(core.InvalidPointError):
            core.point_add((5, 2), None)
        # 逆元对非法点同样报错。
        with self.assertRaises(core.InvalidPointError):
            core.point_neg((5, 2))


if __name__ == "__main__":
    unittest.main()
