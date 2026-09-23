"""压缩编码与严格输入契约的测试。

期望编码字节取自独立参考 reference.py；另含大量手写字节级非法用例：
非最短（前导零/多余后缀）、域外 x、错误奇偶、无穷远编码上下文。
"""

from __future__ import annotations

import math
import unittest

from ecc_teach import core
from ecc_teach.errors import (
    EncodingError,
    InvalidPointError,
    NonFiniteNumberError,
    StrictTypeError,
)

import reference as ref

ALL_POINTS = ref.all_affine_points()  # 18 个仿射点


class TestEncodingAgainstReference(unittest.TestCase):
    def test_encode_matches_reference_for_all_points(self) -> None:
        for pt in ALL_POINTS:
            self.assertEqual(core.encode_point(pt), ref.ref_encode(pt), msg=str(pt))

    def test_core_decode_matches_reference_for_all_points(self) -> None:
        for pt in ALL_POINTS:
            blob = ref.ref_encode(pt)
            self.assertEqual(core.decode_point(blob), pt)
            self.assertEqual(ref.ref_decode(blob), pt)

    def test_round_trip_is_only_supplement(self) -> None:
        # 往返一致仅作补充：真正的期望值来自 ref.ref_decode。
        for pt in ALL_POINTS:
            self.assertEqual(core.decode_point(core.encode_point(pt)), pt)

    def test_hardcoded_compression_bytes(self) -> None:
        # 手写期望，直接按“偶 y=0x02 / 奇 y=0x03 + 单字节 x”核对。
        self.assertEqual(core.encode_point((5, 1)), b"\x03\x05")    # y 奇
        self.assertEqual(core.encode_point((5, 16)), b"\x02\x05")  # y 偶
        self.assertEqual(core.encode_point((0, 6)), b"\x02\x00")
        self.assertEqual(core.encode_point((16, 4)), b"\x02\x10")  # x=16 -> 0x10

    def test_infinity_encoding_contexts(self) -> None:
        self.assertEqual(core.encode_point(None, allow_infinity=True), b"\x00")
        with self.assertRaises(InvalidPointError):
            core.encode_point(None)
        self.assertIsNone(core.decode_point(b"\x00", allow_infinity=True))
        with self.assertRaises(EncodingError):
            core.decode_point(b"\x00")  # 验签等默认上下文拒绝 O

    def test_flipped_parity_decodes_to_negation_point(self) -> None:
        """本曲线的关键事实：三次式在 F17 上无根（不存在 y=0 的点），
        每个有解 x 的两个根互为 ±y 且奇偶相反。因此“错误奇偶”前缀不是
        非法字节，而是唯一地解码成逆点——被测与独立参考必须一致。"""
        # 逐点验证：翻转奇偶位 <=> point_neg，且两边实现结论相同。
        for pt in ALL_POINTS:
            enc = core.encode_point(pt)
            flipped = bytes([0x03 if enc[0] == 0x02 else 0x02, enc[1]])
            got = core.decode_point(flipped)
            self.assertEqual(got, core.point_neg(pt), msg=str(pt))
            self.assertEqual(got, ref.ref_decode(flipped))
        # 手写代表值。
        self.assertEqual(core.decode_point(b"\x02\x05"), (5, 16))
        self.assertEqual(core.decode_point(b"\x03\x05"), (5, 1))
        self.assertEqual(core.point_neg((5, 1)), (5, 16))

    def test_no_singleton_root_x_exists(self) -> None:
        """独立证明：F17 上不存在 y=0 的曲线点（故奇偶两前缀对每个有解 x 都有点）。"""
        self.assertTrue(all(y != 0 for _, y in ALL_POINTS))
        # 每个出现过的 x 都恰好有两个点（奇偶各一）。
        xs = {x for x, _ in ALL_POINTS}
        for x in xs:
            ys = [y for xx, y in ALL_POINTS if xx == x]
            self.assertEqual(len(ys), 2)
            self.assertEqual({y % 2 for y in ys}, {0, 1})
        # 其余 8 个 x 完全无点（rhs 为非二次剩余）。
        self.assertEqual(set(range(17)) - xs, {1, 2, 4, 8, 11, 12, 14, 15})

    def test_non_minimal_and_out_of_domain_bytes(self) -> None:
        bad_inputs = [
            b"",                 # 空
            b"\x02",             # 截断
            b"\x01\x05",         # 非法前缀
            b"\x04\x05",         # 非法前缀
            b"\x02\x11",         # x=17 域外
            b"\x02\xff",         # x=255 域外
            b"\x02\x05\x00",     # 多余后缀 -> 非最短
            b"\x00\x05",         # 0x00 + 尾巴（非无穷远单字节，也非仿射编码）
            b"\x02\x00\x05",     # 前导多余字节 -> 非最短
            b"\x03\x05\x00",     # 合法两字节后加零 -> 非最短
            b"\x02" * 0,         # 空串重复情形
        ]
        for blob in bad_inputs:
            with self.subTest(blob=blob):
                with self.assertRaises(EncodingError):
                    core.decode_point(blob)
                with self.assertRaises(ValueError):
                    ref.ref_decode(blob)  # 独立参考同样拒绝

    def test_x_with_no_curve_point(self) -> None:
        # x=1 时 rhs=1+2+2=5，5 是 F17 的非二次剩余（独立验证）。
        self.assertNotIn(1, {x for x, _ in ALL_POINTS})
        with self.assertRaises(EncodingError):
            core.decode_point(b"\x02\x01")

    def test_decode_type_must_be_exact_bytes(self) -> None:
        for bad in ("\x03\x05", bytearray(b"\x03\x05"), memoryview(b"\x03\x05"), None, 0x305):
            with self.subTest(bad=bad):
                with self.assertRaises(EncodingError):
                    core.decode_point(bad)

    def test_encode_rejects_off_curve_and_bad_structures(self) -> None:
        with self.assertRaises(InvalidPointError):
            core.encode_point((5, 2))          # 不在曲线
        with self.assertRaises(InvalidPointError):
            core.encode_point((17, 1))         # 坐标越界
        with self.assertRaises(InvalidPointError):
            core.encode_point((5, 1, 0))       # 结构错误
        with self.assertRaises(InvalidPointError):
            core.encode_point(("5", 1))        # 坐标类型错误


class TestStrictInputs(unittest.TestCase):
    def test_bool_rejected_as_int(self) -> None:
        with self.assertRaises(StrictTypeError):
            core.scalar_mult(True, core.GENERATOR)
        with self.assertRaises(StrictTypeError):
            core.scalar_mult(False, core.GENERATOR)
        with self.assertRaises(StrictTypeError):
            core.derive_public_key(True)

    def test_float_nan_and_infinity(self) -> None:
        with self.assertRaises(NonFiniteNumberError):
            core.scalar_mult(float("nan"), core.GENERATOR)
        with self.assertRaises(NonFiniteNumberError):
            core.scalar_mult(float("inf"), core.GENERATOR)
        with self.assertRaises(NonFiniteNumberError):
            core.scalar_mult(float("-inf"), core.GENERATOR)

    def test_finite_float_still_type_error(self) -> None:
        with self.assertRaises(StrictTypeError):
            core.scalar_mult(1.0, core.GENERATOR)
        with self.assertRaises(StrictTypeError):
            core.scalar_mult(19.0, core.GENERATOR)

    def test_other_types_rejected(self) -> None:
        with self.assertRaises(StrictTypeError):
            core.scalar_mult("19", core.GENERATOR)
        with self.assertRaises(StrictTypeError):
            core.scalar_mult(complex(1, 0), core.GENERATOR)
        with self.assertRaises(InvalidPointError):
            core.point_add((5.0, 1.0), core.GENERATOR)

    def test_negative_and_out_of_range_scalars(self) -> None:
        with self.assertRaises(ValueError):
            core.scalar_mult(-1, core.GENERATOR)
        with self.assertRaises(ValueError):
            core.derive_public_key(0)
        with self.assertRaises(ValueError):
            core.derive_public_key(19)
        with self.assertRaises(ValueError):
            core.sign_scalar(1, b"m", 0)
        with self.assertRaises(ValueError):
            core.sign_scalar(1, b"m", 19)

    def test_message_must_be_bytes_and_bounded(self) -> None:
        sig = core.sign_scalar(3, b"abc", 5)
        with self.assertRaises(StrictTypeError):
            core.verify_signature(core.derive_public_key(3), "abc", sig)
        with self.assertRaises(StrictTypeError):
            core.verify_signature(core.derive_public_key(3), bytearray(b"abc"), sig)
        with self.assertRaises(core.MessageTooLongError):
            big = b"x" * (core.MAX_MESSAGE_BYTES + 1)
            core.sign_scalar(3, big, 5)
        # 上限边界本身合法。
        ok = core.sign_scalar(3, b"x" * core.MAX_MESSAGE_BYTES, 5)
        self.assertTrue(
            core.is_signature_valid(
                core.derive_public_key(3), b"x" * core.MAX_MESSAGE_BYTES, ok
            )
        )

    def test_no_nan_check_via_math_module(self) -> None:
        # 固定 NaN 位模式，防止环境差异；确保 NaN 不被误当有限值。
        nan = math.nan
        self.assertTrue(math.isnan(nan))
        with self.assertRaises(NonFiniteNumberError):
            core._check_exact_int(nan, "probe")  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
