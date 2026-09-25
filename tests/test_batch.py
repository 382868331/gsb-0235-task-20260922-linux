"""教学批验签测试：聚合/逐项语义分离、抵消反例、严格解码、加法计数对比。"""

import unittest

import ec17
from ec17 import (
    BatchEntry,
    BatchItemError,
    InvalidCoefficientError,
    BatchLengthMismatchError,
    TypeValidationError,
    batch_verify,
    batch_verify_encoded,
    bisect_aggregate_candidates,
)

import reference


def make_valid(secret_key, nonce, message):
    """用被测库签名接口造一条合法记录（合法输入的构造不属于期望值来源）。"""
    public_key = ec17.derive_public_key(secret_key)
    sig = ec17.sign(secret_key, message, nonce)
    return BatchEntry(message, public_key, sig.r, sig.s)


def make_cancellation_pair():
    """构造两条各自无效、但缺陷互为相反数（系数 (1,1) 下聚合抵消）的签名。

    缺陷 d_i = (s_i' - s_i)·G；取 t1=+1、t2=-1 使 d1 + d2 = O。
    用独立参考实现核对两条签名确实各自无效。
    """
    msg1, msg2 = b"cancel-a", b"cancel-b"
    e1 = make_valid(3, 5, msg1)
    e2 = make_valid(11, 7, msg2)
    t1 = 1 if e1.s + 1 < 19 else -1
    t2 = -t1 if 0 <= e2.s - t1 else t1
    bad1 = BatchEntry(msg1, e1.public_key, e1.r, (e1.s + t1) % 19)
    bad2 = BatchEntry(msg2, e2.public_key, e2.r, (e2.s + t2) % 19)
    # 独立参考确认：两条都无效，且缺陷指数之和 ≡ 0 (mod 19)
    assert not reference.ref_verify(msg1, bad1.public_key, bad1.r, bad1.s)
    assert not reference.ref_verify(msg2, bad2.public_key, bad2.r, bad2.s)
    assert (t1 + t2) % 19 == 0
    return bad1, bad2


class TestBatchVerifyValid(unittest.TestCase):
    def test_all_valid_exact(self):
        entries = [
            make_valid(3, 5, b"m0"),
            make_valid(7, 13, b"m1"),
            make_valid(18, 1, b""),
        ]
        report = batch_verify(entries, [1, 2, 3], exact=True)
        self.assertTrue(report.aggregate_ok)
        self.assertTrue(report.all_valid)
        self.assertEqual(report.invalid_indices, ())
        self.assertEqual(report.size, 3)

    def test_non_exact_leaves_all_valid_unknown(self):
        entries = [make_valid(3, 5, b"m0")]
        report = batch_verify(entries, [1])
        self.assertTrue(report.aggregate_ok)
        self.assertIsNone(report.all_valid)
        self.assertIsNone(report.invalid_indices)

    def test_empty_batch_is_valid(self):
        report = batch_verify([], [], exact=True)
        self.assertTrue(report.aggregate_ok)
        self.assertTrue(report.all_valid)
        self.assertEqual(report.invalid_indices, ())
        self.assertEqual(report.point_additions, 0)

    def test_tuple_entries_accepted(self):
        e = make_valid(3, 5, b"m0")
        report = batch_verify([(e.message, e.public_key, e.r, e.s)], [1], exact=True)
        self.assertTrue(report.all_valid)


class TestCancellationCounterexample(unittest.TestCase):
    """必测反例：两条单独无效但聚合抵消的签名。"""

    def test_aggregate_passes_but_exact_catches_both(self):
        bad1, bad2 = make_cancellation_pair()
        report = batch_verify([bad1, bad2], [1, 1], exact=True)
        # 聚合等式通过 —— 这不是安全结论
        self.assertTrue(report.aggregate_ok)
        # exact 逐项确认：两条都无效，按输入序报告
        self.assertFalse(report.all_valid)
        self.assertEqual(report.invalid_indices, (0, 1))

    def test_aggregate_only_mode_would_be_misleading(self):
        bad1, bad2 = make_cancellation_pair()
        report = batch_verify([bad1, bad2], [1, 1])
        self.assertTrue(report.aggregate_ok)
        self.assertIsNone(report.all_valid)  # 非 exact 不得声称全部有效

    def test_exact_checks_passing_subgroups_too(self):
        # 抵消对藏在“聚合通过”的完整批次里，exact 仍须逐项发现
        bad1, bad2 = make_cancellation_pair()
        good = make_valid(7, 13, b"good")
        report = batch_verify([good, bad1, bad2], [1, 1, 1], exact=True)
        self.assertTrue(report.aggregate_ok)
        self.assertEqual(report.invalid_indices, (1, 2))

    def test_single_invalid_breaks_aggregate(self):
        bad1, _ = make_cancellation_pair()
        report = batch_verify([bad1], [1], exact=True)
        self.assertFalse(report.aggregate_ok)
        self.assertEqual(report.invalid_indices, (0,))


class TestStrictRejection(unittest.TestCase):
    def test_illegal_structure_rejects_whole_batch_with_index(self):
        entries = [make_valid(3, 5, b"m0"), BatchEntry(b"m1", (5, 1), (0, 0), 3)]
        with self.assertRaises(BatchItemError) as ctx:
            batch_verify(entries, [1, 1])
        self.assertEqual(ctx.exception.index, 1)

    def test_illegal_encoding_rejects_whole_batch_with_index(self):
        good = make_valid(3, 5, b"m0")
        enc_good = (
            good.message,
            ec17.encode_point(good.public_key),
            ec17.encode_point(good.r),
            ec17.encode_scalar(good.s),
        )
        bad_enc = (b"m1", b"\x02", ec17.encode_point(good.r), b"\x03")  # x=17 域外
        with self.assertRaises(BatchItemError) as ctx:
            batch_verify_encoded([enc_good, bad_enc], [1, 1])
        self.assertEqual(ctx.exception.index, 1)

    def test_encoded_roundtrip_valid(self):
        entries = [make_valid(3, 5, b"m0"), make_valid(7, 13, b"m1")]
        enc = [
            (e.message, ec17.encode_point(e.public_key), ec17.encode_point(e.r),
             ec17.encode_scalar(e.s))
            for e in entries
        ]
        report = batch_verify_encoded(enc, [1, 2], exact=True)
        self.assertTrue(report.all_valid)

    def test_zero_coefficient_rejected(self):
        entries = [make_valid(3, 5, b"m0")]
        with self.assertRaises(InvalidCoefficientError):
            batch_verify(entries, [0])

    def test_coefficient_out_of_domain_rejected(self):
        entries = [make_valid(3, 5, b"m0")]
        with self.assertRaises(InvalidCoefficientError):
            batch_verify(entries, [19])

    def test_coefficient_length_mismatch(self):
        entries = [make_valid(3, 5, b"m0")]
        with self.assertRaises(BatchLengthMismatchError):
            batch_verify(entries, [1, 1])

    def test_bool_coefficient_rejected(self):
        entries = [make_valid(3, 5, b"m0")]
        with self.assertRaises(TypeValidationError):
            batch_verify(entries, [True])


class TestBisect(unittest.TestCase):
    def test_bisect_narrows_single_failure(self):
        entries = [make_valid(3, 5, b"m0"), make_valid(7, 13, b"m1"),
                   make_valid(11, 2, b"m2"), make_valid(1, 18, b"m3")]
        bad = BatchEntry(b"m2", entries[2].public_key, entries[2].r,
                         (entries[2].s + 1) % 19)
        entries[2] = bad
        candidates = bisect_aggregate_candidates(entries, [1, 1, 1, 1])
        self.assertEqual(candidates, (2,))

    def test_bisect_on_cancellation_pair_cannot_narrow(self):
        # 整批聚合通过时二分无候选；若人为拆出失败批又遇跨半抵消，则整组都是候选
        bad1, bad2 = make_cancellation_pair()
        good = make_valid(7, 13, b"good")
        # 整批（含抵消对）聚合通过 → 无候选，但 exact 知道有两项无效
        self.assertEqual(bisect_aggregate_candidates([good, bad1, bad2], [1, 1, 1]), ())
        report = batch_verify([good, bad1, bad2], [1, 1, 1], exact=True)
        self.assertEqual(report.invalid_indices, (1, 2))


class TestPointAdditionCount(unittest.TestCase):
    def test_shared_tables_beat_naive_repeated_verify(self):
        # 多条目共享少数公钥时，共享倍点表摊销后加法次数低于逐项 verify
        keys = (3, 7, 11)
        entries = [
            make_valid(keys[i % 3], (i % 18) + 1, f"m{i}".encode())
            for i in range(36)
        ]
        report = batch_verify(entries, [(i % 18) + 1 for i in range(36)], exact=True)
        self.assertTrue(report.all_valid)

        # 朴素路线：逐项调用 ec17.verify，统计真实群加法次数
        import ec17._curve as curve_mod
        import ec17._schnorr as schnorr_mod

        counter = {"n": 0}
        real_add = curve_mod.point_add

        def counting_add(p, q):
            counter["n"] += 1
            return real_add(p, q)

        try:
            curve_mod.point_add = counting_add
            schnorr_mod.point_add = counting_add
            for e in entries:
                self.assertTrue(ec17.verify(e.message, e.public_key, e.r, e.s))
        finally:
            curve_mod.point_add = real_add
            schnorr_mod.point_add = real_add

        naive = counter["n"]
        self.assertGreater(naive, 0)
        self.assertLess(report.point_additions, naive)


if __name__ == "__main__":
    unittest.main()
