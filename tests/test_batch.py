"""批验签测试：严格解码、聚合/逐项语义区分、抵消反例、缓存与计数。"""

import unittest

import ec17
from ec17._batch import _MULTIPLES_CACHE

import reference  # 独立参考实现（不 import ec17）


def make_entry(secret_key, message, nonce):
    public_key = ec17.derive_public_key(secret_key)
    sig = ec17.sign(secret_key, message, nonce)
    return ec17.BatchEntry(message, public_key, sig.r, sig.s)


def encoded_entry(entry):
    return (
        entry.message,
        ec17.encode_point(entry.public_key),
        ec17.encode_point(entry.r),
        ec17.encode_scalar(entry.s),
    )


class BatchVerifyTest(unittest.TestCase):
    def setUp(self):
        ec17.clear_multiples_cache()
        ec17.reset_point_add_counter()

    def test_empty_batch_is_valid(self):
        report = ec17.batch_verify([], [], exact=True)
        self.assertTrue(report.aggregate_ok)
        self.assertTrue(report.all_valid)
        self.assertEqual(report.invalid_indices, ())
        self.assertEqual(report.item_count, 0)

    def test_all_valid_batch(self):
        entries = [make_entry(sk, b"msg-%d" % sk, nonce)
                   for sk, nonce in [(7, 13), (5, 4), (11, 9)]]
        report = ec17.batch_verify(entries, [3, 5, 7], exact=True)
        self.assertTrue(report.aggregate_ok)
        self.assertTrue(report.all_valid)
        self.assertEqual(report.invalid_indices, ())

    def test_aggregate_only_report_has_no_exact_fields(self):
        entries = [make_entry(7, b"m", 13)]
        report = ec17.batch_verify(entries, [1])
        self.assertTrue(report.aggregate_ok)
        self.assertFalse(report.exact)
        self.assertIsNone(report.all_valid)
        self.assertIsNone(report.invalid_indices)

    def test_single_invalid_located(self):
        good = make_entry(7, b"m1", 13)
        bad_sig = ec17.sign(5, b"m2", 4)
        bad = ec17.BatchEntry(b"m2", ec17.derive_public_key(5),
                              bad_sig.r, (bad_sig.s + 1) % 19)
        report = ec17.batch_verify([good, bad], [1, 1], exact=True)
        self.assertFalse(report.all_valid)
        self.assertEqual(report.invalid_indices, (1,))

    def test_canceling_pair_aggregate_passes_but_exact_catches(self):
        # 必测反例：两个单独无效、但加权误差互相抵消的签名。
        sig1 = ec17.sign(7, b"cancel-a", 13)
        sig2 = ec17.sign(5, b"cancel-b", 4)
        bad1 = ec17.BatchEntry(b"cancel-a", ec17.derive_public_key(7),
                               sig1.r, (sig1.s + 1) % 19)   # 误差 +1
        bad2 = ec17.BatchEntry(b"cancel-b", ec17.derive_public_key(5),
                               sig2.r, (sig2.s - 1) % 19)   # 误差 -1
        # 独立逐项验签对照：两个都无效。
        for entry in (bad1, bad2):
            self.assertFalse(
                ec17.verify(entry.message, entry.public_key, entry.r, entry.s))
            self.assertFalse(
                reference.ref_verify(entry.message, entry.public_key,
                                     entry.r, entry.s))
        report = ec17.batch_verify([bad1, bad2], [1, 1], exact=True)
        # 聚合等式通过（抵消），但报告必须区分：逐项并非全部有效。
        self.assertTrue(report.aggregate_ok)
        self.assertFalse(report.all_valid)
        self.assertEqual(report.invalid_indices, (0, 1))

    def test_canceling_pair_with_nontrivial_coefficients(self):
        # 2*(+1) + 1*(-2) == 0 (mod 19)，系数 2 与 1。
        sig1 = ec17.sign(3, b"w1", 2)
        sig2 = ec17.sign(4, b"w2", 6)
        bad1 = ec17.BatchEntry(b"w1", ec17.derive_public_key(3),
                               sig1.r, (sig1.s + 1) % 19)
        bad2 = ec17.BatchEntry(b"w2", ec17.derive_public_key(4),
                               sig2.r, (sig2.s - 2) % 19)
        report = ec17.batch_verify([bad1, bad2], [2, 1], exact=True)
        self.assertTrue(report.aggregate_ok)
        self.assertEqual(report.invalid_indices, (0, 1))

    def test_exact_matches_reference_per_item(self):
        entries = []
        for sk, nonce, tamper in [(7, 13, 0), (5, 4, 1), (11, 9, 0), (2, 3, -1)]:
            sig = ec17.sign(sk, b"batch-%d" % sk, nonce)
            entries.append(ec17.BatchEntry(
                b"batch-%d" % sk, ec17.derive_public_key(sk),
                sig.r, (sig.s + tamper) % 19))
        report = ec17.batch_verify(entries, [1, 2, 3, 4], exact=True)
        expected = tuple(
            i for i, e in enumerate(entries)
            if not reference.ref_verify(e.message, e.public_key, e.r, e.s))
        self.assertEqual(report.invalid_indices, expected)
        self.assertEqual(report.all_valid, not expected)

    def test_invalid_encoding_rejects_whole_batch_with_index(self):
        good = make_entry(7, b"m1", 13)
        entries = [encoded_entry(good),
                   (b"m2", b"\x02\x11", b"\x02\x05", b"\x03"),  # x=17 域外
                   encoded_entry(make_entry(5, b"m3", 4))]
        with self.assertRaises(ec17.BatchItemError) as ctx:
            ec17.batch_verify_encoded(entries, [1, 1, 1])
        self.assertEqual(ctx.exception.index, 1)
        self.assertIsInstance(ctx.exception.__cause__,
                              ec17.OutOfDomainEncodingError)

    def test_non_shortest_encoding_rejected_with_index(self):
        good = encoded_entry(make_entry(7, b"m1", 13))
        bloated = (b"m2", b"\x02\x05\x00", b"\x02\x05", b"\x03")
        with self.assertRaises(ec17.BatchItemError) as ctx:
            ec17.batch_verify_encoded([good, bloated], [1, 1])
        self.assertEqual(ctx.exception.index, 1)

    def test_scalar_out_of_range_rejected_with_index(self):
        good = encoded_entry(make_entry(7, b"m1", 13))
        bad = (b"m2", ec17.encode_point(ec17.derive_public_key(5)),
               ec17.encode_point(ec17.sign(5, b"m2", 4).r), b"\x13")  # s=19
        with self.assertRaises(ec17.BatchItemError) as ctx:
            ec17.batch_verify_encoded([good, bad], [1, 1])
        self.assertEqual(ctx.exception.index, 1)

    def test_structural_error_in_object_entry_has_index(self):
        good = make_entry(7, b"m1", 13)
        off_curve = ec17.BatchEntry(b"m2", (0, 0), good.r, 3)
        with self.assertRaises(ec17.BatchItemError) as ctx:
            ec17.batch_verify([good, off_curve], [1, 1])
        self.assertEqual(ctx.exception.index, 1)

    def test_coefficient_validation(self):
        entries = [make_entry(7, b"m1", 13)]
        with self.assertRaises(ec17.InvalidCoefficientError):
            ec17.batch_verify(entries, [0])          # 0 被禁止
        with self.assertRaises(ec17.InvalidCoefficientError):
            ec17.batch_verify(entries, [19])         # 域外
        with self.assertRaises(ec17.InvalidCoefficientError):
            ec17.batch_verify(entries, [1, 1])       # 数量不符
        with self.assertRaises(ec17.InvalidCoefficientError):
            ec17.batch_verify(entries, [True])       # bool 拒绝
        with self.assertRaises(ec17.InvalidCoefficientError):
            ec17.batch_verify(entries, [1.0])        # float 拒绝

    def test_cache_only_stores_public_point_multiples(self):
        entries = [make_entry(7, b"cache-a", 13), make_entry(5, b"cache-b", 4)]
        ec17.batch_verify(entries, [1, 1], exact=True)
        self.assertTrue(_MULTIPLES_CACHE)
        for key, table in _MULTIPLES_CACHE.items():
            # 键只能是公开点（G/公钥/承诺 R），不能是消息或质询。
            self.assertIsInstance(key, tuple)
            self.assertTrue(ec17.is_on_curve(key))
            self.assertEqual(len(table), ec17.GROUP_ORDER)
        # 质询不缓存：同公钥不同消息各自现场重算 e 并正确验签。
        again = [make_entry(7, b"cache-c", 13), make_entry(7, b"cache-d", 13)]
        report = ec17.batch_verify(again, [1, 1], exact=True)
        self.assertTrue(report.all_valid)

    def test_exact_batch_uses_fewer_point_adds_than_repeated_verify(self):
        # 24 项、2 个公钥：共享倍点表摊销后，点加次数必须少于逐项 verify。
        entries = []
        for i in range(24):
            sk = 7 if i % 2 == 0 else 5
            entries.append(make_entry(sk, b"count-%d" % i, (i % 18) + 1))
        coeffs = [(i % 18) + 1 for i in range(24)]

        ec17.clear_multiples_cache()
        ec17.reset_point_add_counter()
        report = ec17.batch_verify(entries, coeffs, exact=True)
        self.assertTrue(report.all_valid)
        batch_adds = ec17.point_add_count()

        ec17.reset_point_add_counter()
        for e in entries:
            self.assertTrue(ec17.verify(e.message, e.public_key, e.r, e.s))
        repeated_adds = ec17.point_add_count()

        self.assertLess(batch_adds, repeated_adds)

    def test_exact_must_check_passing_subgroups_too(self):
        # 抵消对藏在“聚合通过”的整体里：exact 不允许只查失败子组。
        sig1 = ec17.sign(7, b"hide-a", 13)
        sig2 = ec17.sign(5, b"hide-b", 4)
        good = make_entry(11, b"hide-c", 9)
        bad1 = ec17.BatchEntry(b"hide-a", ec17.derive_public_key(7),
                               sig1.r, (sig1.s + 1) % 19)
        bad2 = ec17.BatchEntry(b"hide-b", ec17.derive_public_key(5),
                               sig2.r, (sig2.s - 1) % 19)
        report = ec17.batch_verify([good, bad1, bad2], [1, 1, 1], exact=True)
        self.assertTrue(report.aggregate_ok)
        self.assertEqual(report.invalid_indices, (1, 2))


if __name__ == "__main__":
    unittest.main()
