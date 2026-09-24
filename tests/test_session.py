"""有状态签名会话（会话 ID + nonce 生命周期）测试。

期望值来源：
  - 所有签名 (R, s, e) 仍由独立参考 reference.py 的 ``ref_sign`` 给出，
    **不**用被测的 SigningSession 或 ec17.sign 生成期望值；
  - nonce 重用导致私钥泄露这一事实，用解析关系
    sk ≡ (s1-s2)·(e1-e2)^{-1} (mod 19) 直接核算，不依赖被测实现；
  - 幂等/阶段乱序/作废等只检查协议规定的状态与异常类型。
"""

import unittest
from unittest import mock

import ec17
from reference import ORDER, ref_sign, ref_verify, ref_challenge

SID = b"session-A"
MSG = b"ec17-session-teaching"
SK = 7
K = 13


def make_session(session_id=SID, secret_key=SK):
    return ec17.SigningSession(session_id, secret_key)


class HappyPathTests(unittest.TestCase):
    def test_reserve_then_sign_matches_reference(self):
        session = make_session()
        self.assertEqual(session.session_id, SID)
        self.assertEqual(session.public_key, ec17.derive_public_key(SK))
        self.assertTrue(session.reserve_nonce(K, MSG))
        self.assertEqual(session.nonce_status(K), "reserved")
        self.assertEqual(session.reserved_nonces(), [K])
        self.assertEqual(session.nonce_message(K), MSG)

        sig = session.sign(MSG, K)
        pub, r_point, e_val, s_val = ref_sign(SK, MSG, K)
        self.assertEqual((sig.r, sig.s), (r_point, s_val))
        self.assertEqual(session.nonce_status(K), "used")
        self.assertEqual(session.used_nonces(), [K])
        self.assertEqual(session.reserved_nonces(), [])
        # 会话层产出的签名仍能被原有无状态验签接受。
        self.assertTrue(ec17.verify(MSG, pub, sig.r, sig.s))
        self.assertTrue(ref_verify(MSG, pub, sig.r, sig.s))
        self.assertEqual(ec17.challenge(sig.r, pub, MSG), e_val)
        self.assertIs(session.signature_for(K), sig)

    def test_all_18_nonces_round_trip_against_reference(self):
        session = make_session()
        for nonce in range(1, ORDER):
            message = b"msg-for-nonce-" + bytes((nonce,))
            self.assertTrue(session.reserve_nonce(nonce, message))
            sig = session.sign(message, nonce)
            _pub, r_point, _e, s_val = ref_sign(SK, message, nonce)
            self.assertEqual((sig.r, sig.s), (r_point, s_val), nonce)
        self.assertEqual(session.used_nonces(), list(range(1, ORDER)))
        self.assertEqual(session.reserved_nonces(), [])
        self.assertEqual(session.voided_nonces(), [])

    def test_empty_message_boundary_is_supported(self):
        session = make_session()
        session.reserve_nonce(K, b"")
        sig = session.sign(b"", K)
        _pub, r_point, _e, s_val = ref_sign(SK, b"", K)
        self.assertEqual((sig.r, sig.s), (r_point, s_val))

    def test_session_id_length_boundary(self):
        longest = b"s" * ec17.MAX_SESSION_ID_BYTES
        session = make_session(session_id=longest)
        self.assertEqual(session.session_id, longest)
        session.reserve_nonce(K, MSG)
        self.assertEqual(session.nonce_status(K), "reserved")

    def test_bytearray_session_id_normalized_to_bytes(self):
        session = make_session(session_id=bytearray(b"sid-bytes"))
        self.assertEqual(session.session_id, b"sid-bytes")
        self.assertIsInstance(session.session_id, bytes)


class IdempotencyTests(unittest.TestCase):
    def test_duplicate_sign_request_returns_same_signature(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        first = session.sign(MSG, K)
        second = session.sign(MSG, K)
        third = session.sign(bytearray(MSG), K)  # 等长同内容字节也算同一请求
        self.assertIs(first, second)
        self.assertIs(first, third)
        self.assertEqual(session.used_nonces(), [K])

    def test_idempotent_reserve_same_pair_is_noop(self):
        session = make_session()
        self.assertTrue(session.reserve_nonce(K, MSG))
        # 重复预留同一 (nonce, message)：幂等 no-op，返回 False，状态不变。
        self.assertFalse(session.reserve_nonce(K, MSG))
        self.assertEqual(session.nonce_status(K), "reserved")
        sig = session.sign(MSG, K)
        _pub, r_point, _e, s_val = ref_sign(SK, MSG, K)
        self.assertEqual((sig.r, sig.s), (r_point, s_val))

    def test_repeated_requests_after_failed_attempt_keep_working(self):
        # 一次“坏请求”（消息类型错）被拒后，同一合法请求仍可重复成功。
        session = make_session()
        session.reserve_nonce(K, MSG)
        with self.assertRaises(ec17.MessageTypeError):
            session.sign("not-bytes", K)
        self.assertEqual(session.nonce_status(K), "reserved")  # 无半更新
        first = session.sign(MSG, K)
        second = session.sign(MSG, K)
        self.assertIs(first, second)


class NonceReuseTests(unittest.TestCase):
    def test_same_nonce_different_message_after_use_rejected(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        session.sign(MSG, K)
        other = b"a-different-message"
        with self.assertRaises(ec17.NonceReuseError):
            session.sign(other, K)
        # 被拒后原请求的幂等重放仍然可用，状态未被破坏。
        self.assertIs(session.sign(MSG, K), session.signature_for(K))
        self.assertEqual(session.nonce_status(K), "used")

    def test_reserve_with_different_message_after_use_rejected(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        session.sign(MSG, K)
        with self.assertRaises(ec17.NonceStateError):
            session.reserve_nonce(K, b"yet-another")

    def test_reuse_leaks_secret_key_by_analytic_relation(self):
        # 解析核对（只用独立参考造两条同 nonce 签名）：
        # s1 = k + e1*sk, s2 = k + e2*sk  =>  sk = (s1-s2)/(e1-e2) mod 19。
        m1, m2 = b"message-one", b"message-two"
        pub, r1, e1, s1 = ref_sign(SK, m1, K)
        _p2, r2, e2, s2 = ref_sign(SK, m2, K)
        # 同 nonce => R 相同（这也是重用可被检测的原因）。
        self.assertEqual(r1, r2)
        self.assertNotEqual(e1, e2)
        recovered = ((s1 - s2) * pow(e1 - e2, -1, ORDER)) % ORDER
        self.assertEqual(recovered, SK)
        self.assertEqual(pub, ec17.derive_public_key(recovered))

    def test_challenge_values_match_reference_for_the_two_messages(self):
        pub, r_point, e1, _s = ref_sign(SK, b"message-one", K)
        _p, _r, e2, _s2 = ref_sign(SK, b"message-two", K)
        self.assertEqual(ec17.challenge(r_point, pub, b"message-one"), e1)
        self.assertEqual(ec17.challenge(r_point, pub, b"message-two"), e2)


class PhaseOrderingTests(unittest.TestCase):
    def test_sign_without_reserve_is_phase_disorder(self):
        session = make_session()
        with self.assertRaises(ec17.NonceNotReservedError):
            session.sign(MSG, K)
        self.assertEqual(session.nonce_status(K), "available")

    def test_void_without_reserve_is_phase_disorder(self):
        session = make_session()
        with self.assertRaises(ec17.NonceNotReservedError):
            session.void_nonce(K)
        self.assertEqual(session.voided_nonces(), [])

    def test_sign_message_mismatching_reservation_rejected_without_update(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        with self.assertRaises(ec17.NonceStateError):
            session.sign(b"wrong-message", K)
        # 仍是预留态，绑定的原消息照常可签。
        self.assertEqual(session.nonce_status(K), "reserved")
        sig = session.sign(MSG, K)
        _pub, r_point, _e, s_val = ref_sign(SK, MSG, K)
        self.assertEqual((sig.r, sig.s), (r_point, s_val))

    def test_re_reserve_with_different_message_while_reserved_rejected(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        with self.assertRaises(ec17.NonceStateError):
            session.reserve_nonce(K, b"rebind")
        self.assertEqual(session.nonce_message(K), MSG)

    def test_ordering_across_three_nonces_independent(self):
        session = make_session()
        session.reserve_nonce(1, b"a")
        session.reserve_nonce(2, b"b")
        # 先签 2 再签 1：每个 nonce 的阶段只看自己。
        sig2 = session.sign(b"b", 2)
        sig1 = session.sign(b"a", 1)
        self.assertEqual(session.used_nonces(), [1, 2])
        _p, r1, _e, s1 = ref_sign(SK, b"a", 1)
        _p, r2, _e, s2 = ref_sign(SK, b"b", 2)
        self.assertEqual((sig1.r, sig1.s), (r1, s1))
        self.assertEqual((sig2.r, sig2.s), (r2, s2))


class VoidTests(unittest.TestCase):
    def test_reserved_nonce_can_be_voided_and_never_returns(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        session.void_nonce(K)
        self.assertEqual(session.nonce_status(K), "voided")
        self.assertEqual(session.voided_nonces(), [K])
        self.assertIsNone(session.nonce_message(K))
        self.assertIsNone(session.signature_for(K))
        with self.assertRaises(ec17.NonceVoidedError):
            session.reserve_nonce(K, MSG)
        with self.assertRaises(ec17.NonceVoidedError):
            session.sign(MSG, K)
        with self.assertRaises(ec17.NonceVoidedError):
            session.void_nonce(K)

    def test_used_nonce_can_be_voided(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        session.sign(MSG, K)
        session.void_nonce(K)
        self.assertEqual(session.nonce_status(K), "voided")
        with self.assertRaises(ec17.NonceVoidedError):
            session.sign(MSG, K)

    def test_failed_signing_voids_nonce_instead_of_recycling(self):
        # 人为让底层签名计算抛错：失败也不回收为可用，nonce 立即作废。
        session = make_session()
        session.reserve_nonce(K, MSG)
        with mock.patch(
            "ec17._session._stateless_sign", side_effect=RuntimeError("boom")
        ):
            with self.assertRaises(RuntimeError):
                session.sign(MSG, K)
        self.assertEqual(session.nonce_status(K), "voided")
        with self.assertRaises(ec17.NonceVoidedError):
            session.sign(MSG, K)
        with self.assertRaises(ec17.NonceVoidedError):
            session.reserve_nonce(K, MSG)

    def test_other_nonces_unaffected_when_one_voided(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        session.reserve_nonce(4, b"other")
        session.void_nonce(K)
        sig = session.sign(b"other", 4)
        _pub, r_point, _e, s_val = ref_sign(SK, b"other", 4)
        self.assertEqual((sig.r, sig.s), (r_point, s_val))
        self.assertEqual(session.voided_nonces(), [K])


class NoHalfUpdateTests(unittest.TestCase):
    def test_invalid_reserve_inputs_create_no_entry(self):
        session = make_session()
        with self.assertRaises(ec17.MessageTypeError):
            session.reserve_nonce(K, "str-not-allowed")
        with self.assertRaises(ec17.MessageTooLongError):
            session.reserve_nonce(K, b"x" * (ec17.MAX_MESSAGE_BYTES + 1))
        with self.assertRaises(ec17.InvalidNonceError):
            session.reserve_nonce(0, MSG)
        self.assertEqual(session.nonce_status(K), "available")
        self.assertEqual(session.reserved_nonces(), [])
        # 之后合法预留仍成功。
        self.assertTrue(session.reserve_nonce(K, MSG))

    def test_invalid_inputs_on_sign_do_not_move_state(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        with self.assertRaises(ec17.InvalidNonceError):
            session.sign(MSG, 19)
        with self.assertRaises(ec17.TypeValidationError):
            session.sign(MSG, True)
        with self.assertRaises(ec17.MessageTooLongError):
            session.sign(b"y" * (ec17.MAX_MESSAGE_BYTES + 1), K)
        self.assertEqual(session.nonce_status(K), "reserved")
        self.assertEqual(session.used_nonces(), [])

    def test_invalid_inputs_on_void_do_not_move_state(self):
        session = make_session()
        session.reserve_nonce(K, MSG)
        with self.assertRaises(ec17.InvalidNonceError):
            session.void_nonce(-1)
        self.assertEqual(session.nonce_status(K), "reserved")


class ConstructionValidationTests(unittest.TestCase):
    def test_bad_secret_key_rejected_at_construction(self):
        for bad in (0, ORDER, -1):
            with self.assertRaises(ec17.InvalidSecretKeyError):
                make_session(secret_key=bad)
        with self.assertRaises(ec17.TypeValidationError):
            make_session(secret_key=True)

    def test_bad_session_id_rejected_at_construction(self):
        with self.assertRaises(ec17.InvalidSessionIdError):
            make_session(session_id=b"")
        with self.assertRaises(ec17.InvalidSessionIdError):
            make_session(session_id=b"x" * (ec17.MAX_SESSION_ID_BYTES + 1))
        with self.assertRaises(ec17.TypeValidationError):
            make_session(session_id="str-session-id")
        with self.assertRaises(ec17.TypeValidationError):
            make_session(session_id=1234)


class SessionIsolationTests(unittest.TestCase):
    def test_same_id_different_objects_are_independent(self):
        a = make_session(session_id=b"same-id", secret_key=SK)
        b = make_session(session_id=b"same-id", secret_key=SK + 1)
        a.reserve_nonce(K, MSG)
        a.sign(MSG, K)
        # B 中该 nonce 从未预留：会话状态不跨对象共享。
        self.assertEqual(b.nonce_status(K), "available")
        with self.assertRaises(ec17.NonceNotReservedError):
            b.sign(MSG, K)

    def test_distinct_secret_keys_distinct_public_keys(self):
        a = make_session(secret_key=7)
        b = make_session(secret_key=8)
        self.assertNotEqual(a.public_key, b.public_key)
        self.assertEqual(a.public_key, ec17.derive_public_key(7))
        self.assertEqual(b.public_key, ec17.derive_public_key(8))


if __name__ == "__main__":
    unittest.main()
