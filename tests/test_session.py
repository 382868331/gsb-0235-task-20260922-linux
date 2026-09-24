"""会话 ID + nonce 生命周期 + 请求幂等的测试。

期望值来源与旧测试一致：tests/reference.py 的独立参考（朴素仿射公式路线），
被测 ec17 不参与任何期望值的生成。会话层签出的签名必须逐字段等于
``ref_sign`` 的 (P, R, e, s)。另外用一条解析关系交叉核对“nonce 重用为何
必须拒绝”：同一 nonce 签 m1/m2 得 (e1,s1)/(e2,s2) 时，
``sk = (s1-s2)/(e1-e2) mod 19`` 可直接解出私钥。
"""

import unittest

import ec17
from reference import ORDER, ref_sign

ANCHOR_MSG = b"ec17-schnorr-teaching"
OTHER_MSG = b"a-different-synthetic-message"
THIRD_MSG = b"third-message"


def _make_registry_with_session(session_id="sess-A", secret_key=7):
    registry = ec17.SessionRegistry()
    session = registry.create_session(session_id, secret_key)
    return registry, session


class NormalSessionFlowTests(unittest.TestCase):
    def test_reserve_then_sign_matches_reference_anchor(self):
        _reg, session = _make_registry_with_session("sess-A", 7)
        self.assertEqual(session.public_key, ref_sign(7, ANCHOR_MSG, 13)[0])
        self.assertIsNone(session.nonce_status(13))
        session.reserve_nonce(13)
        self.assertEqual(session.nonce_status(13), ec17.NONCE_RESERVED)
        sig = session.sign("req-1", ANCHOR_MSG, 13)
        pub, r_point, e_val, s_val = ref_sign(7, ANCHOR_MSG, 13)
        self.assertEqual((sig.r, sig.s, sig.message), (r_point, s_val, ANCHOR_MSG))
        self.assertEqual(session.nonce_status(13), ec17.NONCE_USED)
        # 旧的纯函数验签入口对会话产物继续有效（向后兼容）。
        self.assertTrue(ec17.verify(ANCHOR_MSG, pub, sig.r, sig.s))
        self.assertEqual(e_val, 14)
        self.assertEqual(s_val, 16)

    def test_every_nonce_for_every_key_matches_reference(self):
        # 小规模枚举：6 个代表私钥 × 全部 18 个 nonce × 2 条消息。
        # 注意同一 nonce 在一个会话中只能绑一条消息，所以两条消息用两个
        # 独立会话（这也顺带核对了会话间的状态隔离）。
        for sk in (1, 3, 7, 11, 17, 18):
            for tag, msg in (("m1", ANCHOR_MSG), ("m2", OTHER_MSG)):
                registry = ec17.SessionRegistry()
                session = registry.create_session(f"enum-{sk}-{tag}", sk)
                for nonce in range(1, ORDER):
                    session.reserve_nonce(nonce)
                for nonce in range(1, ORDER):
                    pub, r_point, _e, s_val = ref_sign(sk, msg, nonce)
                    sig = session.sign(f"req-{nonce}", msg, nonce)
                    self.assertEqual((sig.r, sig.s), (r_point, s_val), (sk, nonce, msg))
                    self.assertTrue(ec17.verify(msg, pub, sig.r, sig.s))
                self.assertEqual(
                    {session.nonce_status(k) for k in range(1, ORDER)},
                    {ec17.NONCE_USED},
                )

    def test_multiple_nonces_keep_independent_states(self):
        _reg, session = _make_registry_with_session()
        session.reserve_nonce(2)
        session.reserve_nonce(5)
        session.sign("r2", ANCHOR_MSG, 2)
        self.assertEqual(session.nonce_status(2), ec17.NONCE_USED)
        self.assertEqual(session.nonce_status(5), ec17.NONCE_RESERVED)
        self.assertIsNone(session.nonce_status(9))

    def test_same_message_signed_again_with_new_request_id_returns_equal_signature(self):
        _reg, session = _make_registry_with_session()
        session.reserve_nonce(13)
        first = session.sign("req-1", ANCHOR_MSG, 13)
        # 已使用 nonce + 同消息 + 新请求 ID：合法，结果确定性一致。
        second = session.sign("req-2", ANCHOR_MSG, 13)
        self.assertEqual(second, first)
        self.assertEqual(session.nonce_status(13), ec17.NONCE_USED)


class IdempotencyTests(unittest.TestCase):
    def setUp(self):
        self.reg, self.session = _make_registry_with_session()
        self.session.reserve_nonce(13)
        self.first = self.session.sign("req-1", ANCHOR_MSG, 13)

    def test_duplicate_request_identical_params_is_idempotent(self):
        replayed = self.session.sign("req-1", ANCHOR_MSG, 13)
        self.assertIs(replayed, self.first)
        # 多重重放仍然幂等。
        self.assertIs(self.session.sign("req-1", ANCHOR_MSG, 13), self.first)

    def test_duplicate_request_with_changed_message_conflicts_and_changes_nothing(self):
        with self.assertRaises(ec17.IdempotencyConflictError):
            self.session.sign("req-1", OTHER_MSG, 13)
        # 状态无半更新：nonce 仍绑定原消息，重放原请求依旧返回原签名。
        self.assertEqual(self.session.nonce_status(13), ec17.NONCE_USED)
        self.assertIs(self.session.sign("req-1", ANCHOR_MSG, 13), self.first)

    def test_duplicate_request_with_changed_nonce_conflicts_without_touching_other_nonce(self):
        # nonce 14 从未预留；冲突检查必须先于 nonce 状态检查，且失败不能
        # 把 14 标记成任何状态。
        with self.assertRaises(ec17.IdempotencyConflictError):
            self.session.sign("req-1", ANCHOR_MSG, 14)
        self.assertIsNone(self.session.nonce_status(14))
        self.assertIs(self.session.sign("req-1", ANCHOR_MSG, 13), self.first)

    def test_first_request_failure_does_not_consume_request_id(self):
        # req-x 在 nonce 未预留时失败；随后预留，再用同一请求 ID 签名应成功。
        fresh = ec17.SigningSession("sess-fresh", 7)
        with self.assertRaises(ec17.NonceNotReservedError):
            fresh.sign("req-x", ANCHOR_MSG, 6)
        fresh.reserve_nonce(6)
        sig = fresh.sign("req-x", ANCHOR_MSG, 6)
        pub, r_point, _e, s_val = ref_sign(7, ANCHOR_MSG, 6)
        self.assertEqual((sig.r, sig.s), (r_point, s_val))
        self.assertTrue(ec17.verify(ANCHOR_MSG, pub, sig.r, sig.s))


class NonceLifecycleTests(unittest.TestCase):
    def test_sign_before_reserve_is_phase_error_and_records_nothing(self):
        _reg, session = _make_registry_with_session()
        with self.assertRaises(ec17.NonceNotReservedError):
            session.sign("req-x", ANCHOR_MSG, 13)
        # 失败不预留、不登记：随后正常预留+同一请求 ID 可以成功。
        self.assertIsNone(session.nonce_status(13))
        session.reserve_nonce(13)
        sig = session.sign("req-x", ANCHOR_MSG, 13)
        self.assertEqual((sig.r, sig.s), (ref_sign(7, ANCHOR_MSG, 13)[1],
                                          ref_sign(7, ANCHOR_MSG, 13)[3]))

    def test_reserve_is_one_shot_in_every_state(self):
        _reg, session = _make_registry_with_session()
        session.reserve_nonce(13)
        with self.assertRaises(ec17.NonceReservationError):
            session.reserve_nonce(13)
        session.sign("req-1", ANCHOR_MSG, 13)
        # 已使用不回收：再次预留仍被拒。
        with self.assertRaises(ec17.NonceReservationError):
            session.reserve_nonce(13)
        session.revoke_nonce(13)
        with self.assertRaises(ec17.NonceReservationError):
            session.reserve_nonce(13)

    def test_revoke_reserved_blocks_signing_and_revocation(self):
        _reg, session = _make_registry_with_session()
        session.reserve_nonce(13)
        session.revoke_nonce(13)
        self.assertEqual(session.nonce_status(13), ec17.NONCE_REVOKED)
        with self.assertRaises(ec17.NonceLifecycleError):
            session.sign("req-1", ANCHOR_MSG, 13)
        with self.assertRaises(ec17.NonceLifecycleError):
            session.revoke_nonce(13)

    def test_revoke_used_then_signing_blocked(self):
        _reg, session = _make_registry_with_session()
        session.reserve_nonce(13)
        session.sign("req-1", ANCHOR_MSG, 13)
        session.revoke_nonce(13)
        self.assertEqual(session.nonce_status(13), ec17.NONCE_REVOKED)
        # 即便同消息也不能再签。
        with self.assertRaises(ec17.NonceLifecycleError):
            session.sign("req-2", ANCHOR_MSG, 13)

    def test_revoke_unknown_nonce(self):
        _reg, session = _make_registry_with_session()
        with self.assertRaises(ec17.NonceNotReservedError):
            session.revoke_nonce(8)
        with self.assertRaises(ec17.InvalidNonceError):
            session.revoke_nonce(0)

    def test_reuse_with_different_message_rejected_and_not_recycled(self):
        _reg, session = _make_registry_with_session(secret_key=7)
        session.reserve_nonce(13)
        session.sign("req-1", ANCHOR_MSG, 13)
        with self.assertRaises(ec17.NonceReuseError):
            session.sign("req-2", OTHER_MSG, 13)
        # nonce 不回收：状态仍 used，再预留被拒。
        self.assertEqual(session.nonce_status(13), ec17.NONCE_USED)
        with self.assertRaises(ec17.NonceReservationError):
            session.reserve_nonce(13)
        # 失败的重用不登记请求：req-2 随后签“原消息”仍可成功。
        same = session.sign("req-2", ANCHOR_MSG, 13)
        self.assertEqual((same.r, same.s), ((16, 4), 16))
        # 新消息永远签不了：换个请求 ID 再试仍被拒。
        with self.assertRaises(ec17.NonceReuseError):
            session.sign("req-3", OTHER_MSG, 13)

    def test_reuse_leaks_secret_key_by_analytic_relation(self):
        # 解析关系核对（全部用独立参考计算，被测实现不参与）：
        # 选两个质询不同的消息，sk = (s1-s2)/(e1-e2) mod 19。
        sk, k = 7, 13
        pub1, _r1, e1, s1 = ref_sign(sk, ANCHOR_MSG, k)
        _p2, _r2, e2, s2 = ref_sign(sk, OTHER_MSG, k)
        self.assertNotEqual(e1, e2)
        recovered = ((s1 - s2) * pow((e1 - e2) % ORDER, -1, ORDER)) % ORDER
        self.assertEqual(recovered, sk)
        self.assertEqual(pub1, ref_sign(recovered, ANCHOR_MSG, k)[0])

    def test_invalid_nonce_values_change_nothing(self):
        _reg, session = _make_registry_with_session()
        for bad in (0, ORDER, -1):
            with self.assertRaises(ec17.InvalidNonceError):
                session.reserve_nonce(bad)
            with self.assertRaises(ec17.InvalidNonceError):
                session.nonce_status(bad)
        with self.assertRaises(ec17.TypeValidationError):
            session.reserve_nonce(True)
        self.assertEqual(
            [session.nonce_status(k) for k in range(1, ORDER)],
            [None] * (ORDER - 1),
        )

    def test_bad_message_or_request_id_on_reserved_nonce_keeps_it_reserved(self):
        _reg, session = _make_registry_with_session()
        session.reserve_nonce(13)
        with self.assertRaises(ec17.MessageTypeError):
            session.sign("req-x", "not-bytes", 13)
        with self.assertRaises(ec17.MessageTooLongError):
            session.sign("req-x", b"x" * (ec17.MAX_MESSAGE_BYTES + 1), 13)
        for bad_request_id in ("", "x" * (ec17.MAX_ID_CHARS + 1), "a\nb"):
            with self.assertRaises(ec17.InvalidSessionIdError):
                session.sign(bad_request_id, ANCHOR_MSG, 13)
        with self.assertRaises(ec17.InvalidSessionIdError):
            session.sign(123, ANCHOR_MSG, 13)
        # 所有失败后 nonce 仍停留在 reserved，可以正常签名。
        self.assertEqual(session.nonce_status(13), ec17.NONCE_RESERVED)
        sig = session.sign("req-x", ANCHOR_MSG, 13)
        self.assertEqual((sig.r, sig.s), ((16, 4), 16))


class RegistryAndPhaseTests(unittest.TestCase):
    def test_registry_create_get_exists_ids(self):
        registry = ec17.SessionRegistry()
        self.assertFalse(registry.session_exists("s1"))
        s1 = registry.create_session("s1", 7)
        s2 = registry.create_session("s2", 3)
        self.assertIs(registry.get_session("s1"), s1)
        self.assertTrue(registry.session_exists("s2"))
        self.assertEqual(registry.session_ids(), ["s1", "s2"])
        self.assertEqual(s1.public_key, ref_sign(7, b"m", 1)[0])
        self.assertEqual(s2.public_key, ref_sign(3, b"m", 1)[0])

    def test_duplicate_session_id_rejected_without_touching_original(self):
        registry = ec17.SessionRegistry()
        original = registry.create_session("s1", 7)
        with self.assertRaises(ec17.SessionAlreadyExistsError):
            registry.create_session("s1", 3)
        self.assertIs(registry.get_session("s1"), original)
        self.assertEqual(original.public_key, ref_sign(7, b"m", 1)[0])

    def test_invalid_session_id_rejected(self):
        registry = ec17.SessionRegistry()
        for bad in ("", "id-with-\t-tab", "x" * (ec17.MAX_ID_CHARS + 1)):
            with self.assertRaises(ec17.InvalidSessionIdError):
                registry.create_session(bad, 7)
            with self.assertRaises(ec17.InvalidSessionIdError):
                registry.get_session(bad)
        with self.assertRaises(ec17.InvalidSessionIdError):
            registry.create_session(b"bytes-id", 7)
        self.assertEqual(registry.session_ids(), [])

    def test_identifier_length_exact_boundary_accepted(self):
        registry = ec17.SessionRegistry()
        max_sid = "y" * ec17.MAX_ID_CHARS
        session = registry.create_session(max_sid, 7)
        self.assertIs(registry.get_session(max_sid), session)
        session.reserve_nonce(1)
        max_req = "z" * ec17.MAX_ID_CHARS
        sig = session.sign(max_req, ANCHOR_MSG, 1)
        self.assertEqual((sig.r, sig.s), (ref_sign(7, ANCHOR_MSG, 1)[1],
                                          ref_sign(7, ANCHOR_MSG, 1)[3]))
        self.assertIs(session.sign(max_req, ANCHOR_MSG, 1), sig)

    def test_bad_secret_key_leaves_no_session(self):
        registry = ec17.SessionRegistry()
        for bad in (0, ORDER, -1):
            with self.assertRaises(ec17.InvalidSecretKeyError):
                registry.create_session(f"s-{bad}", bad)
        self.assertEqual(registry.session_ids(), [])

    def test_unknown_session_get_and_close(self):
        registry = ec17.SessionRegistry()
        with self.assertRaises(ec17.SessionNotFoundError):
            registry.get_session("nope")
        with self.assertRaises(ec17.SessionNotFoundError):
            registry.close_session("nope")

    def test_close_phase_ordering_and_deregistration(self):
        registry = ec17.SessionRegistry()
        session = registry.create_session("s1", 7)
        session.reserve_nonce(4)
        registry.close_session("s1")
        self.assertTrue(session.is_closed)
        self.assertFalse(registry.session_exists("s1"))
        with self.assertRaises(ec17.SessionNotFoundError):
            registry.get_session("s1")
        # 关闭后所有变更操作都是阶段乱序。
        with self.assertRaises(ec17.SessionPhaseError):
            session.reserve_nonce(5)
        with self.assertRaises(ec17.SessionPhaseError):
            session.sign("req-1", ANCHOR_MSG, 4)
        with self.assertRaises(ec17.SessionPhaseError):
            session.revoke_nonce(4)
        with self.assertRaises(ec17.SessionPhaseError):
            session.close()
        # 只读查询在关闭后仍然可用。
        self.assertEqual(session.nonce_status(4), ec17.NONCE_RESERVED)
        # 关闭已注销，同 ID 可以重新创建。
        new_session = registry.create_session("s1", 7)
        self.assertIsNot(new_session, session)
        self.assertIsNone(new_session.nonce_status(4))

    def test_close_unknown_id_via_registry_is_not_found(self):
        registry = ec17.SessionRegistry()
        registry.create_session("s1", 7)
        with self.assertRaises(ec17.SessionNotFoundError):
            registry.close_session("s2")
        self.assertTrue(registry.session_exists("s1"))

    def test_sessions_are_independent(self):
        registry = ec17.SessionRegistry()
        a = registry.create_session("A", 7)
        b = registry.create_session("B", 11)
        a.reserve_nonce(13)
        # 同值 nonce 在 B 中仍是全新的。
        self.assertIsNone(b.nonce_status(13))
        b.reserve_nonce(13)
        a.sign("a-req", ANCHOR_MSG, 13)
        self.assertEqual(a.nonce_status(13), ec17.NONCE_USED)
        self.assertEqual(b.nonce_status(13), ec17.NONCE_RESERVED)
        b.sign("b-req", OTHER_MSG, 13)
        # A 中重用 B 的消息仍按 A 自己的绑定消息判定。
        with self.assertRaises(ec17.NonceReuseError):
            a.sign("a-req-2", OTHER_MSG, 13)
        self.assertEqual(
            (b.sign("b-req", OTHER_MSG, 13).r, b.sign("b-req", OTHER_MSG, 13).s),
            (ref_sign(11, OTHER_MSG, 13)[1], ref_sign(11, OTHER_MSG, 13)[3]),
        )


if __name__ == "__main__":
    unittest.main()
