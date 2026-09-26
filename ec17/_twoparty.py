"""两方加法份额协作签名（仅教学，不安全）。

模型（本题的有限子集，不是生产级阈值签名协议）：
  - 两方各自持有加法私钥份额 sk1、sk2 ∈ 1..18，聚合公钥
    P = P1 + P2 = (sk1 + sk2)·G；
  - 会话由 session_id、固定的参与方顺序（party 1 先、party 2 后）与
    消息共同标识，三者都绑定进 nonce 承诺；
  - 协议流程：先交换 nonce 承诺（commit），再公开 nonce 点（reveal），
    聚合 R = R1 + R2（无穷远则中止）；质询
    e = SHA256( encode(R) ∥ encode(P) ∥ message ) mod 19 绑定聚合公钥、
    消息与聚合 nonce（与单方签名完全相同的质询函数）；
  - 各自产生部分响应 s_i = (k_i + e·sk_i) mod 19，并逐项验证部分响应
    等式 s_i·G = R_i + e·P_i；合成 s = (s1 + s2) mod 19 后得到
    ec17.Signature，直接交原验签器 ec17.verify 验证。

安全口径（教学限定）：
  - nonce 份额一旦公开（reveal 成功）即在所属 Party 内被烧毁，
    哪怕另一方随后退出（cancel）也不可复用；
  - 拒绝重复部分响应、承诺不匹配、无穷远聚合点；
  - 会话可取消，取消后任何协议步骤都抛 SessionStateError，
    已烧毁的 nonce 不恢复；
  - 本模块只演示限定模型下的协作签名流程，不宣称生产协议所需的
    完整安全性（无可证明安全归约、无并发会话防护、无常量时间实现）。
"""

import hashlib

from ._errors import (
    TypeValidationError,
    SessionStateError,
    UnknownPartyError,
    CommitmentMismatchError,
    DuplicatePartialResponseError,
    NonceReuseError,
    AggregatePointAtInfinityError,
    PartialResponseMismatchError,
)
from ._curve import (
    GROUP_ORDER,
    GENERATOR,
    Point,
    point_add,
    scalar_mul,
    _validate_finite_point,
    _reject_nonint,
)
from ._encoding import encode_point
from ._schnorr import (
    Signature,
    challenge,
    assert_verify,
    _validate_message,
    _validate_secret_key,
    _validate_nonce,
)

#: 合法参与方编号（顺序固定：1 为先，2 为后）。
PARTY_IDS = (1, 2)

#: 会话 ID 长度上限（字节）。
MAX_SESSION_ID_BYTES = 64

_COMMIT_DOMAIN = b"ec17-2p-commit-v1"


def _validate_session_id(session_id) -> bytes:
    if isinstance(session_id, str) or not isinstance(session_id, (bytes, bytearray)):
        raise TypeValidationError(
            f"session_id 必须是 bytes/bytearray，收到 {type(session_id).__name__}"
        )
    sid = bytes(session_id)
    if len(sid) == 0:
        raise SessionStateError("session_id 不能为空（会话标识必须可区分）")
    if len(sid) > MAX_SESSION_ID_BYTES:
        raise SessionStateError(
            f"session_id 长度 {len(sid)} 超过上限 {MAX_SESSION_ID_BYTES} 字节"
        )
    return sid


def _validate_party_id(party_id) -> int:
    _reject_nonint("party_id", party_id)
    if party_id not in PARTY_IDS:
        raise UnknownPartyError(
            f"party_id={party_id} 非法：本协议只有两方，编号必须是 1 或 2"
        )
    return party_id


def _commitment(session_id: bytes, party_id: int, nonce_point: Point, message: bytes) -> bytes:
    """nonce 承诺：绑定会话 ID、参与方顺序、nonce 点与消息。"""
    payload = (
        _COMMIT_DOMAIN
        + len(session_id).to_bytes(2, "big")
        + session_id
        + bytes([party_id])
        + encode_point(nonce_point)
        + len(message).to_bytes(4, "big")
        + message
    )
    return hashlib.sha256(payload).digest()


class Party:
    """协作签名的一方：持有加法私钥份额，跟踪已烧毁的 nonce 份额。

    nonce 份额一旦在任意会话中公开（reveal 成功）即被烧毁，之后在任何
    会话中复用都会抛 NonceReuseError；已承诺未公开的 nonce 处于
    预留状态，会话取消且未公开时释放。
    """

    def __init__(self, party_id, secret_share):
        self._party_id = _validate_party_id(party_id)
        self._secret_share = _validate_secret_key(secret_share)
        self._public_share = scalar_mul(self._secret_share, GENERATOR)
        self._reserved_nonces = set()
        self._spent_nonces = set()

    @property
    def party_id(self) -> int:
        return self._party_id

    @property
    def public_share(self):
        """公钥份额 P_i = sk_i·G。"""
        return self._public_share

    def _reserve_nonce(self, nonce) -> int:
        k = _validate_nonce(nonce)
        if k in self._spent_nonces:
            raise NonceReuseError(
                f"party {self._party_id} 的 nonce={k} 已经公开过，禁止复用"
            )
        if k in self._reserved_nonces:
            raise NonceReuseError(
                f"party {self._party_id} 的 nonce={k} 已在其他会话中承诺，禁止并发复用"
            )
        self._reserved_nonces.add(k)
        return k

    def _release_nonce(self, nonce: int) -> None:
        self._reserved_nonces.discard(nonce)

    def _burn_nonce(self, nonce: int) -> None:
        self._reserved_nonces.discard(nonce)
        self._spent_nonces.add(nonce)


class TwoPartySession:
    """一次两方协作签名会话（状态机，单消息、单次使用）。

    步骤顺序：commit（双方）→ reveal（双方）→
    partial_response（双方）→ finalize。
    cancel 可随时中止；会话不可复用。
    """

    def __init__(self, session_id, message, party1, party2):
        self._session_id = _validate_session_id(session_id)
        self._message = _validate_message(message)
        if not isinstance(party1, Party) or not isinstance(party2, Party):
            raise TypeValidationError("party1/party2 必须是 Party 实例")
        if party1.party_id != 1 or party2.party_id != 2:
            raise UnknownPartyError(
                "参与方顺序固定：party1.party_id 必须为 1，party2.party_id 必须为 2"
            )
        if party1 is party2:
            raise SessionStateError("两方不能是同一个 Party 对象")
        self._parties = {1: party1, 2: party2}
        aggregate_public_key = point_add(party1.public_share, party2.public_share)
        if aggregate_public_key is None:
            raise AggregatePointAtInfinityError(
                "聚合公钥 P1+P2 是无穷远点（sk1+sk2 ≡ 0 mod 19），会话无法建立"
            )
        self._aggregate_public_key = aggregate_public_key
        self._commitments = {}
        self._pending_nonces = {}
        self._revealed_nonces = {}
        self._nonce_points = {}
        self._partials = {}
        self._aggregate_nonce = None
        self._cancelled_by = None
        self._finalized = False

    @property
    def session_id(self) -> bytes:
        return self._session_id

    @property
    def message(self) -> bytes:
        return self._message

    @property
    def aggregate_public_key(self):
        return self._aggregate_public_key

    @property
    def aggregate_nonce(self):
        """双方 nonce 点都公开后的聚合点 R = R1 + R2（有限点）。"""
        if self._aggregate_nonce is None:
            raise SessionStateError("双方 nonce 点尚未全部公开，聚合 nonce 不存在")
        return self._aggregate_nonce

    def _require_active(self) -> None:
        if self._cancelled_by is not None:
            raise SessionStateError(
                f"会话已被 party {self._cancelled_by} 取消，不能再执行任何协议步骤"
            )
        if self._finalized:
            raise SessionStateError("会话已完成（finalize），不可复用")

    def _party(self, party_id):
        pid = _validate_party_id(party_id)
        return self._parties[pid]

    def commit(self, party_id, nonce_share) -> bytes:
        """登记一方 nonce 承诺（第一步）。返回 32 字节承诺。"""
        self._require_active()
        party = self._party(party_id)
        pid = party.party_id
        if pid in self._commitments:
            raise SessionStateError(f"party {pid} 已提交过承诺，禁止重复承诺")
        k = party._reserve_nonce(nonce_share)
        nonce_point = scalar_mul(k, GENERATOR)
        commitment = _commitment(self._session_id, pid, nonce_point, self._message)
        self._commitments[pid] = commitment
        self._pending_nonces[pid] = k
        return commitment

    def reveal(self, party_id, nonce_share):
        """公开一方 nonce 点（第二步），校验承诺后烧毁该 nonce 份额。"""
        self._require_active()
        party = self._party(party_id)
        pid = party.party_id
        if pid not in self._commitments:
            raise SessionStateError(f"party {pid} 尚未承诺，不能公开 nonce 点")
        if pid in self._nonce_points:
            raise SessionStateError(f"party {pid} 已公开过 nonce 点，禁止重复公开")
        k = _validate_nonce(nonce_share)
        nonce_point = scalar_mul(k, GENERATOR)
        expected = _commitment(self._session_id, pid, nonce_point, self._message)
        if expected != self._commitments[pid]:
            raise CommitmentMismatchError(
                f"party {pid} 公开的 nonce 点与承诺不匹配"
                "（承诺绑定会话 ID、参与方编号、nonce 点与消息）"
            )
        # 公开成功：nonce 份额立即烧毁，此后任何会话都不可复用；
        # 会话内保留份额副本，供 partial_response 计算 s_i 使用。
        committed = self._pending_nonces.pop(pid)
        party._burn_nonce(committed)
        self._revealed_nonces[pid] = committed
        self._nonce_points[pid] = nonce_point
        if len(self._nonce_points) == 2:
            aggregate = point_add(self._nonce_points[1], self._nonce_points[2])
            if aggregate is None:
                raise AggregatePointAtInfinityError(
                    "聚合 nonce 点 R1+R2 是无穷远点（k1+k2 ≡ 0 mod 19），协议中止"
                )
            self._aggregate_nonce = aggregate
        return nonce_point

    def _challenge(self) -> int:
        return challenge(self._aggregate_nonce, self._aggregate_public_key, self._message)

    def partial_response(self, party_id) -> int:
        """产生并逐项验证一方的部分响应 s_i（第三步）。"""
        self._require_active()
        party = self._party(party_id)
        pid = party.party_id
        if self._aggregate_nonce is None:
            raise SessionStateError("双方 nonce 点尚未全部公开，不能产生部分响应")
        if pid in self._partials:
            raise DuplicatePartialResponseError(
                f"party {pid} 在本会话中已提交过部分响应，禁止重复"
            )
        e = self._challenge()
        k = self._revealed_nonces.get(pid)
        if k is None:
            raise SessionStateError(f"party {pid} 尚未公开 nonce 份额")
        s_i = (k + e * party._secret_share) % GROUP_ORDER
        lhs = scalar_mul(s_i, GENERATOR)
        rhs = point_add(self._nonce_points[pid], scalar_mul(e, party.public_share))
        if lhs != rhs:
            raise PartialResponseMismatchError(
                f"party {pid} 的部分响应等式不成立：s_i·G={lhs} ≠ R_i + e·P_i={rhs}"
            )
        self._partials[pid] = s_i
        return s_i

    def finalize(self):
        """合成最终签名（第四步），并用原验签器自检后返回。"""
        self._require_active()
        if len(self._partials) != 2:
            raise SessionStateError("双方部分响应尚未齐全，不能合成签名")
        s = (self._partials[1] + self._partials[2]) % GROUP_ORDER
        signature = Signature(r=self._aggregate_nonce, s=s, message=self._message)
        # 防御性自检：合成结果必须通过原单方验签器。
        assert_verify(self._message, self._aggregate_public_key, signature.r, signature.s)
        self._finalized = True
        return signature

    def cancel(self, party_id) -> None:
        """一方退出：会话立即失效；已烧毁的 nonce 不恢复。"""
        party = self._party(party_id)
        if self._cancelled_by is not None or self._finalized:
            raise SessionStateError("会话已取消或已完成，不能重复取消")
        self._cancelled_by = party.party_id
        # 释放“已承诺但尚未公开”的 nonce 预留；已公开的保持烧毁。
        for pid, k in self._pending_nonces.items():
            self._parties[pid]._release_nonce(k)
        self._pending_nonces.clear()


def aggregate_public_key(public_share1, public_share2):
    """由两个公钥份额计算聚合公钥 P = P1 + P2（拒绝无穷远结果）。"""
    p1 = _validate_finite_point("public_share1", public_share1)
    p2 = _validate_finite_point("public_share2", public_share2)
    aggregate = point_add(p1, p2)
    if aggregate is None:
        raise AggregatePointAtInfinityError(
            "聚合公钥 P1+P2 是无穷远点（份额互逆），不能作为签名公钥"
        )
    return aggregate
