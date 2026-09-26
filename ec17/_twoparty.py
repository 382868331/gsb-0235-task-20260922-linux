"""两方加法份额协作签名（仅教学，不安全）。

模型（本题的严格限定，**不是**生产级阈值签名协议）：
  - 两方各持加法私钥份额 ``sk1, sk2 ∈ 1..18``，聚合公钥为份额公钥之和
    ``P = P1 + P2 = (sk1 + sk2)·G``；
  - 每方持有一个 :class:`Party` 对象；一次签名创建一个 :class:`PartySession`，
    会话 ID、参与方顺序（party_id 1 在前、2 在后）与消息全部绑定进质询；
  - 协议四轮（每方视角）：
      1. ``start_session``：本地用显式 nonce 份额计算 R_i 与承诺
         ``commitment = SHA256(tag ∥ session_id ∥ party_id ∥ encode(R_i))``；
      2. 交换承诺后 ``reveal()`` 公开 R_i（**nonce 份额在此刻被烧掉，不可复用，
         哪怕对方随后退出**），并用 ``receive_reveal`` 核对对方承诺、
         计算聚合点 ``R = R1 + R2``（无穷远则中止）；
      3. ``partial_response()`` 产出 ``s_i = (k_i + e·sk_i) mod 19``；
         ``receive_partial`` 逐项验证对方部分响应等式
         ``s_i·G == R_i + e·P_i``，并拒绝重复提交；
      4. ``finalize()`` 合成 ``s = (s1 + s2) mod 19``，得到普通
         :class:`ec17.Signature`，交由原验签器 :func:`ec17.verify` 检验。
  - 绑定消息：``bound = tag ∥ session_id ∥ encode(P1) ∥ encode(P2) ∥ message``
    （P1 在前、P2 在后，即参与方顺序绑定）；质询完全复用原公式
    ``e = SHA256(encode(R) ∥ encode(P) ∥ bound) mod 19``，因此合成签名
    直接通过**原**验签器 ``verify(bound, P, R, s)``。

.. warning::
   群只有 19 个元素，nonce 由调用方显式给定；本模块只是**限定模型下的
   协作签名教学练习**，不宣称生产协议的完整安全性（无恶意方证明、
   无并发会话防护、无侧信道防护）。
"""

import hashlib

from ._errors import (
    TypeValidationError,
    PointAtInfinityError,
    ScalarOutOfRangeError,
    SessionIdError,
    SessionStateError,
    CommitmentMismatchError,
    DuplicatePartialResponseError,
    NonceReuseError,
    InfinityAggregateError,
    PartialResponseMismatchError,
)
from ._curve import (
    GROUP_ORDER,
    GENERATOR,
    point_add,
    scalar_mul,
    _reject_nonint,
)
from ._encoding import encode_point, decode_point
from ._schnorr import (
    Signature,
    challenge,
    _validate_message,
    _validate_secret_key,
    _validate_nonce,
    assert_verify,
)

#: 会话 ID 长度上限（字节）。
MAX_SESSION_ID_BYTES = 64

_COMMIT_TAG = b"ec17-2p-commit-v1"
_BIND_TAG = b"ec17-2p-bind-v1"


def _validate_session_id(session_id) -> bytes:
    if isinstance(session_id, str):
        raise SessionIdError(
            "session_id 必须是 bytes（不隐式编码 str，请先显式 encode）"
        )
    if not isinstance(session_id, (bytes, bytearray)):
        raise SessionIdError(
            f"session_id 必须是 bytes/bytearray，收到 {type(session_id).__name__}"
        )
    session_id = bytes(session_id)
    if len(session_id) == 0:
        raise SessionIdError("session_id 不能为空（会话绑定要求非空标识）")
    if len(session_id) > MAX_SESSION_ID_BYTES:
        raise SessionIdError(
            f"session_id 长度 {len(session_id)} 超过上限 {MAX_SESSION_ID_BYTES} 字节"
        )
    return session_id


def _validate_party_id(party_id) -> int:
    _reject_nonint("party_id", party_id)
    if party_id not in (1, 2):
        raise TypeValidationError(
            f"party_id={party_id} 非法：本协议恰两方，只允许 1 或 2"
        )
    return party_id


def _commitment(session_id: bytes, party_id: int, r_point) -> bytes:
    digest_input = (
        _COMMIT_TAG + session_id + bytes((party_id,)) + encode_point(r_point)
    )
    return hashlib.sha256(digest_input).digest()


def _bind_message(session_id, p1, p2, message) -> bytes:
    """把会话 ID、参与方顺序（P1 在前）与消息折叠为待签消息。"""
    return _BIND_TAG + session_id + encode_point(p1) + encode_point(p2) + message


class Party:
    """一个协作签名参与方：持有一份加法私钥份额，跨会话跟踪已烧掉的 nonce。

    ``party_id`` 只能是 1 或 2（决定参与方顺序绑定）；``secret_share`` 是
    1..18 的教学私钥份额。nonce 份额一旦在某会话中 ``reveal()`` 公开，
    即登记在本对象中**永久不可复用**——即使对方随后退出、会话中止。
    """

    def __init__(self, party_id, secret_share):
        self._party_id = _validate_party_id(party_id)
        self._secret_share = _validate_secret_key(secret_share)
        self._public_share = scalar_mul(self._secret_share, GENERATOR)
        self._burned_nonces = set()

    @property
    def party_id(self) -> int:
        return self._party_id

    @property
    def public_share(self):
        """份额公钥 ``P_i = sk_i·G``。"""
        return self._public_share

    @property
    def burned_nonces(self) -> frozenset:
        """已公开（烧掉）的 nonce 份额集合（只读视图）。"""
        return frozenset(self._burned_nonces)

    def _burn_nonce(self, nonce: int) -> None:
        if nonce in self._burned_nonces:
            raise NonceReuseError(
                f"nonce 份额 {nonce} 已在本方此前会话中公开，不可复用"
                "（即使对方随后退出也不回收）"
            )
        self._burned_nonces.add(nonce)

    def start_session(self, session_id, message, peer, nonce) -> "PartySession":
        """开启一次两方签名会话，返回 :class:`PartySession`。

        ``peer`` 是对方 :class:`Party`（只读取其 party_id 与份额公钥）；
        ``nonce`` 为本方 nonce 份额（1..18，显式给定，同 ``sign`` 的教学约定）。
        """
        if not isinstance(peer, Party):
            raise TypeValidationError(
                f"peer 必须是 Party，收到 {type(peer).__name__}"
            )
        if peer.party_id == self._party_id:
            raise TypeValidationError(
                f"peer.party_id={peer.party_id} 与本方相同，两方协议要求 1 与 2 配对"
            )
        return PartySession(
            party=self,
            session_id=_validate_session_id(session_id),
            message=_validate_message(message),
            peer=peer,
            nonce=_validate_nonce(nonce),
        )


class PartySession:
    """一次两方签名会话的单方状态机（由 :meth:`Party.start_session` 创建）。"""

    def __init__(self, *, party, session_id, message, peer, nonce):
        self._party = party
        self._session_id = session_id
        self._message = message
        self._peer = peer
        self._nonce = nonce
        self._r_own = scalar_mul(nonce, GENERATOR)
        if self._r_own is None:  # pragma: no cover - nonce∈1..18 保证有限
            raise PointAtInfinityError("nonce 份额导出的 R_i 是无穷远点")
        self._commitment = _commitment(session_id, party.party_id, self._r_own)
        self._peer_commitment = None
        self._revealed = False
        self._r_peer = None
        self._r_agg = None
        self._p_agg = None
        self._bound_message = None
        self._challenge = None
        self._s_own = None
        self._s_peer = None

    # -- 只读属性 ---------------------------------------------------------

    @property
    def session_id(self) -> bytes:
        return self._session_id

    @property
    def message(self) -> bytes:
        return self._message

    @property
    def bound_message(self) -> bytes:
        """绑定会话 ID/参与方顺序/消息后的实际待签消息（reveal 完成后可用）。"""
        if self._bound_message is None:
            raise SessionStateError("必须先完成承诺交换与 receive_reveal 才有绑定消息")
        return self._bound_message

    @property
    def commitment(self) -> bytes:
        """本方 nonce 承诺（32 字节），第一步发送给对方。"""
        return self._commitment

    @property
    def aggregate_public_key(self):
        """聚合公钥 P = P1 + P2；为无穷远点则抛 InfinityAggregateError。"""
        p_agg = point_add(self._party.public_share, self._peer.public_share)
        if p_agg is None:
            raise InfinityAggregateError(
                "聚合公钥 P1 + P2 是无穷远点（份额私钥互为相反数），协议中止"
            )
        return p_agg

    # -- 协议步骤 ---------------------------------------------------------

    def receive_commitment(self, peer_commitment) -> None:
        """登记对方承诺（32 字节）；必须在 reveal 之前交换。"""
        if not isinstance(peer_commitment, (bytes, bytearray)):
            raise TypeValidationError(
                f"peer_commitment 必须是 bytes，收到 {type(peer_commitment).__name__}"
            )
        peer_commitment = bytes(peer_commitment)
        if len(peer_commitment) != 32:
            raise TypeValidationError(
                f"peer_commitment 长度 {len(peer_commitment)}，承诺必须是 32 字节 SHA256 输出"
            )
        if self._peer_commitment is not None:
            raise SessionStateError("对方承诺已登记，同一会话不允许重复提交承诺")
        self._peer_commitment = peer_commitment

    def reveal(self) -> bytes:
        """公开本方 nonce 点（返回其压缩编码），**此刻烧掉 nonce 份额**。"""
        if self._revealed:
            raise SessionStateError("本方 nonce 点已公开，同一会话不允许重复 reveal")
        # 先烧掉再公开：即使对方随后退出，nonce 也不回收。
        self._party._burn_nonce(self._nonce)
        self._revealed = True
        return encode_point(self._r_own)

    def receive_reveal(self, peer_r_enc) -> None:
        """接收对方 nonce 点编码：核对承诺，计算聚合点 R 与质询 e。"""
        if self._peer_commitment is None:
            raise SessionStateError("必须先 receive_commitment 再 receive_reveal")
        if self._r_peer is not None:
            raise SessionStateError("对方 nonce 点已接收，同一会话不允许重复 reveal")
        r_peer = decode_point(peer_r_enc, allow_infinity=False)
        expected = _commitment(self._session_id, self._peer.party_id, r_peer)
        if expected != self._peer_commitment:
            raise CommitmentMismatchError(
                f"对方公开的 nonce 点 {r_peer} 与其承诺不匹配，协议中止"
            )
        self._r_peer = r_peer
        r_agg = point_add(self._r_own, r_peer)
        if r_agg is None:
            raise InfinityAggregateError(
                "聚合 nonce 点 R1 + R2 是无穷远点，协议中止"
            )
        self._r_agg = r_agg
        self._p_agg = self.aggregate_public_key
        shares = {1: None, 2: None}
        shares[self._party.party_id] = self._party.public_share
        shares[self._peer.party_id] = self._peer.public_share
        self._bound_message = _bind_message(
            self._session_id, shares[1], shares[2], self._message
        )
        self._challenge = challenge(r_agg, self._p_agg, self._bound_message)

    def _require_challenge(self, step: str) -> None:
        if self._challenge is None:
            raise SessionStateError(
                f"必须先完成承诺交换与 receive_reveal 才能 {step}"
            )

    def partial_response(self) -> int:
        """计算本方部分响应 s_i = (k_i + e·sk_i) mod 19。"""
        self._require_challenge("产生部分响应")
        if not self._revealed:
            raise SessionStateError("必须先 reveal 公开本方 nonce 点再产生部分响应")
        if self._s_own is None:
            self._s_own = (
                self._nonce + self._challenge * self._party._secret_share
            ) % GROUP_ORDER
        return self._s_own

    def receive_partial(self, peer_s) -> int:
        """接收并**逐项验证**对方部分响应：s_peer·G == R_peer + e·P_peer。"""
        self._require_challenge("接收部分响应")
        _reject_nonint("peer_s", peer_s)
        if not 0 <= peer_s < GROUP_ORDER:
            raise ScalarOutOfRangeError(
                f"peer_s={peer_s} 超出规范范围 0..{GROUP_ORDER - 1}"
            )
        if self._s_peer is not None:
            raise DuplicatePartialResponseError(
                "同一会话已收到对方部分响应，拒绝重复提交"
            )
        lhs = scalar_mul(peer_s, GENERATOR)
        rhs = point_add(self._r_peer, scalar_mul(self._challenge, self._peer.public_share))
        if lhs != rhs:
            raise PartialResponseMismatchError(
                f"对方部分响应等式不成立：s_peer·G={lhs} ≠ R_peer + e·P_peer={rhs}"
                f"（s_peer={peer_s}, e={self._challenge}）"
            )
        self._s_peer = peer_s
        return peer_s

    def finalize(self) -> Signature:
        """合成最终签名 (R, s)，并用原验签器自检后返回。"""
        self._require_challenge("合成签名")
        if self._s_own is None:
            raise SessionStateError("必须先 partial_response 产生本方部分响应")
        if self._s_peer is None:
            raise SessionStateError("必须先 receive_partial 接收对方部分响应")
        s_agg = (self._s_own + self._s_peer) % GROUP_ORDER
        signature = Signature(r=self._r_agg, s=s_agg, message=self._bound_message)
        # 交付前用原（单方）验签器逐项自检，失败属于库内部矛盾。
        assert_verify(self._bound_message, self._p_agg, signature.r, signature.s)
        return signature
