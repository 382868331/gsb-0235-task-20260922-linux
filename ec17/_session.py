"""带会话 ID 与 nonce 生命周期的有状态签名层（仅教学，不安全）。

本模块在不改变 :mod:`ec17` 旧纯函数接口的前提下，增加：

- **会话 ID**：:class:`SigningSession` 以一个字符串 ID 标识，nonce 状态与
  请求幂等记录都按会话隔离；:class:`SessionRegistry` 按 ID 管理多个会话；
- **nonce 预留 / 使用 / 作废状态机**：每个 nonce 在一个会话内依次经历
  ``reserved（已预留）→ used（已使用，绑定一条消息）``，或从 reserved/used
  转移到 ``revoked（已作废）``；
- **防重用**：已使用的 nonce 只允许重签**同一条消息**（结果确定性相同），
  签不同消息抛 :class:`NonceReuseError`，且 nonce 保持 used，**不会被回收**
  成可重新预留的可用状态；
- **请求幂等**：``sign`` 必须携带请求 ID；同一请求 ID 携带相同参数重放时
  返回首次的同一签名；携带不同参数抛 :class:`IdempotencyConflictError`，
  不做任何状态变更；
- **阶段约束**：未预留不能签、作废后不能签、会话关闭后任何变更操作都被
  拒绝（阶段乱序抛 :class:`SessionPhaseError` 等）。

所有状态变更都在输入全部校验通过、签名计算成功之后才提交，非法调用不会
留下“半更新”状态。

.. warning::
   状态只存在于内存中的教学对象里：没有持久化、没有崩溃恢复、没有并发
   防护、没有真实密码安全性。
"""

from dataclasses import dataclass

from ._errors import (
    InvalidSessionIdError,
    SessionNotFoundError,
    SessionAlreadyExistsError,
    SessionPhaseError,
    NonceReservationError,
    NonceNotReservedError,
    NonceLifecycleError,
    NonceReuseError,
    IdempotencyConflictError,
)
from ._curve import Point
from ._schnorr import (
    Signature,
    derive_public_key,
    sign as _core_sign,
    _validate_secret_key,
    _validate_nonce,
    _validate_message,
)

#: nonce 已预留、尚未用于签名。
NONCE_RESERVED = "reserved"
#: nonce 已用于签名，并绑定了一条消息。
NONCE_USED = "used"
#: nonce 已作废，不能再用于签名。
NONCE_REVOKED = "revoked"

#: 会话 ID / 请求 ID 的最大字符数（接口边界）。
MAX_ID_CHARS = 256


def _validate_identifier(name: str, value) -> str:
    """会话 ID / 请求 ID 的统一校验：非空 str，长度受限，拒绝控制字符。"""
    if not isinstance(value, str):
        raise InvalidSessionIdError(
            f"参数 {name!r} 必须是 str，收到 {type(value).__name__}"
            "（不隐式解码 bytes）"
        )
    if len(value) == 0:
        raise InvalidSessionIdError(f"参数 {name!r} 不能为空字符串")
    if len(value) > MAX_ID_CHARS:
        raise InvalidSessionIdError(
            f"参数 {name!r} 长度 {len(value)} 超过上限 {MAX_ID_CHARS} 字符"
        )
    bad = next((c for c in value if ord(c) < 0x20 or ord(c) == 0x7F), None)
    if bad is not None:
        raise InvalidSessionIdError(
            f"参数 {name!r} 含控制字符 U+{ord(bad):04X}，不允许换行/制表符等"
        )
    return value


@dataclass(frozen=True)
class _RequestRecord:
    """一次成功签名请求的归档（请求 ID 幂等重放用）。"""

    message: bytes
    nonce: int
    signature: Signature


class SigningSession:
    """单个签名会话：绑定一个教学私钥，维护 nonce 状态机与请求幂等表。

    建议通过 :class:`SessionRegistry` 创建；也可以直接实例化使用。
    会话对象**不是**线程安全的，状态只在内存中。
    """

    def __init__(self, session_id, secret_key):
        self._session_id = _validate_identifier("session_id", session_id)
        sk = _validate_secret_key(secret_key)
        self._secret_key = sk
        self._public_key = derive_public_key(sk)
        # nonce -> NONCE_RESERVED / NONCE_USED / NONCE_REVOKED
        self._nonce_states: dict[int, str] = {}
        # nonce -> 首次成功签名时绑定的消息（仅 used/revoked-from-used 有记录）
        self._bound_messages: dict[int, bytes] = {}
        # request_id -> _RequestRecord
        self._requests: dict[str, _RequestRecord] = {}
        self._closed = False

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def public_key(self) -> Point:
        return self._public_key

    @property
    def is_closed(self) -> bool:
        return self._closed

    def _require_open(self, operation: str) -> None:
        if self._closed:
            raise SessionPhaseError(
                f"会话 {self._session_id!r} 已关闭，不能再执行 {operation}"
                "（关闭后不接受预留/签名/作废/重复关闭）"
            )

    def reserve_nonce(self, nonce) -> None:
        """预留一个 nonce（1..18）。

        每个 nonce 在一个会话中只能成功预留一次：已预留/已使用/已作废的
        nonce 再次预留抛 :class:`NonceReservationError`。失败不改变任何状态。
        """
        self._require_open("reserve_nonce")
        k = _validate_nonce(nonce)
        state = self._nonce_states.get(k)
        if state is not None:
            raise NonceReservationError(
                f"会话 {self._session_id!r} 中 nonce={k} 当前状态为 {state}，"
                "不能重复预留（已使用/已作废的 nonce 不会被回收为可用）"
            )
        self._nonce_states[k] = NONCE_RESERVED

    def revoke_nonce(self, nonce) -> None:
        """作废一个已预留或已使用的 nonce；作废后永不能再用于签名。

        - 从未预留 → :class:`NonceNotReservedError`；
        - 已作废 → :class:`NonceLifecycleError`；
        - 已预留 / 已使用 → 转为 revoked。
        """
        self._require_open("revoke_nonce")
        k = _validate_nonce(nonce)
        state = self._nonce_states.get(k)
        if state is None:
            raise NonceNotReservedError(
                f"会话 {self._session_id!r} 中 nonce={k} 从未预留，不能作废"
            )
        if state == NONCE_REVOKED:
            raise NonceLifecycleError(
                f"会话 {self._session_id!r} 中 nonce={k} 已是 revoked，"
                "不能再次作废"
            )
        self._nonce_states[k] = NONCE_REVOKED

    def nonce_status(self, nonce):
        """返回 nonce 当前状态字符串。

        取值为 :data:`NONCE_RESERVED` / :data:`NONCE_USED` /
        :data:`NONCE_REVOKED`；从未预留返回 ``None``。已关闭会话仍可查询。
        """
        k = _validate_nonce(nonce)
        return self._nonce_states.get(k)

    def sign(self, request_id, message, nonce) -> Signature:
        """在本会话内用已预留的 nonce 对消息签名（必须携带请求 ID）。

        生命周期规则：

        - nonce 从未预留 → :class:`NonceNotReservedError`（阶段乱序：
          必须先 reserve_nonce）；
        - nonce 已作废 → :class:`NonceLifecycleError`；
        - nonce 已使用且消息与首次**不同** → :class:`NonceReuseError`，
          nonce 维持 used，不回收；
        - nonce 已使用且消息**相同** → 返回相同签名（数学上确定性一致），
          新的请求 ID 仍被登记；
        - 请求 ID 曾成功使用过：参数完全相同则幂等返回首次签名，参数不同
          抛 :class:`IdempotencyConflictError`，状态不变；
        - 任何输入校验失败都不改变 nonce 状态、不登记请求（无半更新）。
        """
        self._require_open("sign")
        req_id = _validate_identifier("request_id", request_id)
        msg = _validate_message(message)
        k = _validate_nonce(nonce)

        record = self._requests.get(req_id)
        if record is not None:
            if record.nonce == k and record.message == msg:
                return record.signature
            raise IdempotencyConflictError(
                f"请求 ID {req_id!r} 已在会话 {self._session_id!r} 中使用，"
                f"首次参数为 nonce={record.nonce}, message={record.message!r}，"
                f"本次为 nonce={k}, message={msg!r}（拒绝且不改变任何状态）"
            )

        state = self._nonce_states.get(k)
        if state is None:
            raise NonceNotReservedError(
                f"会话 {self._session_id!r} 中 nonce={k} 尚未预留，"
                "必须先 reserve_nonce 再签名（阶段乱序）"
            )
        if state == NONCE_REVOKED:
            raise NonceLifecycleError(
                f"会话 {self._session_id!r} 中 nonce={k} 已作废，"
                "不能用于签名（作废不可撤销）"
            )

        if state == NONCE_USED:
            bound = self._bound_messages[k]
            if bound != msg:
                raise NonceReuseError(
                    f"会话 {self._session_id!r} 中 nonce={k} 已绑定消息 "
                    f"{bound!r}，不能用于不同消息 {msg!r}；该 nonce 保持 used，"
                    "不会被回收为可用"
                )

        # 纯函数计算；走到这里所有输入都已合法，签名不会再失败。
        signature = _core_sign(self._secret_key, msg, k)

        # 计算成功后一次性提交状态（reserved→used、登记请求）。
        if state == NONCE_RESERVED:
            self._nonce_states[k] = NONCE_USED
            self._bound_messages[k] = msg
        self._requests[req_id] = _RequestRecord(message=msg, nonce=k, signature=signature)
        return signature

    def close(self) -> None:
        """关闭会话。关闭后预留/签名/作废/再次关闭全部抛 SessionPhaseError。"""
        if self._closed:
            raise SessionPhaseError(
                f"会话 {self._session_id!r} 已经处于关闭状态，不能重复关闭"
            )
        self._closed = True


class SessionRegistry:
    """按会话 ID 管理 :class:`SigningSession` 的内存注册表（教学用）。"""

    def __init__(self):
        self._sessions: dict[str, SigningSession] = {}

    def create_session(self, session_id, secret_key) -> SigningSession:
        """创建并登记会话；ID 已存在抛 :class:`SessionAlreadyExistsError`。

        先完成全部参数校验再登记，非法参数不会留下空壳会话。
        """
        sid = _validate_identifier("session_id", session_id)
        sk = _validate_secret_key(secret_key)
        existing = self._sessions.get(sid)
        if existing is not None:
            if existing.is_closed:
                # 理论上不可达：关闭时会从注册表移除；防御性保留。
                raise SessionAlreadyExistsError(  # pragma: no cover
                    f"会话 ID {sid!r} 已存在（状态为已关闭）"
                )
            raise SessionAlreadyExistsError(f"会话 ID {sid!r} 已存在，不能重复创建")
        session = SigningSession(sid, sk)
        self._sessions[sid] = session
        return session

    def get_session(self, session_id) -> SigningSession:
        """按 ID 取回会话；未知 ID 抛 :class:`SessionNotFoundError`。"""
        sid = _validate_identifier("session_id", session_id)
        session = self._sessions.get(sid)
        if session is None:
            raise SessionNotFoundError(f"会话 ID {sid!r} 不存在（或已关闭并注销）")
        return session

    def session_exists(self, session_id) -> bool:
        """ID 当前是否对应一个登记在册（未关闭注销）的会话。"""
        sid = _validate_identifier("session_id", session_id)
        return sid in self._sessions

    def session_ids(self):
        """当前在册会话 ID 的快照列表（按插入顺序）。"""
        return list(self._sessions)

    def close_session(self, session_id) -> None:
        """按 ID 关闭会话并从注册表注销；未知 ID 抛 SessionNotFoundError。"""
        sid = _validate_identifier("session_id", session_id)
        session = self._sessions.get(sid)
        if session is None:
            raise SessionNotFoundError(f"会话 ID {sid!r} 不存在，无法关闭")
        # close() 成功（未重复关闭）后才从注册表移除。
        session.close()
        del self._sessions[sid]
