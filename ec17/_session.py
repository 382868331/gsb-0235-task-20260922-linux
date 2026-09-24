"""有状态的签名会话：会话 ID + nonce 生命周期管理（仅教学，不安全）。

在原有**无状态**纯函数（:func:`ec17.sign` / :func:`ec17.verify` 等，
本模块不改其任何语义）之上，增加一个进程内、内存态的会话层：

  - 每个会话有一个显式的会话 ID（:class:`bytes`，1..256 字节）；
  - nonce（1..18）在会话内经历状态机：

      ``(不存在) --reserve--> RESERVED --use--> USED``
                                   ``             ``
                                   ``             +--> use(同一请求) 幂等重放
                                   v
                                VOIDED （终态：失败也不回收为可用）

    即 nonce 只能“先预留、再使用”；使用时必须携带预留时的消息。
    作废是终态，作废后不能再预留/使用/作废。

  - **同一 nonce 不能签不同消息**：已用于消息 m 的 nonce 再被要求签
    m'≠m 时抛 :class:`NonceReuseError`；对**完全相同的请求**
    （同会话、同 nonce、同消息字节）重复签名是幂等重放，返回同一个
    缓存签名，不重复产生新对象语义之外的副作用。
  - 失败不留半更新状态：所有输入校验通过后才落状态；签名计算失败时
    nonce 被作废（按题意“失败也不回收为可用”），绝不静默回到可用。

阶段乱序（未预留就使用/作废、对已作废 nonce 操作、重复预留）一律抛
:class:`NonceStateError` 的具体子类。

.. warning::
   会话状态只存在于内存、不做持久化，进程退出即丢失；不提供崩溃恢复、
   并发锁或任何真实安全性。群只有 19 个元素，所有数据仅限教学合成值。
"""

from enum import Enum

from ._errors import (
    TypeValidationError,
    InvalidSessionIdError,
    NonceStateError,
    NonceNotReservedError,
    NonceVoidedError,
    NonceReuseError,
)
from ._schnorr import (
    Signature,
    sign as _stateless_sign,
    derive_public_key as _derive_public_key,
    _validate_message,
    _validate_secret_key,
    _validate_nonce,
)

#: 会话 ID 的最大长度（字节）。
MAX_SESSION_ID_BYTES = 256


class NonceStatus(str, Enum):
    """nonce 在会话内的生命周期状态。"""

    RESERVED = "reserved"
    USED = "used"
    VOIDED = "voided"


def _validate_session_id(session_id) -> bytes:
    """会话 ID 必须是 bytes（str 不隐式编码）、非空且不超过长度上限。"""
    if isinstance(session_id, str):
        raise TypeValidationError(
            "session_id 必须是 bytes（不隐式编码 str，请先显式 encode）"
        )
    if not isinstance(session_id, (bytes, bytearray)):
        raise TypeValidationError(
            f"session_id 必须是 bytes/bytearray，收到 {type(session_id).__name__}"
        )
    sid = bytes(session_id)
    if len(sid) == 0:
        raise InvalidSessionIdError("session_id 不能为空字节串")
    if len(sid) > MAX_SESSION_ID_BYTES:
        raise InvalidSessionIdError(
            f"session_id 长度 {len(sid)} 超过上限 {MAX_SESSION_ID_BYTES} 字节"
        )
    return sid


def _entry(status, message, signature):
    return {"status": status, "message": message, "signature": signature}


class SigningSession:
    """带会话 ID 与 nonce 预留/使用/作废状态的内存态教学签名会话。

    用法（严格分阶段）::

        session = SigningSession(b"demo-session", secret_key=7)
        session.reserve_nonce(13, b"hello")      # 1. 预留 nonce 并绑定消息
        sig = session.sign(b"hello", 13)         # 2. 用预留 nonce 签名
        again = session.sign(b"hello", 13)       # 同请求重放 → 同一签名（幂等）
        session.void_nonce(5)  # 也可以对尚未使用的预留 nonce 显式作废

    所有方法在非法输入时抛带参数名的异常，且不改变任何已有状态
    （失败不留半更新）。对象不作任何线程安全承诺。
    """

    def __init__(self, session_id, secret_key):
        sid = _validate_session_id(session_id)
        # 先校验私钥再写入对象，保证构造失败不留半成品。
        sk = _validate_secret_key(secret_key)
        self._session_id = sid
        self._secret_key = sk
        self._public_key = _derive_public_key(sk)
        # nonce -> {"status", "message", "signature"}
        self._nonces: dict[int, dict] = {}

    # ---- 基本属性 ---------------------------------------------------------

    @property
    def session_id(self) -> bytes:
        """会话的 ID（构造时给定，只读）。"""
        return self._session_id

    @property
    def secret_key(self) -> int:
        """教学私钥（1..18，仅用于合成数据）。"""
        return self._secret_key

    @property
    def public_key(self):
        """由私钥导出的公钥 P = sk·G。"""
        return self._public_key

    # ---- 查询 -------------------------------------------------------------

    def nonce_status(self, nonce) -> str:
        """返回 nonce 当前状态：``"reserved" | "used" | "voided"``。

        从未预留过的 nonce 返回 ``"available"``（不是枚举成员，仅用于
        查询展示）；nonce 本身仍需是 1..18 的合法整数。
        """
        k = _validate_nonce(nonce)
        entry = self._nonces.get(k)
        return "available" if entry is None else entry["status"].value

    def nonce_message(self, nonce):
        """返回 nonce 预留/使用时绑定的消息；可用或已作废的 nonce 返回 ``None``。

        已作废 nonce 的绑定消息不对外暴露（作废即不可再用）。
        """
        k = _validate_nonce(nonce)
        entry = self._nonces.get(k)
        if entry is None or entry["status"] is NonceStatus.VOIDED:
            return None
        return entry["message"]

    def reserved_nonces(self) -> list[int]:
        """当前处于“已预留未使用”状态的 nonce，升序返回。"""
        return sorted(
            k for k, e in self._nonces.items() if e["status"] is NonceStatus.RESERVED
        )

    def used_nonces(self) -> list[int]:
        """当前处于“已使用”状态的 nonce，升序返回。"""
        return sorted(
            k for k, e in self._nonces.items() if e["status"] is NonceStatus.USED
        )

    def voided_nonces(self) -> list[int]:
        """已作废的 nonce，升序返回。"""
        return sorted(
            k for k, e in self._nonces.items() if e["status"] is NonceStatus.VOIDED
        )

    def signature_for(self, nonce):
        """返回某 nonce 已生成的签名；未使用（含可用/预留/作废）时返回 ``None``。"""
        k = _validate_nonce(nonce)
        entry = self._nonces.get(k)
        if entry is None:
            return None
        return entry["signature"]

    # ---- 状态迁移 ----------------------------------------------------------

    def reserve_nonce(self, nonce, message):
        """预留一个 nonce 并绑定待签消息（阶段 1）。

        消息在此时就要给出并校验：题意要求“同一 nonce 不能签不同消息”，
        预留即把 nonce 与消息绑定。重复预留同一 *(nonce, message)* 返回
        ``False`` 且状态不变（幂等）；以下情形报错且不改状态：

          - nonce 已预留但绑定的是另一条消息 → :class:`NonceStateError`；
          - nonce 已使用 → :class:`NonceStateError`（无论消息是否相同）；
          - nonce 已作废 → :class:`NonceVoidedError`（作废不回收）。

        成功预留返回 ``True``。
        """
        k = _validate_nonce(nonce)
        msg = _validate_message(message)

        entry = self._nonces.get(k)
        if entry is None:
            self._nonces[k] = _entry(NonceStatus.RESERVED, msg, None)
            return True
        status = entry["status"]
        if status is NonceStatus.VOIDED:
            raise NonceVoidedError(
                f"nonce={k} 已作废，不能重新预留（作废是终态，不回收为可用）"
            )
        if status is NonceStatus.USED:
            raise NonceStateError(
                f"nonce={k} 已用于签名，不能重复预留（会话 {self._session_id!r}）"
            )
        # 已预留
        if entry["message"] == msg:
            return False
        raise NonceStateError(
            f"nonce={k} 已预留并绑定另一条消息"
            f"（已绑定 {entry['message']!r}，本次 {msg!r}）；"
            "同一 nonce 不能绑定不同消息"
        )

    def sign(self, message, nonce) -> Signature:
        """用已预留的 nonce 对绑定消息签名（阶段 2）。

        - nonce 未预留 → :class:`NonceNotReservedError`（阶段乱序）；
        - nonce 已作废 → :class:`NonceVoidedError`；
        - 消息与预留时绑定的不一致：
            已使用过 → :class:`NonceReuseError`（同一 nonce 签不同消息）；
            仅预留   → :class:`NonceStateError`（预留绑定不可更改）；
        - 对同一 (nonce, message) 的重复请求**幂等**：直接返回首次生成的
          同一个 :class:`Signature` 对象，不重新走签名计算。

        若底层签名计算意外失败，该 nonce 立即作废且不回收，错误继续抛出。
        """
        k = _validate_nonce(nonce)
        msg = _validate_message(message)

        entry = self._nonces.get(k)
        if entry is None:
            raise NonceNotReservedError(
                f"nonce={k} 尚未预留，不能直接签名（必须先 reserve_nonce）"
            )
        status = entry["status"]
        if status is NonceStatus.VOIDED:
            raise NonceVoidedError(
                f"nonce={k} 已作废，不能用于签名（作废不回收为可用）"
            )

        if entry["message"] != msg:
            if status is NonceStatus.USED:
                raise NonceReuseError(
                    f"nonce={k} 已签署消息 {entry['message']!r}，"
                    f"不能再签不同消息 {msg!r}（nonce 重用会泄露教学私钥）"
                )
            raise NonceStateError(
                f"nonce={k} 预留时绑定 {entry['message']!r}，"
                f"签名时却给出 {msg!r}；预留绑定不可更改"
            )

        if status is NonceStatus.USED:
            # 幂等重放：同会话、同 nonce、同消息字节的重复请求。
            return entry["signature"]

        # RESERVED -> USED：先计算，成功后再一次性落状态（无半更新）。
        try:
            signature = _stateless_sign(self._secret_key, msg, k)
        except Exception:
            # 失败也不回收为可用：作废该 nonce 后原样抛出。
            self._nonces[k] = _entry(NonceStatus.VOIDED, msg, None)
            raise
        self._nonces[k] = _entry(NonceStatus.USED, msg, signature)
        return signature

    def void_nonce(self, nonce) -> None:
        """作废 nonce（终态，失败也不回收为可用）。

        - 未预留的 nonce → :class:`NonceNotReservedError`（阶段乱序）；
        - 已作废再作废 → :class:`NonceVoidedError`；
        - 已预留或已使用的 nonce 可以作废（例如调用方判定一次签名流程
          失败/放弃），作废后不能再预留或使用。
        """
        k = _validate_nonce(nonce)
        entry = self._nonces.get(k)
        if entry is None:
            raise NonceNotReservedError(
                f"nonce={k} 尚未预留，不能作废（必须先 reserve_nonce）"
            )
        if entry["status"] is NonceStatus.VOIDED:
            raise NonceVoidedError(f"nonce={k} 已经是作废状态，作废不可重复")
        bound_message = entry["message"]
        self._nonces[k] = _entry(NonceStatus.VOIDED, bound_message, None)
