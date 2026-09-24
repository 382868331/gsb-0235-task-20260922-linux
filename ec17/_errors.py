"""固定的错误语义。

所有库异常都继承 :class:`EC17Error`；类型错误同时继承标准库 ``TypeError``，
调用方既可以按教学库异常捕获，也可以按内置类型错误捕获。错误消息一律带
参数名，保证“可定位”。
"""


class EC17Error(Exception):
    """ec17 库所有异常的根。"""


class ValidationError(EC17Error):
    """输入值不满足契约的基类。"""


class TypeValidationError(ValidationError, TypeError):
    """参数类型非法（含 bool 冒充整数、NaN/Infinity 等浮点输入）。"""


class PointError(EC17Error):
    """点对象相关错误的基类。"""


class CoordinateOutOfDomainError(PointError):
    """坐标整数存在但不在域 F_17（0..16）内。"""


class PointNotOnCurveError(PointError):
    """坐标在域内，但不满足曲线方程 y² ≡ x³+2x+2 (mod 17)。"""


class PointAtInfinityError(PointError):
    """契约要求有限点的位置传入了无穷远点。"""


class EncodingError(EC17Error):
    """点/标量字节编解码错误的基类。"""


class EmptyEncodingError(EncodingError):
    """解码输入为空字节串。"""


class TruncatedEncodingError(EncodingError):
    """编码长度不足（被截断）。"""


class InvalidEncodingPrefixError(EncodingError):
    """压缩/标量编码首字节前缀非法。"""


class OutOfDomainEncodingError(EncodingError):
    """编码尾部携带的整数超出本协议域（点 x≥17 或标量≥19）。"""


class NonShortestEncodingError(EncodingError):
    """存在尾随字节等非最短（非规范）编码。"""


class SignatureError(EC17Error):
    """签名/验签相关错误的基类。"""


class ScalarOutOfRangeError(SignatureError):
    """标量（s、私钥、nonce）不在 0..18。"""


class SignatureMismatchError(SignatureError):
    """签名等式 sG = R + eP 不成立（验签失败）。"""


class InvalidSecretKeyError(SignatureError):
    """私钥不是 1..18 的整数（0 会得到无穷远公钥，故禁用）。"""


class InvalidNonceError(SignatureError):
    """签名 nonce 不是 0..18 的整数。"""


class MessageError(EC17Error):
    """消息参数相关错误的基类。"""


class MessageTypeError(MessageError, TypeError):
    """消息不是 ``bytes``/``bytearray``（不隐式编码字符串）。"""


class MessageTooLongError(MessageError):
    """消息长度超过 :data:`ec17.MAX_MESSAGE_BYTES`。"""


class SessionError(EC17Error):
    """会话与 nonce 生命周期相关错误的基类。"""


class InvalidSessionIdError(SessionError, TypeError):
    """会话 ID / 请求 ID 类型或格式非法（非 str、空串、过长、含控制字符）。"""


class SessionNotFoundError(SessionError):
    """会话注册表中不存在该会话 ID。"""


class SessionAlreadyExistsError(SessionError):
    """create_session 使用了已经存在的会话 ID。"""


class SessionPhaseError(SessionError):
    """操作与会话阶段不符（关闭后再预留/签名/作废、重复关闭）。"""


class NonceReservationError(SessionError):
    """预留冲突：nonce 在本会话中已被预留、使用或作废，不能再次预留。"""


class NonceNotReservedError(SessionError):
    """操作一个本会话中从未成功预留的 nonce。"""


class NonceLifecycleError(SessionError):
    """nonce 状态机不允许的转移（用已作废 nonce 签名、作废已使用/已作废的 nonce）。"""


class NonceReuseError(SessionError):
    """已使用的 nonce 被用于另一条不同消息；拒绝且该 nonce 不被回收为可用。"""


class IdempotencyConflictError(SessionError):
    """同一请求 ID 重放时携带了与首次请求不同的参数。"""
