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


class BatchError(EC17Error):
    """批验签相关错误的基类。"""


class BatchLengthMismatchError(BatchError):
    """系数个数与批大小不一致。"""


class BatchTooLargeError(BatchError):
    """批大小超过 :data:`ec17.MAX_BATCH_SIZE`。"""


class InvalidCoefficientError(BatchError):
    """聚合系数越界或为零（零系数会把对应项静默剔除，故禁止）。"""


class BatchItemError(BatchError):
    """批中第 index 项非法（解码/结构校验失败），整批拒绝。"""

    def __init__(self, index: int, detail: str):
        self.index = index
        super().__init__(f"批项[{index}] 非法：{detail}（整批拒绝，无部分通过）")
