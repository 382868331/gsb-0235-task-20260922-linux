"""固定的错误语义（教学模块 ``ecc_teach``）。

所有异常都继承 :class:`ECCTeachError`，便于调用方统一捕获；
同时各自继承一个标准库内建异常（``TypeError`` / ``ValueError``），
不破坏习惯用法。

教学不安全（TEACHING ONLY）：本模块只服务于离线密码工程教学，
曲线群仅 19 个点，禁止用于任何真实密钥或真实安全场景。
"""

from __future__ import annotations


class ECCTeachError(Exception):
    """本库所有自定义异常的共同基类。"""


class StrictTypeError(ECCTeachError, TypeError):
    """类型不满足严格契约。

    典型情形：整数参数收到 ``bool``（``True`` 会被 Python 当作 1，
    本库一律拒绝）、收到非精确 ``int``、字节参数收到 ``str``/``bytearray``。
    """


class NonFiniteNumberError(ECCTeachError, ValueError):
    """数值输入为 ``NaN`` 或带符号 ``Infinity``。

    本库没有任何浮点算法；浮点数值即使有限也会因类型被拒绝，
    但 ``NaN``/``Infinity`` 单独给出可定位的错误。
    """


class InvalidPointError(ECCTeachError, ValueError):
    """点不是合法的曲线点：结构错误、坐标越界或不在曲线上。"""


class EncodingError(ECCTeachError, ValueError):
    """压缩点编码非法：长度不对、非最短、前缀非法或域外。"""


class MessageTooLongError(ECCTeachError, ValueError):
    """消息长度超过教学接口上限（``MAX_MESSAGE_BYTES``）。"""


class InvalidSignatureError(ECCTeachError, ValueError):
    """签名无效。

    ``reason`` 是机器可读的稳定原因码，取值固定为：

    - ``"s_range"``：``s`` 不在 ``0..18``；
    - ``"public_key_encoding"``：公钥压缩编码非法（含非最短/域外/非曲线上）；
    - ``"public_key_infinity"``：公钥是无穷远点；
    - ``"r_encoding"``：签名中的 R 压缩编码非法；
    - ``"r_infinity"``：R 是无穷远点；
    - ``"equation_fail"``：方程 ``sG = R + eP`` 不成立。

    检查顺序即上面的排列顺序，因此一次验证只暴露第一个原因。
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        if not isinstance(reason, str) or not reason:
            raise StrictTypeError("reason 必须是非空 str")
        self.reason = reason
        message = f"签名无效：{reason}"
        if detail:
            message += f"（{detail}）"
        super().__init__(message)
