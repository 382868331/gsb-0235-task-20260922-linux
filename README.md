# ec17 — 椭圆曲线教学签名的严格验签与会话 nonce 管理（仅教学，不安全）

为离线密码工程教学实现的可复用库：在小素域椭圆曲线
**y² = x³ + 2x + 2 (mod 17)** 上实现点加/倍乘、压缩点编码，一个
Schnorr 风格教学签名的**严格验签**，以及一层带**会话 ID** 与
**nonce 预留/使用/作废状态机**的有状态签名层（含请求 ID 幂等）。

> ⚠️ **教学专用，不提供任何安全性。** 群只有 19 个元素，私钥空间可瞬间穷举；
> nonce 仍是调用方显式给定的小整数（会话层只防“同一 nonce 签不同消息”这类
> 误用，不做随机化）；**禁止使用真实密钥/密钥文件**。
> 本库只实现题面契约的有限数学/协议子集，**不兼容也不宣称兼容** RFC 6979、
> secp256k1、FIPS 186 等任何行业标准。

## 运行环境

- Python **3.14.7**（Linux 原生验证；仅使用标准库 `hashlib`、`dataclasses`、`math`、`unittest`）
- **无需安装任何第三方依赖**，安装 Python 后即可运行
- 核心、测试、演示全部**离线**：不联网、不需要账号/硬件/数据库/中间件/云 API/Docker
- 示例数据由仓库内确定性代码生成，无随机源、无外部附件

## 准确命令

```bash
python -m unittest discover -s tests -v   # 运行必要测试（87 个，约 0.2 秒）
python demo.py                            # 固定输入演示（约 0.04 秒，远低于 90 秒）
```

## 公开数据结构

| 名称 | 含义 |
|---|---|
| `Point` | 有限点，类型 `tuple[int, int]`，即 `(x, y)`，x,y ∈ 0..16 |
| `INFINITY` | 无穷远点（群单位元），用 `None` 表示 |
| `Signature` | 不可变 dataclass：`r: Point`、`s: int`、`message: bytes` |

曲线常量：`FIELD_PRIME=17`、`COEFF_A=2`、`COEFF_B=2`、`GROUP_ORDER=19`、
`GENERATOR=(5,1)`、`MAX_MESSAGE_BYTES=65535`。

曲线上恰有 18 个有限点，加上无穷远点共 19 个；G 是阶为 19 的生成元。

## 接口

### 群运算（`ec17/_curve.py`）

- `is_on_curve(point) -> bool`：无穷远返回 `False`；坐标域外返回 `False`；
  坐标类型非法抛 `TypeValidationError`。
- `point_neg(point)`：负点；`-O = O`。
- `point_add(p, q)`：点加（覆盖单位元、互逆点 P+(-P)=O、倍点切线）。
- `scalar_mul(k, point)`：双加法标量乘；`k` 必须是 **0..18** 的整数（`k=0` → O），
  不做隐式模 19 约化。

### 编码（`ec17/_encoding.py`，SEC1 风格的固定长度教学子集）

- 点编码：无穷远 → `00`（1 字节）；有限点 (x,y) → `prefix || x`（2 字节），
  `02` 表示 y 偶、`03` 表示 y 奇，x 为单字节。
- `encode_point(point) -> bytes`
- `decode_point(data, *, allow_infinity=True)`：严格解码。
- 标量：`encode_scalar(n)` / `decode_scalar(data, *, name="scalar")`，0..18 各 1 字节。

### Schnorr 教学签名（`ec17/_schnorr.py`）

- `derive_public_key(secret_key) -> Point`，`secret_key ∈ 1..18`。
- `sign(secret_key, message: bytes, nonce) -> Signature`，**nonce 由调用方显式
  提供**（∈ 1..18，0 被禁止），不读随机源、不读密钥文件。
- `challenge(r, public_key, message) -> int`：
  `e = SHA256( encode(R) ∥ encode(P) ∥ message ) mod 19`。
- `s = (nonce + e·secret_key) mod 19`。
- 严格验签：
  - `verify(message, public_key, r, s) -> bool`
  - `assert_verify(message, public_key, r, s) -> None`（等式失败抛异常）
  - `verify_encoded(message, public_key_enc, r_enc, s_enc) -> bool`（字节入口）
  - `encode_signature(sig) -> bytes`（固定 3 字节：2 字节 R + 1 字节 s）、
    `decode_signature(data, message) -> Signature`

验签要求：**s ∈ 0..18；R、P 都不能是无穷远点且必须在曲线上**。
结构/范围非法抛对应可定位异常；仅“结构合法但等式 `s·G = R + e·P` 不成立”时
`verify` 返回 `False`（`assert_verify` 抛 `SignatureMismatchError`）。

### 会话层（`ec17/_session.py`）：会话 ID + nonce 状态机 + 请求幂等

在不改变上述纯函数接口的前提下新增的有状态层。`SigningSession` 绑定一个
教学私钥与一个字符串会话 ID；`SessionRegistry` 按 ID 管理多个会话。
nonce 状态与请求记录全部**按会话隔离**，只存在于内存。

状态常量：`NONCE_RESERVED="reserved"`、`NONCE_USED="used"`、
`NONCE_REVOKED="revoked"`。每个 nonce（1..18）在一个会话内的生命周期：

```
  (不存在) ──reserve_nonce──▶ reserved ──sign(m)──▶ used(绑定 m)
                                  │                     │
                                  └──── revoke_nonce ───┴──▶ revoked（终态）
```

`SigningSession(session_id, secret_key)` 的方法：

- `reserve_nonce(nonce)`：预留；同一 nonce 在任何状态下都不能再次预留
  （已使用/已作废均**不回收**），冲突抛 `NonceReservationError`。
- `sign(request_id, message, nonce) -> Signature`：
  - 必须先预留；未预留抛 `NonceNotReservedError`（阶段乱序）；
  - 已作废 nonce 抛 `NonceLifecycleError`；
  - 已使用 nonce 签**不同消息**抛 `NonceReuseError`，nonce 保持 used；
    签**同一条消息**允许（结果确定性相同）；
  - **请求 ID 幂等**：同一 `request_id` + 相同 (message, nonce) 重放，
    返回首次的同一个 `Signature` 对象；参数不同抛
    `IdempotencyConflictError`，不做任何状态变更；
  - 任何输入/阶段校验失败都**不改变状态、不登记请求 ID**（无半更新；
    签名计算本身是对旧纯函数 `ec17.sign` 的调用，在校验全部通过后执行）。
- `revoke_nonce(nonce)`：reserved/used → revoked；从未预留抛
  `NonceNotReservedError`，重复作废抛 `NonceLifecycleError`。
- `nonce_status(nonce)`：返回 `reserved`/`used`/`revoked`；从未预留返回
  `None`（关闭后仍可查询）。
- `close()`：关闭后预留/签名/作废/重复关闭全部抛 `SessionPhaseError`；
  只读属性 `session_id`、`public_key`、`is_closed` 与 `nonce_status` 仍可用。

`SessionRegistry()` 的方法：`create_session(session_id, secret_key)`
（ID 重复抛 `SessionAlreadyExistsError`，非法参数不留空壳会话）、
`get_session(id)`（未知 ID 抛 `SessionNotFoundError`）、
`session_exists(id)`、`session_ids()`、
`close_session(id)`（关闭并从注册表注销；注销后同 ID 可重新创建）。

会话/请求 ID 的边界：必须是**非空 str**，长度 1..`MAX_ID_CHARS`(=256) 字符，
拒绝控制字符（换行/制表符等）；`bytes` 不隐式解码。

## 错误语义（`ec17/_errors.py`）

所有异常继承 `EC17Error`；类型错误同时是内置 `TypeError`。消息一律带参数名。

- 类型：`TypeValidationError`（拒绝 **bool 冒充整数**、拒绝 float，
  尤其拒绝 **NaN/±Infinity**）、`MessageTypeError`。
- 点：`CoordinateOutOfDomainError`（坐标不在 0..16）、`PointNotOnCurveError`
  （域内但不满足方程）、`PointAtInfinityError`。
- 编码：`EmptyEncodingError`、`TruncatedEncodingError`、
  `InvalidEncodingPrefixError`、`OutOfDomainEncodingError`（点 x≥17 / 标量≥19）、
  `NonShortestEncodingError`（任何尾随字节、`00` 后携带字节）。
- 签名：`ScalarOutOfRangeError`、`SignatureMismatchError`、
  `InvalidSecretKeyError`、`InvalidNonceError`、`MessageTooLongError`。
- 会话：`InvalidSessionIdError`（同时是 `TypeError`）、
  `SessionNotFoundError`、`SessionAlreadyExistsError`、
  `SessionPhaseError`（关闭后变更/重复关闭）、
  `NonceReservationError`（重复预留）、`NonceNotReservedError`
  （操作从未预留的 nonce，含未预留先签名的阶段乱序）、
  `NonceLifecycleError`（作废 nonce 签名、重复作废）、
  `NonceReuseError`（已用 nonce 签不同消息）、
  `IdempotencyConflictError`（请求 ID 重放参数不一致）。

设计原则：非法输入**报错而非静默纠正**；会话层的每次状态变更都在输入与
阶段全部校验通过、签名计算成功之后一次性提交，失败不留半更新状态。
纯函数层不存在“部分成功”的有状态变更；本库没有“搜索预算”类算法，
也不区分预算耗尽/无解。

### 错误奇偶前缀

翻转奇偶前缀（`02↔03`）本身**不是**编码错误——它规范地解码为原点的负点
（-R），随后因验签等式不成立被拒绝。这与“非最短/域外编码”是两类不同问题。

### s+19 可塑性

数学上 `(s+19)·G = s·G`（模群阶）客观成立，但本协议在**输入边界**直接拒绝
任何越界标量：`s=19` 抛 `ScalarOutOfRangeError`，字节 `0x13` 抛
`OutOfDomainEncodingError`，不做隐式约化。

## 输入上限（接口边界）

- 点坐标 x,y：整数，0..16；群标量（s / scalar_mul 的 k）：0..18。
- 私钥：1..18；签名 nonce：1..18。
- 消息：`bytes`，长度 0..`MAX_MESSAGE_BYTES`(=65 535) 字节；`str` 不隐式编码。
- 会话 ID / 请求 ID：非空 `str`，1..`MAX_ID_CHARS`(=256) 字符，无控制字符。
- 编码长度：点 1 或 2 字节、标量恰 1 字节、签名帧恰 3 字节。
- 所有整数参数拒绝 `bool`、`float`（含 NaN/Infinity）。

## 浮点与误差口径

核心算法只做**整数模运算**，代码路径中没有浮点结果，因此不存在浮点误差或
容差问题，也不以宽容差掩盖边界。唯一接触 `math` 的地方是用 `math.isfinite`
来**拒绝** NaN/Infinity 输入。

## 设计取舍

- 无穷远点用 `None` 而不是引入专门类，贴合教学公式，且让“R/P 不能无穷”的
  检查显式可见。
- 坐标只有一个字节（域为 17），编码刻意采用固定长度，使“非最短编码”有
  明确、可机械判定的含义（任何多余尾随字节即拒绝）。
- 验签对“结构非法”与“等式不成立”分别处理：前者抛异常（可定位），后者
  返回 `False`，避免把篡改误报成程序错误。
- 群运算在每个入口重复做点校验而非只在边界校验，教学上保证任何组合调用
  都不可能处理非法点；曲线极小，性能无关紧要。

## 测试与独立性

`tests/reference.py` 是**独立参考实现，绝不 import 被测核心**（有 AST 测试
强制保证），并用两条互相独立的路线给出期望值：
(1) 朴素仿射公式 + 重复相加；(2) 枚举 G 的全部倍数构建离散对数指数表，
群运算退化为指数的整数加法。

测试覆盖：穷举 19×19 全加法表与 19³ 全三元组结合律、点集基数、G 的阶、
无穷远单位元、逆点、交换/结合律；编码的空/截断/非法前缀/域外/非最短/
错误奇偶；签名 324 组 (私钥×nonce) 对独立参考的全量比对、s=0 合法签名、
篡改消息、错误公钥、翻转 R 奇偶、**s+19 可塑性在边界被拒**、R/P 无穷远与
不在曲线上、消息类型与长度上限、3 字节签名帧的各类畸形。
会话层另覆盖：6 私钥×18 nonce×2 消息对独立参考的枚举比对、预留→使用→
作废全状态机、重复预留（含 used/revoked 不回收）、同 nonce 签不同消息被拒
且不登记失败请求、**请求 ID 幂等重放与参数冲突不留半更新**、未预留先签名/
作废后签名/关闭后变更等阶段乱序、会话隔离与关闭注销后同 ID 重建；
并用解析关系 `sk=(s1-s2)/(e1-e2) mod 19` 由两组独立参考向量代数解出私钥，
说明防重用的必要性。
编解码往返一致只作为**补充**断言，不作为期望值来源。

## demo.py

`python demo.py` 现场穷举曲线点、核对阶，用固定的 `secret_key=7, nonce=13,
message=b"ec17-schnorr-teaching"` 真实生成并验证一个签名（打印 R/P 编码、
SHA256、e、s 与验签结果），并**实际触发**两个旧边界：篡改末字节的消息
（`SignatureMismatchError`，`verify → False`）与 `s+19`（`ScalarOutOfRangeError`）。
随后演示会话层：未预留先签名（阶段乱序）、预留→签名→used、请求 ID 幂等
重放与换参数冲突、同 nonce 签不同消息被拒且不回收/不登记失败请求、
reserved→revoked 后签名与重复作废被拒、用解析关系现场从重用向量解出私钥、
会话关闭后的阶段乱序与同 ID 重建。不含 `sleep`，不使用预录结果，也不做
压力测试。

## 已知限制

- 仅支持这一条 17 阶小曲线与上述固定协议，不支持任意曲线参数、随机 nonce、
  批验签、DER/SEC1 多字节整数编码或任何标准序列化。
- nonce 仍由调用方显式给小整数；会话层只在**单进程内存对象**内跟踪
  reserved/used/revoked 与请求幂等，**没有持久化与崩溃恢复**（进程退出状态
  即丢失），**不是线程安全**的，也不防跨会话/跨实例的 nonce 重用。
- 不提供任何侧信道防护（标量乘非常量时间）；在 19 元素群上也无安全可言。
- 无两方/阈值签名：一个 `SigningSession` 只绑定一个私钥。
- 无版本化/前向兼容承诺：这是一次性教学交付。

## 目录

```
ec17/            可导入库
  __init__.py      公共接口导出
  _errors.py       错误类型与语义
  _curve.py        曲线点加/倍乘/标量乘
  _encoding.py     点与标量压缩编码（严格/最短/域外检查）
  _schnorr.py      Schnorr 风格教学签名与严格验签（纯函数）
  _session.py      会话 ID / nonce 状态机 / 请求 ID 幂等（有状态层）
tests/
  reference.py                     独立参考（不依赖被测核心）
  test_group_law.py                穷举群表/结合律/单位元/逆点
  test_encoding.py                 编码严格性
  test_schnorr.py                  验签/篡改/可塑性/无穷与离曲线
  test_session.py                  会话/nonce 生命周期/幂等/阶段乱序
  test_reference_independence.py   参考隔离性（AST）
demo.py          固定输入演示
README.md
requirements.txt （仅说明：标准库，无第三方依赖）
```
