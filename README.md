# ec17 — 椭圆曲线教学签名的严格验签（仅教学，不安全）

为离线密码工程教学实现的可复用库：在小素域椭圆曲线
**y² = x³ + 2x + 2 (mod 17)** 上实现点加/倍乘、压缩点编码，以及一个
Schnorr 风格教学签名的**严格验签**；并在无状态原语之上提供**带会话 ID 与
nonce 生命周期（预留/使用/作废）的有状态签名会话**，防同 nonce 签不同消息、
支持重复请求幂等与阶段乱序拒绝。

> ⚠️ **教学专用，不提供任何安全性。** 群只有 19 个元素，私钥空间可瞬间穷举；
> 无状态 `sign` 的 nonce 由调用方显式给定；会话层只在**单进程内存**内跟踪
> nonce 状态，不持久化、无并发锁、无崩溃恢复；**禁止使用真实密钥/密钥文件**。
> 本库只实现题面契约的有限数学/协议子集，**不兼容也不宣称兼容** RFC 6979、
> secp256k1、FIPS 186 等任何行业标准。

## 运行环境

- Python **3.14.7**（Linux 原生验证；仅使用标准库 `hashlib`、`dataclasses`、
  `enum`、`math`、`unittest`）
- **无需安装任何第三方依赖**，安装 Python 后即可运行
- 核心、测试、演示全部**离线**：不联网、不需要账号/硬件/数据库/中间件/云 API/Docker
- 示例数据由仓库内确定性代码生成，无随机源、无外部附件

## 准确命令

```bash
python -m unittest discover -s tests -v   # 运行必要测试（90 个，约 0.2 秒）
python demo.py                            # 固定输入演示（约 0.04 秒，远低于 90 秒）
```

## 公开数据结构

| 名称 | 含义 |
|---|---|
| `Point` | 有限点，类型 `tuple[int, int]`，即 `(x, y)`，x,y ∈ 0..16 |
| `INFINITY` | 无穷远点（群单位元），用 `None` 表示 |
| `Signature` | 不可变 dataclass：`r: Point`、`s: int`、`message: bytes` |
| `NonceStatus` | nonce 生命周期枚举：`RESERVED` / `USED` / `VOIDED` |
| `SigningSession` | 带会话 ID 与 nonce 状态机的有状态签名会话（内存态） |

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

以上无状态接口的语义在本次迭代中**完全不变**，原有合法调用与旧测试断言全部保留。

### 有状态签名会话（`ec17/_session.py`，本次新增）

`SigningSession(session_id, secret_key)` 在无状态原语之上提供进程内、内存态的
会话层。会话 ID 为 1..`MAX_SESSION_ID_BYTES`(=256) 字节的 `bytes`（`str`
不隐式编码）；私钥仍为 1..18。

nonce（1..18）在**每个会话内独立**经历状态机：

```
(从未出现) ──reserve_nonce(k, m)──▶ RESERVED ──sign(m, k)──▶ USED
                                       │                         │
                                       │   同一(nonce,消息)重复 sign：幂等返回缓存签名
                                       │   不同消息 sign：NonceReuseError
                                       ▼
                                    VOIDED（终态：作废/失败都不回收为可用）
```

- `reserve_nonce(nonce, message) -> bool`：**阶段 1**，预留 nonce 并绑定待签
  消息（预留即绑定，才能判定“同一 nonce 不能签不同消息”）。首次预留返回
  `True`；对同一 `(nonce, message)` 重复预留是幂等 no-op，返回 `False`、
  状态不变。
- `sign(message, nonce) -> Signature`：**阶段 2**，只能对“已预留且消息一致”
  的 nonce 调用；成功后状态为 `used`。**同会话、同 nonce、同消息字节**的
  重复请求幂等，返回首次生成的**同一个签名对象**（不重复计算）；已用 nonce
  收到不同消息抛 `NonceReuseError`。
- `void_nonce(nonce)`：把已预留或已使用的 nonce 置为作废终态。作废不可逆：
  作废后再预留/使用/作废都抛 `NonceVoidedError`。**签名计算失败时该 nonce
  自动作废，绝不回收为可用**（题面要求）。
- 查询：`nonce_status(nonce)`（`"available"/"reserved"/"used"/"voided"`）、
  `nonce_message(nonce)`、`signature_for(nonce)`、`reserved_nonces()`、
  `used_nonces()`、`voided_nonces()`；属性 `session_id`、`secret_key`、
  `public_key`。

阶段乱序的错误：未预留就 `sign`/`void_nonce` 抛 `NonceNotReservedError`；
预留后用不同消息签名（尚未使用）或重复预留成别的消息抛 `NonceStateError`。
所有输入先完整校验、通过后才落状态，**任何失败都不留半更新**（测试逐条核对）。

会话状态是对象实例级的：不同 `SigningSession` 对象之间互不共享，即使它们的
会话 ID 相同。

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
- 会话（新增）：`SessionError`（基类）、`InvalidSessionIdError`（空或超长
  会话 ID）、`NonceStateError`（阶段乱序基类）、`NonceNotReservedError`
  （未预留就使用/作废）、`NonceVoidedError`（操作已作废 nonce）、
  `NonceReuseError`（同一 nonce 已签过一条消息又要求签不同消息）。

设计原则：非法输入**报错而非静默纠正**。曲线/编码/签名层都是纯函数，
不存在“部分成功”的变更；会话层是唯一有状态的部分，但每次状态迁移都在
**全部输入校验通过之后**一次性落状态，失败路径要么完全不改状态、要么按
题面把 nonce 置为作废终态（绝不半更新、绝不回收为可用）。本库没有“搜索
预算”类算法，也不区分预算耗尽/无解。

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
- 会话 ID：`bytes`，长度 1..`MAX_SESSION_ID_BYTES`(=256) 字节。
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
- 会话层刻意只做“单对象内存态”：消息在预留时就绑定（否则无法定义“同一
  nonce 不能签不同消息”），幂等以消息字节逐字节相等为准（`bytearray`
  同内容视为同一请求），作废设计为不可逆终态——宁可废掉一个 nonce 也不
  让它回到可用池，贴合题面“失败也不回收”。

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
会话层（`tests/test_session.py`，28 个用例）：全 18 个 nonce 对独立参考的
签名比对、空消息与会话 ID 长度边界、**重复请求幂等**（返回同一签名对象/
重复预留 no-op）、**同一 nonce 签不同消息抛 NonceReuseError** 并用解析关系
`sk=(s1-s2)(e1-e2)^{-1} mod 19` 独立核算私钥泄露、**阶段乱序**（未预留就
签名/作废、预留消息不一致、重复预留）、预留/已用 nonce 作废与作废终态、
底层签名失败后 nonce 作废不回收（注入失败）、非法输入不留半更新、构造校验
与多会话对象隔离。
编解码往返一致只作为**补充**断言，不作为期望值来源。

## demo.py

`python demo.py` 现场穷举曲线点、核对阶，用固定的 `secret_key=7, nonce=13,
message=b"ec17-schnorr-teaching"` 真实生成并验证一个签名（打印 R/P 编码、
SHA256、e、s 与验签结果），并**实际触发**两个拒绝边界：篡改末字节的消息
（`SignatureMismatchError`，`verify → False`）与 `s+19`（`ScalarOutOfRangeError`）。
随后演示有状态会话（`secret_key=7, session_id=b"demo-session-001"`）：
nonce=5 预留→签名（该固定数据恰好得到边界值 s=0）→同请求幂等重放；
同 nonce 签不同消息抛 `NonceReuseError`，并现场用解析关系还原出私钥 7；
未预留就签名抛 `NonceNotReservedError`；nonce=8 作废后重新预留抛
`NonceVoidedError`；空会话 ID、nonce=0 在边界被拒且状态不变。
不含 `sleep`，不使用预录结果，也不做压力测试。

## 已知限制

- 仅支持这一条 17 阶小曲线与上述固定协议，不支持任意曲线参数、随机 nonce、
  批验签、DER/SEC1 多字节整数编码或任何标准序列化。
- 无状态 `sign` 的 nonce 完全由调用方负责；重用 nonce 会直接泄露私钥
  （这正是教学要演示的风险）。
- `SigningSession` 状态仅在单进程内存中：**不持久化、无崩溃恢复、无并发
  锁/原子性承诺**；不做两方阈值签名、不去重跨会话对象（会话 ID 是调用方
  提供的标签，库不登记全局会话注册表）。
- 不提供任何侧信道防护（标量乘非常量时间）；在 19 元素群上也无安全可言。
- 无版本化/前向兼容承诺：这是一次性教学交付。

## 目录

```
ec17/            可导入库
  __init__.py      公共接口导出
  _errors.py       错误类型与语义
  _curve.py        曲线点加/倍乘/标量乘
  _encoding.py     点与标量压缩编码（严格/最短/域外检查）
  _schnorr.py      Schnorr 风格教学签名与严格验签（无状态）
  _session.py      会话 ID + nonce 预留/使用/作废状态机（本次新增）
tests/
  reference.py                     独立参考（不依赖被测核心）
  test_group_law.py                穷举群表/结合律/单位元/逆点
  test_encoding.py                 编码严格性
  test_schnorr.py                  验签/篡改/可塑性/无穷与离曲线
  test_session.py                  会话/nonce 生命周期/幂等/乱序/作废（新增）
  test_reference_independence.py   参考隔离性（AST）
demo.py          固定输入演示
README.md
requirements.txt （仅说明：标准库，无第三方依赖）
```
