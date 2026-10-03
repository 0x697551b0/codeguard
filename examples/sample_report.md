# CodeGuard 代码审查报告

> 生成时间：2026-10-03T16:48:05+00:00　|　模型：`mock-scripted-model`

## 一、总体结论

**整体风险等级：🔴 CRITICAL**
**代码质量评分：5 / 100**

【离线 Mock 模式】已按脚本完整跑通 Agent 闭环（推理 → 工具调用 → 观察 → 报告）。报告中的 12 条问题取自内置静态规则引擎在 `D:\软件工程实践\codeguard\examples\demo_buggy_code` 上的真实输出，因此可与 `python -m codeguard scan` 的结果交叉验证。语义层面的深入结论（逻辑缺陷、业务边界、并发时序等）需要配置真实 API Key 后由模型给出。

### 问题分布

| 严重级别 | 数量 |
| --- | ---: |
| 🟥 CRITICAL | 6 |
| 🟧 HIGH | 8 |
| 🟨 MEDIUM | 6 |
| 🟩 LOW | 29 |
| ⬜ INFO | 26 |
| **合计** | **75** |

## 二、问题清单（75 条）

### 1. 🟥 疑似硬编码密钥：API_TOKEN

- **位置：** `examples/demo_buggy_code/user_service.py:22`
- **级别：** CRITICAL　|　**类别：** security　|　**来源：** 规则引擎 `CG105`

```python
API_TOKEN = 'sk-l********'（已脱敏）
```

**问题说明：** 凭据硬编码在源码中，一旦进入版本库或日志即视为泄露，且无法按环境轮换。

**修复建议：** 改为 `os.environ['SERVICE_TOKEN']`，并通过 .env / 密钥管理服务注入；同时轮换已泄露的凭据。

### 2. 🟥 危险调用 `eval()`：任意代码执行（在 evaluate_filter 中）

- **位置：** `examples/demo_buggy_code/user_service.py:64`
- **级别：** CRITICAL　|　**类别：** security　|　**来源：** 规则引擎 `CG101`

```python
return eval(expression)
```

**问题说明：** `eval` 的输入若来自用户或外部数据，会被直接当作代码/命令执行。

**修复建议：** 改用 `ast.literal_eval`，或使用显式解析器（json / int()）。

### 3. 🟥 危险调用 `os.system()`：Shell 注入（在 run_backup 中）

- **位置：** `examples/demo_buggy_code/user_service.py:77`
- **级别：** CRITICAL　|　**类别：** security　|　**来源：** 规则引擎 `CG102`

```python
os.system(command)
```

**问题说明：** `os.system` 的输入若来自用户或外部数据，会被直接当作代码/命令执行。

**修复建议：** 改用不执行字符串的安全 API，并对输入做白名单校验。

### 4. 🟥 危险调用 `pickle.loads()`：反序列化可执行任意代码（在 restore_session 中）

- **位置：** `examples/demo_buggy_code/user_service.py:99`
- **级别：** CRITICAL　|　**类别：** security　|　**来源：** 规则引擎 `CG103`

```python
return pickle.loads(payload_bytes)
```

**问题说明：** `pickle.loads` 的输入若来自用户或外部数据，会被直接当作代码/命令执行。

**修复建议：** 改用不执行字符串的安全 API，并对输入做白名单校验。

### 5. 🟥 除数为字面量 0

- **位置：** `examples/demo_buggy_code/user_service.py:103`
- **级别：** CRITICAL　|　**类别：** reliability　|　**来源：** 规则引擎 `CG205`

```python
return amount / 0
```

**问题说明：** 该表达式必然抛出 `ZeroDivisionError`，属于确定性缺陷。

**修复建议：** 确认除数来源；若来自输入需显式校验并给出业务错误。

### 6. 🟥 shell=True 存在命令注入风险（在 cleanup_workspace 中）

- **位置：** `examples/demo_buggy_code/user_service.py:144`
- **级别：** CRITICAL　|　**类别：** security　|　**来源：** 规则引擎 `CG102`

```python
subprocess.call("rm -rf %s/*" % path, shell=True)
```

**问题说明：** shell=True 时命令交由系统 shell 解析，用户可控输入可注入任意命令。

**修复建议：** 改为列表参数并保持 shell=False：`subprocess.run(['ls', '-l'], check=True)`。

### 7. 🟧 疑似硬编码密钥：DB_PASSWORD

- **位置：** `examples/demo_buggy_code/user_service.py:21`
- **级别：** HIGH　|　**类别：** security　|　**来源：** 规则引擎 `CG105`

```python
DB_PASSWORD = 'Supe********'（已脱敏）
```

**问题说明：** 凭据硬编码在源码中，一旦进入版本库或日志即视为泄露，且无法按环境轮换。

**修复建议：** 改为 `os.environ['SERVICE_TOKEN']`，并通过 .env / 密钥管理服务注入；同时轮换已泄露的凭据。

### 8. 🟧 可变默认参数：load_users()（在 load_users 中）

- **位置：** `examples/demo_buggy_code/user_service.py:29`
- **级别：** HIGH　|　**类别：** reliability　|　**来源：** 规则引擎 `CG203`

```python
def load_users(db_path, include_deleted=[], verbose=True):
```

**问题说明：** 默认参数在函数定义时求值一次并被所有调用共享，就地修改会污染后续调用。

**修复建议：** 改用 `None` 哨兵：`def f(items=None): items = [] if items is None else items`。

### 9. 🟧 拼接后的 SQL 变量被直接执行：sql（在 find_user_by_email 中）

- **位置：** `examples/demo_buggy_code/user_service.py:55`
- **级别：** HIGH　|　**类别：** security　|　**来源：** 规则引擎 `CG106`

```python
cursor.execute(sql)
```

**问题说明：** 变量 `sql` 由格式化/拼接构造（见第 54 行），再交给 `execute` 执行，等价于拼接 SQL，存在注入风险。

**修复建议：** 把 SQL 写成固定模板并用驱动占位符传参：`sql = '... WHERE email = %s'` 然后 `cursor.execute(sql, (email,))`。

### 10. 🟧 关闭 TLS 校验：urllib.request.urlopen(verify=False)（在 check_remote_config 中）

- **位置：** `examples/demo_buggy_code/user_service.py:82`
- **级别：** HIGH　|　**类别：** security　|　**来源：** 规则引擎 `CG104`

```python
response = urllib.request.urlopen(url, verify=False)
```

**问题说明：** 关闭证书校验后无法防御中间人攻击，抓包即可窃取凭据。

**修复建议：** 移除 verify=False；自签证书场景请通过 `verify='/path/ca.pem'` 指定 CA。

### 11. 🟧 可变默认参数：process_batch()（在 process_batch 中）

- **位置：** `examples/demo_buggy_code/user_service.py:106`
- **级别：** HIGH　|　**类别：** reliability　|　**来源：** 规则引擎 `CG203`

```python
def process_batch(records, options={}):
```

**问题说明：** 默认参数在函数定义时求值一次并被所有调用共享，就地修改会污染后续调用。

**修复建议：** 改用 `None` 哨兵：`def f(items=None): items = [] if items is None else items`。

### 12. 🟧 可变默认参数：get_user_or_default()（在 get_user_or_default 中）

- **位置：** `examples/demo_buggy_code/user_service.py:122`
- **级别：** HIGH　|　**类别：** reliability　|　**来源：** 规则引擎 `CG203`

```python
def get_user_or_default(user_id, db_path, cache={}):
```

**问题说明：** 默认参数在函数定义时求值一次并被所有调用共享，就地修改会污染后续调用。

**修复建议：** 改用 `None` 哨兵：`def f(items=None): items = [] if items is None else items`。

### 13. 🟧 裸 except 会吞掉所有异常

- **位置：** `examples/demo_buggy_code/user_service.py:127`
- **级别：** HIGH　|　**类别：** reliability　|　**来源：** 规则引擎 `CG201`

```python
except:
```

**问题说明：** `except:` 会连 `KeyboardInterrupt`、`SystemExit` 一起吞掉，导致程序无法中断、错误被掩盖。

**修复建议：** 捕获具体异常类型（如 `except ValueError as exc:`），或至少 `except Exception:` 并记录日志后重新抛出。

### 14. 🟧 裸 except 会吞掉所有异常

- **位置：** `examples/demo_buggy_code/utils.py:52`
- **级别：** HIGH　|　**类别：** reliability　|　**来源：** 规则引擎 `CG201`

```python
except:
```

**问题说明：** `except:` 会连 `KeyboardInterrupt`、`SystemExit` 一起吞掉，导致程序无法中断、错误被掩盖。

**修复建议：** 捕获具体异常类型（如 `except ValueError as exc:`），或至少 `except Exception:` 并记录日志后重新抛出。

### 15. 🟨 SQL 变量被直接执行，需确认来源：query（在 load_users 中）

- **位置：** `examples/demo_buggy_code/user_service.py:36`
- **级别：** MEDIUM　|　**类别：** security　|　**来源：** 规则引擎 `CG106`

```python
cursor.execute(query)
```

**问题说明：** 变量 `query` 的取值无法静态确认，且未传任何参数，若其中含外部输入即构成注入。本条目列为需人工确认的提示。

**修复建议：** 确认该 SQL 是固定模板且参数经驱动占位符传入；否则改为参数化查询。

### 16. 🟨 open() 未使用 with 上下文管理器

- **位置：** `examples/demo_buggy_code/user_service.py:69`
- **级别：** MEDIUM　|　**类别：** reliability　|　**来源：** 规则引擎 `CG206`

```python
fh = open(output_path, "w")
```

**问题说明：** 异常路径下文件句柄不会及时释放，长驻进程会造成句柄泄漏。

**修复建议：** 改为 `with open(path, encoding='utf-8') as fh: ...`。

### 17. 🟨 疑似用弱随机数生成安全凭据：random.choice（在 generate_reset_token 中）

- **位置：** `examples/demo_buggy_code/user_service.py:90`
- **级别：** MEDIUM　|　**类别：** security　|　**来源：** 规则引擎 `CG107`

```python
token += random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
```

**问题说明：** `random` 基于梅森旋转算法，可被预测，不能用于安全敏感值。

**修复建议：** 改用 `secrets.token_urlsafe(32)` / `secrets.token_hex(16)`。

### 18. 🟨 `finally` 中使用 `return` 会吞掉异常

- **位置：** `examples/demo_buggy_code/user_service.py:146`
- **级别：** MEDIUM　|　**类别：** reliability　|　**来源：** 规则引擎 `CG208`

```python
return True
```

**问题说明：** `finally` 中的跳转语句会覆盖正在传播的异常，导致异常被静默丢弃、调用方拿到错误的正常返回值。

**修复建议：** 把清理逻辑只放在 `finally` 中，跳转语句移出 `finally`（或改为 `else` 分支）。

### 19. 🟨 捕获 `Exception` 后静默忽略

- **位置：** `examples/demo_buggy_code/user_service.py:153`
- **级别：** MEDIUM　|　**类别：** reliability　|　**来源：** 规则引擎 `CG202`

```python
except Exception:
```

**问题说明：** 宽泛捕获且既不记录日志也不重新抛出，故障会被完全静默，线上问题极难定位。

**修复建议：** 记录 `logger.exception(...)` 后重新抛出，或收窄捕获类型并给出降级逻辑。

### 20. 🟨 捕获 `Exception` 后静默忽略

- **位置：** `examples/demo_buggy_code/utils.py:33`
- **级别：** MEDIUM　|　**类别：** reliability　|　**来源：** 规则引擎 `CG202`

```python
except Exception as e:
```

**问题说明：** 宽泛捕获且既不记录日志也不重新抛出，故障会被完全静默，线上问题极难定位。

**修复建议：** 记录 `logger.exception(...)` 后重新抛出，或收窄捕获类型并给出降级逻辑。

### 21. 🟩 字面量重复出现 3 次：3

- **位置：** `examples/demo_buggy_code/user_service.py:25`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG305`

```python
3
```

**问题说明：** 同一个字面量在 3 处硬编码，修改时容易遗漏。

**修复建议：** 提取为模块级常量（如 `MAX_RETRY = 3`），或放入配置文件。

### 22. 🟩 缺少文档字符串：load_users（在 load_users 中）

- **位置：** `examples/demo_buggy_code/user_service.py:29`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def load_users(db_path, include_deleted=[], verbose=True):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 23. 🟩 缺少文档字符串：find_user_by_email（在 find_user_by_email 中）

- **位置：** `examples/demo_buggy_code/user_service.py:52`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def find_user_by_email(conn, email):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 24. 🟩 应使用 `is`/`is not` 比较 None

- **位置：** `examples/demo_buggy_code/user_service.py:57`
- **级别：** LOW　|　**类别：** reliability　|　**来源：** 规则引擎 `CG204`

```python
if row == None:
```

**问题说明：** `==` 会调用重载的 `__eq__`，语义上不可靠；单例比较应使用 `is`。

**修复建议：** 改写为 `x is None` / `x is not None`。

### 25. 🟩 缺少文档字符串：export_users（在 export_users 中）

- **位置：** `examples/demo_buggy_code/user_service.py:67`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def export_users(db_path, output_path):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 26. 🟩 缺少文档字符串：run_backup（在 run_backup 中）

- **位置：** `examples/demo_buggy_code/user_service.py:75`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def run_backup(script_name):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 27. 🟩 缺少文档字符串：check_remote_config（在 check_remote_config 中）

- **位置：** `examples/demo_buggy_code/user_service.py:81`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def check_remote_config(url):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 28. 🟩 缺少文档字符串：generate_reset_token（在 generate_reset_token 中）

- **位置：** `examples/demo_buggy_code/user_service.py:87`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def generate_reset_token():
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 29. 🟩 缺少文档字符串：hash_password（在 hash_password 中）

- **位置：** `examples/demo_buggy_code/user_service.py:94`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def hash_password(password):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 30. 🟩 缺少文档字符串：restore_session（在 restore_session 中）

- **位置：** `examples/demo_buggy_code/user_service.py:98`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def restore_session(payload_bytes):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 31. 🟩 缺少文档字符串：divide（在 divide 中）

- **位置：** `examples/demo_buggy_code/user_service.py:102`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def divide(amount, total):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 32. 🟩 缺少文档字符串：process_batch（在 process_batch 中）

- **位置：** `examples/demo_buggy_code/user_service.py:106`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def process_batch(records, options={}):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 33. 🟩 缺少文档字符串：get_user_or_default（在 get_user_or_default 中）

- **位置：** `examples/demo_buggy_code/user_service.py:122`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def get_user_or_default(user_id, db_path, cache={}):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 34. 🟩 缺少文档字符串：validate_age（在 validate_age 中）

- **位置：** `examples/demo_buggy_code/user_service.py:136`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def validate_age(age):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 35. 🟩 缺少文档字符串：cleanup_workspace（在 cleanup_workspace 中）

- **位置：** `examples/demo_buggy_code/user_service.py:142`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def cleanup_workspace(path):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 36. 🟩 缺少文档字符串：fetch_json（在 fetch_json 中）

- **位置：** `examples/demo_buggy_code/user_service.py:149`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def fetch_json(url):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 37. 🟩 变量遮蔽内置名称：list

- **位置：** `examples/demo_buggy_code/user_service.py:158`
- **级别：** LOW　|　**类别：** style　|　**来源：** 规则引擎 `CG404`

```python
list = [1, 2, 3]
```

**问题说明：** 以 `list` 作为变量名会遮蔽同名内置对象，后续代码无法再正常使用它。

**修复建议：** 改名，例如 `list_value` / `items`（list）等语义化名称。

### 38. 🟩 缺少文档字符串：compute_stats（在 compute_stats 中）

- **位置：** `examples/demo_buggy_code/user_service.py:161`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def compute_stats(values):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 39. 🟩 未使用的导入：sys

- **位置：** `examples/demo_buggy_code/utils.py:8`
- **级别：** LOW　|　**类别：** style　|　**来源：** 规则引擎 `CG403`

```python
import sys
```

**问题说明：** 导入的 `sys` 在文件中未被引用，属于死代码。

**修复建议：** 删除 `import sys`；若属于可选依赖，改为在函数内延迟导入。

### 40. 🟩 缺少文档字符串：parse_config_line（在 parse_config_line 中）

- **位置：** `examples/demo_buggy_code/utils.py:11`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def parse_config_line(line):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 41. 🟩 缺少文档字符串：is_valid_email（在 is_valid_email 中）

- **位置：** `examples/demo_buggy_code/utils.py:24`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def is_valid_email(email):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 42. 🟩 应使用 `is`/`is not` 比较 None

- **位置：** `examples/demo_buggy_code/utils.py:25`
- **级别：** LOW　|　**类别：** reliability　|　**来源：** 规则引擎 `CG204`

```python
return re.match(r"^[^@]+@[^@]+\.[^@]+$", email) != None
```

**问题说明：** `==` 会调用重载的 `__eq__`，语义上不可靠；单例比较应使用 `is`。

**修复建议：** 改写为 `x is None` / `x is not None`。

### 43. 🟩 缺少文档字符串：retry_call（在 retry_call 中）

- **位置：** `examples/demo_buggy_code/utils.py:28`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def retry_call(func, times=3, delay=1):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 44. 🟩 缺少文档字符串：format_timestamp（在 format_timestamp 中）

- **位置：** `examples/demo_buggy_code/utils.py:38`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def format_timestamp(ts):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 45. 🟩 缺少文档字符串：truncate（在 truncate 中）

- **位置：** `examples/demo_buggy_code/utils.py:42`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def truncate(text, limit):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 46. 🟩 缺少文档字符串：safe_int（在 safe_int 中）

- **位置：** `examples/demo_buggy_code/utils.py:49`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def safe_int(value):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 47. 🟩 缺少文档字符串：merge_dicts（在 merge_dicts 中）

- **位置：** `examples/demo_buggy_code/utils.py:56`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def merge_dicts(a, b):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 48. 🟩 缺少文档字符串：get_env_or_default（在 get_env_or_default 中）

- **位置：** `examples/demo_buggy_code/utils.py:63`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def get_env_or_default(name, default=None):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 49. 🟩 缺少文档字符串：chunk（在 chunk 中）

- **位置：** `examples/demo_buggy_code/utils.py:69`
- **级别：** LOW　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG304`

```python
def chunk(items, size=100):
```

**问题说明：** 公共函数没有 docstring，调用方难以了解契约与副作用。

**修复建议：** 补充简要说明用户意图的 docstring（推荐 Google 风格）。

### 50. ⬜ 缺少返回值类型注解：load_users（在 load_users 中）

- **位置：** `examples/demo_buggy_code/user_service.py:29`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def load_users(db_path, include_deleted=[], verbose=True):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 51. ⬜ 缺少返回值类型注解：find_user_by_email（在 find_user_by_email 中）

- **位置：** `examples/demo_buggy_code/user_service.py:52`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def find_user_by_email(conn, email):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 52. ⬜ 缺少返回值类型注解：evaluate_filter（在 evaluate_filter 中）

- **位置：** `examples/demo_buggy_code/user_service.py:62`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def evaluate_filter(expression):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 53. ⬜ 缺少返回值类型注解：export_users（在 export_users 中）

- **位置：** `examples/demo_buggy_code/user_service.py:67`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def export_users(db_path, output_path):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 54. ⬜ 缺少返回值类型注解：run_backup（在 run_backup 中）

- **位置：** `examples/demo_buggy_code/user_service.py:75`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def run_backup(script_name):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 55. ⬜ 缺少返回值类型注解：check_remote_config（在 check_remote_config 中）

- **位置：** `examples/demo_buggy_code/user_service.py:81`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def check_remote_config(url):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 56. ⬜ 缺少返回值类型注解：generate_reset_token（在 generate_reset_token 中）

- **位置：** `examples/demo_buggy_code/user_service.py:87`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def generate_reset_token():
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 57. ⬜ 缺少返回值类型注解：hash_password（在 hash_password 中）

- **位置：** `examples/demo_buggy_code/user_service.py:94`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def hash_password(password):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 58. ⬜ 缺少返回值类型注解：restore_session（在 restore_session 中）

- **位置：** `examples/demo_buggy_code/user_service.py:98`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def restore_session(payload_bytes):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 59. ⬜ 缺少返回值类型注解：divide（在 divide 中）

- **位置：** `examples/demo_buggy_code/user_service.py:102`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def divide(amount, total):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 60. ⬜ 缺少返回值类型注解：process_batch（在 process_batch 中）

- **位置：** `examples/demo_buggy_code/user_service.py:106`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def process_batch(records, options={}):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 61. ⬜ 缺少返回值类型注解：get_user_or_default（在 get_user_or_default 中）

- **位置：** `examples/demo_buggy_code/user_service.py:122`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def get_user_or_default(user_id, db_path, cache={}):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 62. ⬜ 缺少返回值类型注解：validate_age（在 validate_age 中）

- **位置：** `examples/demo_buggy_code/user_service.py:136`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def validate_age(age):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 63. ⬜ 缺少返回值类型注解：cleanup_workspace（在 cleanup_workspace 中）

- **位置：** `examples/demo_buggy_code/user_service.py:142`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def cleanup_workspace(path):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 64. ⬜ 缺少返回值类型注解：fetch_json（在 fetch_json 中）

- **位置：** `examples/demo_buggy_code/user_service.py:149`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def fetch_json(url):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 65. ⬜ 缺少返回值类型注解：compute_stats（在 compute_stats 中）

- **位置：** `examples/demo_buggy_code/user_service.py:161`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def compute_stats(values):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 66. ⬜ 行长度超限（131 > 120）

- **位置：** `examples/demo_buggy_code/user_service.py:173`
- **级别：** INFO　|　**类别：** style　|　**来源：** 规则引擎 `CG401`

```python
return {"average": average, "max": maximum, "min": minimum, "stddev": stddev, "median": median, "count": count, "total": total}
```

**问题说明：** 超长行影响可读性，且在代码评审/diff 中难以并排查看。

**修复建议：** 按 PEP 8 折行，或提取中间变量以缩短表达式。

### 67. ⬜ 缺少返回值类型注解：parse_config_line（在 parse_config_line 中）

- **位置：** `examples/demo_buggy_code/utils.py:11`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def parse_config_line(line):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 68. ⬜ 缺少返回值类型注解：is_valid_email（在 is_valid_email 中）

- **位置：** `examples/demo_buggy_code/utils.py:24`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def is_valid_email(email):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 69. ⬜ 缺少返回值类型注解：retry_call（在 retry_call 中）

- **位置：** `examples/demo_buggy_code/utils.py:28`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def retry_call(func, times=3, delay=1):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 70. ⬜ 缺少返回值类型注解：format_timestamp（在 format_timestamp 中）

- **位置：** `examples/demo_buggy_code/utils.py:38`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def format_timestamp(ts):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 71. ⬜ 缺少返回值类型注解：truncate（在 truncate 中）

- **位置：** `examples/demo_buggy_code/utils.py:42`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def truncate(text, limit):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 72. ⬜ 缺少返回值类型注解：safe_int（在 safe_int 中）

- **位置：** `examples/demo_buggy_code/utils.py:49`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def safe_int(value):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 73. ⬜ 缺少返回值类型注解：merge_dicts（在 merge_dicts 中）

- **位置：** `examples/demo_buggy_code/utils.py:56`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def merge_dicts(a, b):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 74. ⬜ 缺少返回值类型注解：get_env_or_default（在 get_env_or_default 中）

- **位置：** `examples/demo_buggy_code/utils.py:63`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def get_env_or_default(name, default=None):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

### 75. ⬜ 缺少返回值类型注解：chunk（在 chunk 中）

- **位置：** `examples/demo_buggy_code/utils.py:69`
- **级别：** INFO　|　**类别：** maintainability　|　**来源：** 规则引擎 `CG307`

```python
def chunk(items, size=100):
```

**问题说明：** 无返回注解会降低 mypy 等静态检查的有效性。

**修复建议：** 补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。

## 三、值得肯定的设计

- 内置静态规则引擎与 Agent 循环解耦，可单独作为 CI 质量门禁复用
- 工具层对工作区做了路径沙箱约束，避免越权读取

## 四、需要人工确认

- [ ] 配置 CODEGUARD_API_KEY 后重新运行，以获得基于语义理解的完整审查结论

## 附录

**审查范围：**

- `examples/demo_buggy_code`

**运行指标：**

| 指标 | 值 |
| --- | --- |
| 迭代轮数 | 3 |
| 工具调用次数 | 2 |
| 工具明细 | run_static_analysis×1、submit_review×1 |
| Token 用量 | 540（prompt 360 / completion 180） |
| 耗时 | 0.02 秒 |
| 结束原因 | `submitted` |
| 模式 | 离线 Mock（未调用真实模型） |

---

_本报告由 CodeGuard 生成。规则引擎结果可能存在误报，语义结论请结合业务上下文复核。_