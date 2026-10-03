"""示例：一个"问题很多"的用户管理模块，用于演示 CodeGuard 的审查能力。

⚠️ 本文件**故意**包含各类典型缺陷，请勿用于生产环境。
它覆盖了内置规则引擎的大部分类别：
    * 安全：SQL 注入、硬编码密钥、shell 注入、关闭 TLS 校验、弱随机数
    * 可靠性：裸 except、可变默认参数、资源泄漏、除零、assert 校验
    * 可维护性：超长函数、深层嵌套、重复字面量、print 输出
    * 风格：超长行、未使用导入、遮蔽内置名
"""

import hashlib
import json
import os
import pickle
import random
import sqlite3
import subprocess
import urllib.request


DB_PASSWORD = "SuperSecret123!"
API_TOKEN = "sk-live-9f8a7b6c5d4e3f2a1b0c"

DEFAULT_TIMEOUT = 30
MAX_RETRY = 3
RETRY_DELAY = 2


def load_users(db_path, include_deleted=[], verbose=True):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    if include_deleted:
        query = "SELECT * FROM users WHERE deleted = 1"
    else:
        query = "SELECT * FROM users WHERE deleted = 0"
    cursor.execute(query)
    rows = cursor.fetchall()
    result = []
    for row in rows:
        item = {}
        item["id"] = row[0]
        item["name"] = row[1]
        item["email"] = row[2]
        item["created_at"] = row[3]
        item["status"] = row[4]
        if verbose:
            print("loaded user", item["id"])
        result.append(item)
    return result


def find_user_by_email(conn, email):
    cursor = conn.cursor()
    sql = "SELECT id, name FROM users WHERE email = '%s'" % email
    cursor.execute(sql)
    row = cursor.fetchone()
    if row == None:
        return {}
    return {"id": row[0], "name": row[1]}


def evaluate_filter(expression):
    """缺陷：把外部传入的表达式直接交给 eval 执行。"""
    return eval(expression)


def export_users(db_path, output_path):
    users = load_users(db_path)
    fh = open(output_path, "w")
    fh.write(json.dumps(users))
    fh.close()
    return len(users)


def run_backup(script_name):
    command = "bash /opt/backup/%s.sh" % script_name
    os.system(command)
    return True


def check_remote_config(url):
    response = urllib.request.urlopen(url, verify=False)
    data = json.loads(response.read())
    return data


def generate_reset_token():
    token = ""
    for index in range(32):
        token += random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
    return token


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def restore_session(payload_bytes):
    return pickle.loads(payload_bytes)


def divide(amount, total):
    return amount / 0


def process_batch(records, options={}):
    options.setdefault("strict", True)
    results = []
    for record in records:
        if record:
            if "value" in record:
                if record["value"] is not None:
                    if isinstance(record["value"], (int, float)):
                        if record["value"] > 0:
                            if options["strict"]:
                                results.append(record["value"] * 2)
                            else:
                                results.append(record["value"])
    return results


def get_user_or_default(user_id, db_path, cache={}):
    if user_id in cache:
        return cache[user_id]
    try:
        users = load_users(db_path)
    except:
        return None
    for user in users:
        if user["id"] == user_id:
            cache[user_id] = user
            return user
    return None


def validate_age(age):
    assert age > 0, "age must be positive"
    assert age < 200, "age too large"
    return age


def cleanup_workspace(path):
    try:
        subprocess.call("rm -rf %s/*" % path, shell=True)
    finally:
        return True


def fetch_json(url):
    try:
        with urllib.request.urlopen(url, timeout=DEFAULT_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        pass


# 缺陷：遮蔽内置名称 `list`
list = [1, 2, 3]


def compute_stats(values):
    total = 0
    count = 0
    for value in values:
        total = total + value
        count = count + 1
    average = total / count
    maximum = max(values)
    minimum = min(values)
    variance = sum((value - average) ** 2 for value in values) / count
    stddev = variance ** 0.5
    median = sorted(values)[count // 2]
    return {"average": average, "max": maximum, "min": minimum, "stddev": stddev, "median": median, "count": count, "total": total}
