"""端口快照的存储与对比 —— 「最近有什么变了」。

每次采集写一行 ``port_snapshots``（时间戳 + 端口 JSON），并提供「与上次相比
新增 / 消失 / 服务名变了」的差异。**不做无界增长**：只保留最近 N 次（默认 50），
写入后立刻按 ``id`` 倒序裁掉多余的。

为什么用快照对比而不是让用户自己看两次表格：端口变化是「事件」——某天 SMB 端口
突然从 0.0.0.0 变成只绑本机、或者多出来一个 8080，看单张表是发现不了的。
"""

import json
import time

#: 默认保留的快照条数。50 次按「一天刷新两次」算够看一个月，占空间可忽略。
DEFAULT_KEEP = 50

#: 差异的标识口径：同一个「协议 + 绑定地址 + 端口」才算同一个东西。
#: 只按端口比会把「0.0.0.0:445」和「127.0.0.1:445」当成同一个，那正是最该看见的变化。
def entry_key(entry):
    return "%s|%s|%d" % (entry.get("protocol") or "", entry.get("address") or "",
                         int(entry.get("port") or 0))


def format_time(ts):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError):
        return ""


def _loads(text, default):
    try:
        value = json.loads(text) if text else default
        return value if value is not None else default
    except (ValueError, TypeError):
        return default


def row_to_dict(row):
    """数据库行 → 接口用的字典（JSON 字段解开、时间补上可读文本）。"""
    if not row:
        return None
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "created_at_text": format_time(row["created_at"]),
        "job_id": row.get("job_id"),
        "source": row.get("source") or "",
        "detail": row.get("detail") or "",
        "listening": int(row.get("listening") or 0),
        "mapped": int(row.get("mapped") or 0),
        "socket_count": int(row.get("socket_count") or 0),
        "container_count": int(row.get("container_count") or 0),
        "ports": _loads(row.get("ports"), []),
        "containers": _loads(row.get("containers"), []),
    }


def summary_of(row):
    """快照的「轻量版」——列表里不需要带上每条端口记录。

    入参接受数据库行，也接受已经 :func:`row_to_dict` 过的字典（幂等）。
    """
    data = row_to_dict(row)
    if data is None:
        return None
    return {
        "id": data["id"],
        "created_at": data["created_at"],
        "created_at_text": data["created_at_text"],
        "listening": data["listening"],
        "mapped": data["mapped"],
        "container_count": data["container_count"],
        "source": data["source"],
    }


def save(app, collected, job_id=None, keep=DEFAULT_KEEP):
    """写入一次快照并裁剪历史，返回新行的轻量摘要。"""
    entries = collected.get("entries") or []
    containers = collected.get("containers") or []
    proc = collected.get("proc") or {}

    compact_containers = [{
        "id": item.get("id"), "name": item.get("name"), "image": item.get("image"),
        "state": item.get("state"), "status": item.get("status"),
        "running_for": item.get("running_for"), "ports_text": item.get("ports_text"),
    } for item in containers]

    row_id = app.store.insert(
        "INSERT INTO port_snapshots (created_at, job_id, source, detail, listening, mapped,"
        " socket_count, container_count, ports, containers)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            float(collected.get("collected_at") or time.time()),
            job_id,
            str(proc.get("source") or ""),
            str(proc.get("detail") or ""),
            int(collected.get("listen_count") or 0),
            int(collected.get("mapped_count") or 0),
            int(collected.get("socket_count") or 0),
            int(collected.get("container_count") or 0),
            json.dumps(entries, ensure_ascii=False),
            json.dumps(compact_containers, ensure_ascii=False),
        ),
    )
    pruned = prune(app, keep)
    row = app.store.query_one("SELECT * FROM port_snapshots WHERE id=?", (row_id,))
    result = summary_of(row)
    if result is not None:
        result["pruned"] = pruned
    return result


def prune(app, keep=DEFAULT_KEEP):
    """只保留最近 ``keep`` 条。返回删除条数。"""
    try:
        keep = max(1, int(keep))
    except (TypeError, ValueError):
        keep = DEFAULT_KEEP
    rows = app.store.query(
        "SELECT id FROM port_snapshots ORDER BY id DESC LIMIT -1 OFFSET ?", (keep,)
    )
    for row in rows:
        app.store.execute("DELETE FROM port_snapshots WHERE id=?", (row["id"],))
    return len(rows)


def count(app):
    return int(app.store.scalar("SELECT COUNT(*) FROM port_snapshots", default=0) or 0)


def latest(app):
    return row_to_dict(app.store.query_one(
        "SELECT * FROM port_snapshots ORDER BY id DESC LIMIT 1"))


def previous(app, before_id):
    return row_to_dict(app.store.query_one(
        "SELECT * FROM port_snapshots WHERE id<? ORDER BY id DESC LIMIT 1", (int(before_id),)))


def list_snapshots(app, limit=20, offset=0):
    rows = app.store.query(
        "SELECT * FROM port_snapshots ORDER BY id DESC LIMIT ? OFFSET ?",
        (max(1, int(limit)), max(0, int(offset))),
    )
    return [summary_of(row_to_dict(row)) for row in rows]


def diff(previous_row, latest_row):
    """两份快照的差异。

    * ``added``   —— 上次没有、这次出现的（新服务上线 / 换了绑定）
    * ``removed`` —— 上次有、这次没有的（服务停了 / 不再对外）
    * ``changed`` —— 同一个端口，但识别出的服务名变了（服务被换掉了）
    """
    if not latest_row:
        return {"added": [], "removed": [], "changed": [],
                "previous_at": None, "latest_at": None, "has_previous": False}

    old = {entry_key(item): item for item in (previous_row or {}).get("ports") or []}
    new = {entry_key(item): item for item in latest_row.get("ports") or []}

    added = [new[key] for key in sorted(new) if key not in old]
    removed = [old[key] for key in sorted(old) if key not in new]
    changed = []
    for key in sorted(new):
        if key not in old:
            continue
        before = old[key]
        after = new[key]
        if (before.get("service_name"), before.get("service_source")) != \
                (after.get("service_name"), after.get("service_source")):
            changed.append({
                "key": key,
                "port": after.get("port"),
                "protocol": after.get("protocol"),
                "address": after.get("address"),
                "before": before.get("service_name"),
                "after": after.get("service_name"),
            })

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "previous_at": (previous_row or {}).get("created_at"),
        "previous_at_text": format_time((previous_row or {}).get("created_at") or 0) or None,
        "latest_at": latest_row.get("created_at"),
        "latest_at_text": latest_row.get("created_at_text"),
        "has_previous": bool(previous_row),
    }


def changes(app):
    """「与上次相比」的完整答案，供 ``/api/services/changes`` 直接返回。"""
    newest = latest(app)
    if not newest:
        return {"has_snapshot": False, "has_previous": False, "added": [], "removed": [],
                "changed": [], "latest": None, "previous": None,
                "detail": "还没有任何快照 —— 先刷新一次端口地图或提交一次采集任务"}

    older = previous(app, newest["id"])
    result = diff(older, newest)
    result["has_snapshot"] = True
    result["latest"] = summary_of(newest)
    result["previous"] = summary_of(older)
    result["snapshot_count"] = count(app)
    if not older:
        result["detail"] = "这是第一次快照，还没有可比较的上一次"
    return result
