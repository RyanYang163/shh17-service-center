"""服务中心 —— 应用装配与业务逻辑。

回答一个问题：**我的 TNAS 到底在跑什么。**

职责划分：

* ``procnet.py``      —— ``/proc/net/tcp`` ``tcp6`` 的解析（谁在监听）
* ``etcservices.py``  —— ``/etc/services`` 的解析（端口 → 系统服务名）
* ``fingerprint.py``  —— 端口 → 「这通常是做什么的」（**建议**，非权威结论）
* ``docker_engine.py``—— 可选的容器清单（检测不到就用不了，不影响其它）
* ``collect.py``      —— 把上面几路合成一张端口地图 + 「打开」地址推导
* ``history.py``      —— 端口快照入库与「与上次相比」
* ``main.py``（本文件）—— 路由、任务处理器、导出

**只读铁律**（README 与 ``.lang`` 都写明了，代码必须自己守住）：

* 不启动 / 停止 / 重启 / 修改任何服务或容器；没有 ``systemctl``、没有 ``docker start``；
* 不做 ``docker exec``，也不提供任何接受命令行字符串的接口；
* 唯一的写操作是**本应用自己的**数据目录（SQLite 快照、日志）与**用户显式指定的**
  导出目录（必须过白名单）。
"""

import csv
import io
import json
import os
import time

from tnasapp import fsapi, server as srv

from . import collect, docker_engine, etcservices, fingerprint, history

APP_ID = "shh17-service-center"
APP_VERSION = "1.0.0"
TITLE = "Service Center"
DESCRIPTION = "看清 NAS 上跑了哪些服务、端口与容器，一键打开（严格只读）。"

#: 导出时最多写多少行——防止把整台机器的套接字表灌进一个 CSV
EXPORT_NAME_PREFIX = "service-center-ports"

MIGRATIONS = [
    # 版本 6（前 5 个是框架的任务队列 SCHEMA）
    """
    CREATE TABLE IF NOT EXISTS port_snapshots (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at      REAL    NOT NULL,
        job_id          INTEGER,
        source          TEXT    NOT NULL DEFAULT '',
        detail          TEXT    NOT NULL DEFAULT '',
        listening       INTEGER NOT NULL DEFAULT 0,
        mapped          INTEGER NOT NULL DEFAULT 0,
        socket_count    INTEGER NOT NULL DEFAULT 0,
        container_count INTEGER NOT NULL DEFAULT 0,
        ports           TEXT    NOT NULL DEFAULT '[]',
        containers      TEXT    NOT NULL DEFAULT '[]'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_snapshots_created ON port_snapshots(created_at DESC)",
]


class ServiceCenterApp(srv.App):
    """只加了几个默认配置项。

    这几个键都刻意做成**运行期可覆盖**（落在 ``config/runtime.json``）：
    ``proc_root`` / ``services_path`` 让测试能注入一个假的 ``/proc`` 与 ``/etc/services``，
    于是「非 Linux 上拿不到内核表」这条降级路径也能在本机被真实地测出来。
    """

    def default_settings(self):
        base = super().default_settings()
        base.update({
            "proc_root": collect.DEFAULT_PROC_ROOT,
            "services_path": etcservices.DEFAULT_PATH,
            # 容器探测：默认开。检测不到 docker 只是「不可用」，不是错误
            "docker_enabled": True,
            # 快照保留条数（有界增长）
            "snapshot_keep": history.DEFAULT_KEEP,
            # 导出目录：留空 = 不落盘，直接在浏览器里下载
            "export_dir": "",
        })
        return base


def create_app(paths=None, log_level="INFO"):
    app = ServiceCenterApp(
        APP_ID, TITLE, version=APP_VERSION, workers=2, log_level=log_level,
        extra_migrations=MIGRATIONS, paths=paths,
        description=DESCRIPTION,
        engines={"docker": docker_engine.status()},
    )
    fsapi.register(app)
    _register_routes(app)
    _register_jobs(app)
    return app


# ---------------------------------------------------------------- 内部工具


def _collect_now(app, host=None, docker_all=False):
    """按当前配置采集一次。任何来源不可用都只是字段里的一个原因，不会抛异常。"""
    return collect.collect(
        proc_root=collect.default_proc_root(app.settings),
        services_path=collect.default_services_path(app.settings),
        docker_enabled=bool(app.settings.get("docker_enabled", True)),
        docker_all=docker_all,
        host=host,
    )


def _record(app, snapshot, job_id=None):
    """把一次采集写进历史（剥掉随请求变化的字段）。"""
    payload = dict(snapshot)
    payload["entries"] = collect.strip_session_fields(snapshot.get("entries") or [])
    keep = app.settings.get("snapshot_keep", history.DEFAULT_KEEP)
    return history.save(app, payload, job_id=job_id, keep=keep)


def _counts(entries):
    return {
        "mapped": len(entries),
        "listening": len([item for item in entries if item.get("listening")]),
        "open": len([item for item in entries if item.get("open_reachable")]),
        "web": len([item for item in entries
                    if (item.get("fingerprint") or {}).get("web")]),
    }


def _ports_payload(app, host, record, docker_all=False):
    snapshot = _collect_now(app, host=host, docker_all=docker_all)
    saved = _record(app, snapshot) if record else None
    return {
        "ok": True,
        "collected_at": snapshot["collected_at"],
        "collected_at_text": history.format_time(snapshot["collected_at"]),
        "entries": snapshot["entries"],
        "counts": _counts(snapshot["entries"]),
        "categories": snapshot["categories"],
        "sources": {"proc": snapshot["proc"], "services": snapshot["services"],
                    "docker": snapshot["docker"]},
        "recorded": bool(record),
        "snapshot": saved,
        "read_only": True,
        "fingerprint_note": fingerprint.NOTE,
    }


def _findings(entries):
    """值得提醒用户的两类情况（只陈述事实，不给操作建议）。"""
    findings = []
    for entry in entries:
        if (entry.get("fingerprint") or {}).get("kind") == "container" \
                and entry["port"] in (2375,):
            findings.append({
                "level": "warn", "port": entry["port"],
                "title": "疑似未加密的 Docker 远程接口",
                "detail": "端口 %d 通常对应 Docker 引擎的明文远程 API，"
                          "能以 root 权限操控整台设备。本应用只做提示，不做任何改动。"
                          % entry["port"],
            })
    return findings


def _to_csv(entries):
    """导出 CSV。

    开头加 UTF-8 BOM：这份文件主要是给人用 Excel 打开的，没有 BOM 时中文表头
    在 Excel 里会显示成乱码。其余场合（JSON）不加。
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")  # LF，与仓库内所有文本一致
    writer.writerow(["端口", "协议", "绑定地址", "绑定范围", "服务名", "识别来源",
                     "类别", "系统服务名", "容器", "监听状态", "打开地址"])
    for entry in entries:
        mark = entry.get("fingerprint") or {}
        writer.writerow([
            entry.get("port"),
            entry.get("protocol"),
            entry.get("address"),
            entry.get("scope"),
            entry.get("service_name"),
            entry.get("service_source"),
            mark.get("kind") or "",
            entry.get("service") or "",
            ", ".join(entry.get("containers") or []),
            "监听中" if entry.get("listening") else "未在监听表内",
            entry.get("open_url") or "",
        ])
    return "﻿" + buffer.getvalue()


def _export_body(fmt, snapshot, host, stamp):
    """返回 ``(bytes, 文件名)``。"""
    entries = snapshot["entries"]
    if fmt == "csv":
        name = "%s-%s.csv" % (EXPORT_NAME_PREFIX, stamp)
        return _to_csv(entries).encode("utf-8"), name
    name = "%s-%s.json" % (EXPORT_NAME_PREFIX, stamp)
    payload = {
        "app": APP_ID,
        "version": APP_VERSION,
        "generated_at": snapshot["collected_at"],
        "generated_at_text": history.format_time(snapshot["collected_at"]),
        "extra": {
            "fingerprint_note": fingerprint.NOTE,
            "fingerprint_confidence": fingerprint.CONFIDENCE,
            "read_only": True,
            "opened_from": host,
        },
        "sources": {"proc": snapshot["proc"], "services": snapshot["services"],
                    "docker": snapshot["docker"]},
        "counts": _counts(entries),
        "categories": snapshot["categories"],
        "containers": snapshot["containers"],
        "entries": entries,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"), name


def _unique_path(directory, filename):
    """同名时加 ``-1`` / ``-2`` 后缀，**不覆盖**已有文件。"""
    stem, ext = os.path.splitext(filename)
    candidate = os.path.join(directory, filename)
    index = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, "%s-%d%s" % (stem, index, ext))
        index += 1
        if index > 999:
            break
    return candidate


# ---------------------------------------------------------------- 路由


def _register_routes(app):
    @app.get("/api/services/ports")
    def _ports(req):
        """端口地图。

        默认 ``record=1``：**每次刷新都留下一次快照**，这样「变化历史」才有东西可对比。
        只想看不想留痕时传 ``record=0``。
        """
        host = collect.host_from_headers(req.headers)
        return srv.Response.json(_ports_payload(
            app, host, record=req.bool_arg("record", True),
            docker_all=req.bool_arg("all"),
        ))

    @app.get("/api/services/summary")
    def _summary(req):
        """概览统计。**不写快照**（这是个纯读接口，不会被反复刷新灌满历史）。"""
        host = collect.host_from_headers(req.headers)
        snapshot = _collect_now(app, host=host, docker_all=req.bool_arg("all"))
        diff = history.changes(app)
        latest = diff.get("latest")
        return srv.Response.json({
            "ok": True,
            "collected_at": snapshot["collected_at"],
            "collected_at_text": history.format_time(snapshot["collected_at"]),
            "counts": _counts(snapshot["entries"]),
            "categories": snapshot["categories"],
            "containers": snapshot["container_count"],
            "sources": {"proc": snapshot["proc"], "services": snapshot["services"],
                        "docker": snapshot["docker"]},
            "snapshots": {
                "count": history.count(app),
                "keep": app.settings.get("snapshot_keep", history.DEFAULT_KEEP),
                "latest": latest,
            },
            "changes": {
                "has_snapshot": diff.get("has_snapshot", False),
                "has_previous": diff.get("has_previous", False),
                "added": len(diff.get("added") or []),
                "removed": len(diff.get("removed") or []),
                "changed": len(diff.get("changed") or []),
                "latest_at_text": diff.get("latest_at_text"),
            },
            "findings": _findings(snapshot["entries"]),
            "read_only": True,
            "fingerprint_note": fingerprint.NOTE,
        })

    @app.get("/api/services/containers")
    def _containers(req):
        """容器清单。

        检测不到 docker 时**照样 200**，用 ``available=false`` + ``detail`` 说明原因——
        这是「不可用」，不是错误。默认只列运行中的，``all=1`` 连已退出的也列。
        """
        all_containers = req.bool_arg("all")
        if not app.settings.get("docker_enabled", True):
            return srv.Response.json({
                "ok": True,
                "available": False,
                "detail": "本次部署已关闭容器探测（运行期设置 docker_enabled=false）",
                "all": all_containers, "count": 0, "running": 0, "containers": [],
                "engine": {"name": "docker", "available": False, "version": "",
                           "detail": "已被运行期设置关闭", "enables": ["containers"]},
                "read_only": True,
            })

        result = docker_engine.list_containers(all_containers=all_containers)
        containers = result["containers"]
        return srv.Response.json({
            "ok": True,
            "available": result["available"],
            "detail": result["detail"],
            "all": all_containers,
            "count": len(containers),
            "running": len([item for item in containers
                            if (item.get("state") or "").lower() == "running"]),
            "containers": containers,
            "engine": docker_engine.status(),
            "read_only": True,
        })

    @app.get("/api/services/changes")
    def _changes(req):
        """与上一次快照相比新增 / 消失 / 换了服务名的端口。"""
        payload = history.changes(app)
        payload["ok"] = True
        payload["added"] = payload.get("added") or []
        payload["removed"] = payload.get("removed") or []
        payload["changed"] = payload.get("changed") or []
        return srv.Response.json(payload)

    @app.get("/api/services/snapshots")
    def _snapshots(req):
        """快照列表（轻量，不带每条端口记录）。``id`` 给定时返回该条的完整内容。"""
        raw_id = req.arg("id")
        if raw_id:
            try:
                snapshot_id = int(raw_id)
            except (TypeError, ValueError):
                return srv.Response.error("快照 id 必须是整数：%s" % raw_id, 400,
                                          "示例：/api/services/snapshots?id=1")
            row = app.store.query_one("SELECT * FROM port_snapshots WHERE id=?", (snapshot_id,))
            if not row:
                return srv.Response.error("没有 id 为 %d 的快照" % snapshot_id, 404,
                                          "可先用 /api/services/snapshots 看有哪些")
            return srv.Response.json({"ok": True, "snapshot": history.row_to_dict(row)})

        limit = max(1, min(200, req.int_arg("limit", 20)))
        offset = max(0, req.int_arg("offset", 0))
        return srv.Response.json({
            "ok": True,
            "count": history.count(app),
            "keep": app.settings.get("snapshot_keep", history.DEFAULT_KEEP),
            "limit": limit,
            "offset": offset,
            "snapshots": history.list_snapshots(app, limit=limit, offset=offset),
        })

    @app.get("/api/services/snapshot/latest")
    def _snapshot_latest(req):
        """最近一次快照（完整内容，含每条端口记录）。"""
        row = history.latest(app)
        if not row:
            return srv.Response.json({
                "ok": True, "snapshot": None, "count": 0,
                "detail": "还没有任何快照 —— 刷新一次端口地图或提交一次采集任务即可产生",
            })
        return srv.Response.json({"ok": True, "snapshot": row, "count": history.count(app)})

    @app.post("/api/services/snapshot")
    def _snapshot_submit(req):
        """采集一次快照。语义等同 ``POST /api/jobs {"type":"snapshot"}``。"""
        body = req.json_body() or {}
        if not isinstance(body, dict):
            return srv.Response.error("请求体必须是 JSON 对象", 400)
        job = app.jobs.submit(
            "snapshot",
            {"all": bool(body.get("all"))},
            title=body.get("title") or "采集端口快照",
        )
        return srv.Response.json({"ok": True, "job": job}, status=201)

    @app.get("/api/services/fingerprints")
    def _fingerprints(req):
        """指纹表 —— 界面上「这些结论是怎么来的」那一节用它。"""
        return srv.Response.json({
            "ok": True,
            "confidence": fingerprint.CONFIDENCE,
            "note": fingerprint.NOTE,
            "kinds": fingerprint.KIND_LABELS,
            "count": len(fingerprint.KNOWN),
            "fingerprints": fingerprint.table(),
        })

    @app.get("/api/services/export")
    def _export(req):
        """导出端口地图。

        * 不给 ``dir`` —— 不落盘，直接把内容作为附件返回（最安全，也最常用）；
        * 给了 ``dir`` —— **必须先过白名单**，否则 403。写进去的文件名带时间戳，
          同名时加后缀，**不覆盖**已有文件。
        """
        fmt = (req.arg("format") or "json").strip().lower()
        if fmt not in ("csv", "json"):
            return srv.Response.error("不支持的导出格式：%s" % fmt, 400,
                                      "format 只能是 csv 或 json")

        host = collect.host_from_headers(req.headers)
        snapshot = _collect_now(app, host=host, docker_all=req.bool_arg("all"))
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        body, filename = _export_body(fmt, snapshot, host, stamp)

        target = (req.arg("dir") or str(app.settings.get("export_dir") or "")).strip()
        if not target:
            content_type = ("text/csv; charset=utf-8" if fmt == "csv"
                            else "application/json; charset=utf-8")
            return srv.Response(200, body, content_type, {
                "Content-Disposition": 'attachment; filename="%s"' % filename,
            })

        try:
            real_dir = app.allowed.check(target, must_exist=False)
        except Exception as exc:
            return srv.Response.error(
                "导出目录不在允许访问的目录内：%s" % target, 403,
                "%s；请在「设置」里把它加入可访问目录白名单" % exc,
            )
        try:
            os.makedirs(real_dir, exist_ok=True)
        except OSError as exc:
            return srv.Response.error("无法创建导出目录：%s" % exc, 500)

        path = _unique_path(real_dir, filename)
        try:
            with open(path, "wb") as handle:
                handle.write(body)
        except OSError as exc:
            return srv.Response.error("写入导出文件失败：%s" % exc, 500,
                                      "请确认该目录对应用用户可写")
        app.log.info("端口地图已导出：%s（%d 字节）", path, len(body))
        return srv.Response.json({
            "ok": True, "format": fmt, "path": path, "filename": os.path.basename(path),
            "bytes": len(body), "count": len(snapshot["entries"]),
        })


# ---------------------------------------------------------------- 任务


def _register_jobs(app):
    @app.jobs.register("snapshot")
    def _job_snapshot(ctx):
        """采集一次端口快照并入库、与上次对比。

        整个过程只是**读**：读 /proc、读 /etc/services、读 docker ps 的输出，
        然后写进本应用自己的 SQLite。没有任何一步会碰到被观测的服务或容器。
        """
        docker_all = bool(ctx.params.get("all"))
        ctx.log("开始采集端口快照（只读）")
        ctx.progress(1, 4, "读取内核监听套接字表")
        snapshot = _collect_now(app, host=None, docker_all=docker_all)

        ctx.checkpoint()
        ctx.log("内核表来源：%s" % snapshot["proc"]["detail"])
        if not snapshot["proc"]["source"] == "unavailable":
            ctx.log("解析出 %d 个监听套接字，合成 %d 条端口记录"
                    % (snapshot["listen_count"], snapshot["mapped_count"]))
        else:
            ctx.log("拿不到内核监听表，端口地图为空（不是错误，界面照常可用）", "WARN")

        ctx.progress(2, 4, "读取容器清单")
        if snapshot["docker"]["available"]:
            ctx.log("容器：%s" % snapshot["docker"]["detail"])
        else:
            ctx.log("容器清单不可用：%s" % snapshot["docker"]["detail"], "WARN")

        ctx.checkpoint()
        ctx.progress(3, 4, "写入快照并对比上次")
        saved = _record(app, snapshot, job_id=ctx.job_id)
        diff = history.changes(app)
        added = diff.get("added") or []
        removed = diff.get("removed") or []
        for entry in added[:20]:
            ctx.log("新增端口：%s/%d（%s）"
                    % (entry.get("protocol"), entry.get("port"), entry.get("service_name")))
        for entry in removed[:20]:
            ctx.log("消失端口：%s/%d（%s）"
                    % (entry.get("protocol"), entry.get("port"), entry.get("service_name")))

        ctx.progress(4, 4, "完成")
        ctx.set_result({
            "snapshot_id": (saved or {}).get("id"),
            "listening": snapshot["listen_count"],
            "mapped": snapshot["mapped_count"],
            "containers": snapshot["container_count"],
            "docker_available": snapshot["docker"]["available"],
            "proc_source": snapshot["proc"]["source"],
            "added": len(added),
            "removed": len(removed),
            "changed": len(diff.get("changed") or []),
            "total_snapshots": history.count(app),
        })


def main(argv=None):
    from tnasapp import cli

    return cli.main(APP_ID, APP_VERSION, create_app, argv=argv,
                    description="服务中心 —— 看清 NAS 上跑了哪些服务、端口与容器（只读）")
