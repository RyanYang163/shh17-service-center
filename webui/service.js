/* ============================================================================
   服务中心 —— 前端逻辑
   ----------------------------------------------------------------------------
   依赖 ./app.js 提供的 API / U / UI / Jobs / Bars / Shell 与 ./icons.js 的 Icons。
   所有请求走 API.get/post（它自动处理平台前缀与鉴权头）。

   六個视图：概览 / 端口地图 / 容器 / 变化历史 / 任务 / 设置。
   界面上必须守住的几条口径：
     · 指纹是**建议**，不是结论 —— 表格与详情里都标注「仅供参考」；
     · 只绑回环地址的服务，地址能拼出来但从浏览器打不开 —— 按钮置灰并说明原因；
     · 拿不到 /proc 或没有 docker 时显示**空状态 + 原因**，不是报错。
   ========================================================================== */

(function () {
  'use strict';

  const State = {
    ports: null,          // 最近一次端口地图响应
    summary: null,
    containers: null,
    changes: null,
    settings: null,
    app: null,
    filter: { query: '', webOnly: false, listeningOnly: false },
    containerAll: false,
    loading: false,
  };

  //: Shell.init() 返回的实例（有 show(key)）。
  //: **不能**直接写 `Shell.show(...)` —— app.js 里 `const Shell` 是脚本级常量，
  //: 它优先于 `window.Shell` 被解析，而那个对象上并没有 show()。
  let shellRef = null;

  function goto(view) {
    if (shellRef) shellRef.show(view);
  }

  /* ------------------------------------------------------------ 小工具 */

  function badgeForKind(entry) {
    const mark = entry.fingerprint;
    if (!mark) return U.el('span', { class: 'small faint', text: '未收录' });
    return UI.badge(mark.kind_label || mark.kind, mark.web ? 'info' : 'neutral');
  }

  /** 一行里的「服务名」单元格：指纹名优先，其次 /etc/services，最后如实说未知。 */
  function serviceCell(entry) {
    const mark = entry.fingerprint;
    const sub = mark
      ? (mark.note || '')
      : (entry.service ? '来自 /etc/services，未收录进指纹表' : '端口未收录，无法推断');
    return U.el('td', {}, [
      U.el('div', { class: 'svc', text: entry.service_name }),
      U.el('div', { class: 'hint-inline', text: sub }),
    ]);
  }

  /** 监听状态：真在监听 / 只由容器发布 / 不在内核监听表里。 */
  function statusCell(entry) {
    let cls = 'off';
    let text = '未在监听表内';
    if (entry.listening) {
      cls = entry.scope === 'localhost' ? 'local' : 'up';
      text = entry.scope === 'localhost' ? '监听中（仅本机）' : '监听中';
    } else if (entry.source === 'docker') {
      text = '由容器发布';
    }
    return U.el('td', { class: 'nowrap' }, [
      U.el('span', { class: 'dot ' + cls }),
      U.el('span', { text: text }),
    ]);
  }

  /** 「打开」按钮。地址打不开时必须置灰并把原因写在 title 上，不能点了才失败。 */
  function openButton(entry) {
    const url = effectiveUrl(entry);
    const enabled = Boolean(url) && entry.open_reachable !== false;
    const button = U.el('button', {
      class: 'btn sm ' + (enabled ? 'primary' : 'ghost'),
      text: '打开',
      title: enabled ? url : (entry.open_note || '该服务没有可用的网页界面'),
    });
    if (!enabled) {
      button.setAttribute('aria-disabled', 'true');
      button.disabled = true;
      return button;
    }
    button.addEventListener('click', () => {
      window.open(url, '_blank', 'noopener');
    });
    return button;
  }

  /**
   * 真正拿去打开的地址。
   *
   * 后端按「请求头里的主机名」拼地址（指引 8.4.3 禁止写死 IP），但应用是被平台
   * 反代进来的：平台 Nginx 转发到后端的 unix socket 时，``Host`` 很可能是
   * ``localhost``，那时拼出来的 ``http://localhost:8181`` 打开的是**用户自己的电脑**。
   * 所以当派生出的主机名是回环地址、而浏览器地址栏里的主机名不是时，改用后者 ——
   * 那才是「你当前访问 NAS 用的地址」，而且只有浏览器自己知道。
   */
  function effectiveUrl(entry) {
    if (!entry.open_url) return null;
    const isLoopback = (host) => !host || host === 'localhost' || host === '127.0.0.1'
      || host === '::1' || host === '[::1]';
    try {
      const url = new URL(entry.open_url);
      const pageHost = window.location.hostname;
      if (isLoopback(url.hostname) && !isLoopback(pageHost)) {
        url.hostname = pageHost;      // 端口保持后端给的（那才是服务端口）
      }
      return url.toString();
    } catch (error) {
      return entry.open_url;          // 拿不到就退回后端给的地址，不因为这段兜底而更差
    }
  }

  function addressCell(entry) {
    return U.el('td', { class: 'mono small' }, [
      U.el('div', { text: entry.address }),
      U.el('div', { class: 'hint-inline', text: entry.family === 'ipv6' ? 'IPv6' : 'IPv4' }),
    ]);
  }

  function showEntryDetail(entry) {
    const mark = entry.fingerprint || {};
    const rows = [
      ['端口', String(entry.port)],
      ['协议', entry.protocol],
      ['绑定地址', entry.address],
      ['绑定范围', { all: '所有网卡', localhost: '仅本机', specific: '指定地址' }[entry.scope] || entry.scope],
      ['状态', entry.listening ? '在监听（' + entry.state + '）' : '未在监听表内'],
      ['服务名', entry.service_name],
      ['识别依据', entry.service_source === 'fingerprint' ? '端口指纹（建议）'
        : entry.service_source === 'etc-services' ? '/etc/services' : '未能识别'],
      ['指纹说明', mark.note || '—'],
      ['/etc/services', entry.service || '—'],
      ['容器', (entry.containers || []).join('、') || '—'],
      ['打开地址', entry.open_url || '（无）'],
    ];
    let html = '<dl class="kv">' + rows.map(([key, value]) =>
      `<dt>${U.esc(key)}</dt><dd>${U.esc(value)}</dd>`).join('') + '</dl>';
    html += `<p class="small muted mt2">指纹按端口号推断，任何程序都可以占用任意端口，` +
      `因此这里给的是<strong>建议</strong>而不是结论。本应用只读取内核的监听表，` +
      `不会去连你的服务，也不会启动、停止或修改任何东西。</p>`;
    UI.modal({
      title: `端口 ${entry.port} / ${entry.protocol}`,
      icon: 'hash',
      wide: true,
      bodyHtml: html,
      buttons: [{ text: '关闭' }],
    });
  }

  function entriesTable(entries, options) {
    const opts = options || {};
    const wrap = U.el('div', { class: 'table-wrap' });
    const table = U.el('table', { class: 'data' }, [
      U.el('thead', {}, [U.el('tr', {}, [
        U.el('th', { text: '端口' }),
        U.el('th', { text: '协议' }),
        U.el('th', { text: '绑定' }),
        U.el('th', { text: '服务名' }),
        U.el('th', { text: '类别' }),
        U.el('th', { text: '状态' }),
        U.el('th', { text: '容器' }),
        U.el('th', { text: '操作' }),
      ])]),
    ]);
    const tbody = U.el('tbody', {});
    entries.forEach((entry) => {
      const detail = U.el('button', { class: 'btn sm ghost', text: '详情', title: '查看这一条的细节' });
      detail.addEventListener('click', () => showEntryDetail(entry));
      tbody.appendChild(U.el('tr', {}, [
        U.el('td', { class: 'mono', text: String(entry.port) }),
        U.el('td', { class: 'mono small', text: entry.protocol }),
        addressCell(entry),
        serviceCell(entry),
        U.el('td', {}, [badgeForKind(entry)]),
        statusCell(entry),
        U.el('td', { class: 'small faint', text: (entry.containers || []).join('、') || '—' }),
        U.el('td', {}, [U.el('div', { class: 'btn-row' }, [openButton(entry), detail])]),
      ]));
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    if (opts.note) wrap.appendChild(U.el('p', { class: 'small muted mt1', text: opts.note }));
    return wrap;
  }

  function applyingFilter(entries) {
    const query = State.filter.query.trim().toLowerCase();
    return entries.filter((entry) => {
      if (State.filter.webOnly && !(entry.fingerprint && entry.fingerprint.web)) return false;
      if (State.filter.listeningOnly && !entry.listening) return false;
      if (!query) return true;
      const haystack = [
        entry.port, entry.protocol, entry.address, entry.service_name,
        entry.service || '', (entry.fingerprint || {}).kind || '',
        (entry.containers || []).join(' '),
      ].join(' ').toLowerCase();
      return haystack.indexOf(query) >= 0;
    });
  }

  function sourceBanners(body) {
    const nodes = [];
    const sources = body.sources || {};
    const proc = sources.proc || {};
    const services = sources.services || {};
    const docker = sources.docker || {};

    if (proc.source === 'unavailable') {
      nodes.push(UI.banner('warn', '读不到内核监听表，端口地图为空',
        U.esc(proc.detail) +
        '<ul><li>本应用靠 <code>/proc/net/tcp</code> 判断「谁在监听」，' +
        '非 Linux 系统或 /proc 未挂载时拿不到这张表。</li>' +
        '<li>这不是错误：容器清单与「打开」等其它功能照常可用。</li></ul>'));
    } else if (proc.source === 'partial') {
      nodes.push(UI.banner('info', '只读到部分内核表', U.esc(proc.detail)));
    } else if (proc.detail) {
      nodes.push(UI.banner('ok', '已读取内核监听表', U.esc(proc.detail)));
    }
    if (services.source !== 'file') {
      nodes.push(UI.banner('info', '没有 /etc/services，端口 → 服务名反查不可用',
        U.esc(services.detail || '') +
        '<br>端口与指纹仍会正常显示，只是少了「系统里这个名字」这一列。'));
    }
    if (!docker.available) {
      nodes.push(UI.banner('info', '容器清单不可用（不影响其它功能）',
        U.esc(docker.detail || '') + '<br>本应用把 docker 当作可选的增强：没有它照样能用。'));
    }
    return nodes;
  }

  function tile(label, value, hint) {
    return U.el('div', { class: 'stat-tile' }, [
      U.el('div', { class: 'label', text: label }),
      U.el('div', { class: 'value' }, [
        U.el('span', { text: value }),
        hint ? U.el('small', { text: hint }) : null,
      ]),
    ]);
  }

  async function refreshButton(options) {
    const opts = options || {};
    const button = U.el('button', { class: 'btn primary' }, [
      U.el('span', { html: Icons.svg('refresh', { size: 15 }) }),
      U.el('span', { text: opts.text || '刷新并记录快照' }),
    ]);
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        // record=1：每次刷新都留下一次快照，「变化历史」才有东西可对比
        State.ports = await API.get('api/services/ports?record=1');
        UI.ok('已刷新', State.ports.snapshot
          ? '快照 #' + State.ports.snapshot.id + ' 已记录' : '');
        if (opts.onDone) opts.onDone(State.ports);
      } catch (error) {
        UI.err(error, '刷新失败');
      } finally {
        button.disabled = false;
      }
    });
    return button;
  }

  async function snapshotJobButton(text) {
    const button = U.el('button', { class: 'btn' }, [
      U.el('span', { html: Icons.svg('package', { size: 15 }) }),
      U.el('span', { text: text || '后台采集一次快照' }),
    ]);
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        await Jobs.submit('snapshot', {}, '采集端口快照');
        UI.ok('采集任务已提交', '可在底部任务栏查看进度');
      } catch (error) {
        UI.err(error, '提交失败');
      } finally {
        button.disabled = false;
      }
    });
    return button;
  }

  /* ------------------------------------------------------------ 概览 */

  async function renderOverview(host) {
    host.innerHTML = '';
    host.appendChild(UI.banner('info', '正在采集…', '读取内核监听表与容器清单'));

    let summary;
    try {
      summary = await API.get('api/services/summary');
      State.summary = summary;
    } catch (error) {
      host.innerHTML = '';
      host.appendChild(UI.banner('error', '无法读取概览', U.esc(error.message) +
        '<ul><li>服务可能正在重启，稍后重试</li>' +
        '<li>或查看日志：journalctl -u shh17-service-center</li></ul>'));
      return;
    }

    host.innerHTML = '';

    const readonly = UI.banner('ok', '严格只读',
      '本应用只<strong>读取</strong>内核的监听套接字表与 docker 的容器列表。' +
      '它不会启动、停止、重启或修改任何服务与容器，也不会执行任何命令。');
    host.appendChild(readonly);

    sourceBanners(summary).forEach((node) => host.appendChild(node));

    host.appendChild(U.el('div', { class: 'grid cols-4 mb2' }, [
      tile('监听端口', U.num(summary.counts.listening), '个套接字在监听'),
      tile('可打开的服务', U.num(summary.counts.open), '有网页界面'),
      tile('容器', summary.sources.docker.available ? U.num(summary.containers) : '—',
        summary.sources.docker.available ? '运行中' : '不可用'),
      tile('快照', U.num(summary.snapshots.count), '保留最近 ' + summary.snapshots.keep + ' 次'),
    ]));

    const actions = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('scan', { size: 17 }) }),
        U.el('span', { text: '采集' }),
      ]),
      U.el('div', { class: 'card-hint',
        text: '刷新会立刻重新读取一次并把结果记进历史；后台采集走任务队列，不阻塞界面。' }),
    ]);
    actions.appendChild(U.el('div', { class: 'btn-row' }, [
      await refreshButton({ onDone: () => { goto('overview'); } }),
      await snapshotJobButton(),
    ]));
    actions.appendChild(U.el('div', { class: 'small faint mt1', text:
      '上次采集：' + (summary.collected_at_text || '—') }));
    host.appendChild(actions);

    (summary.findings || []).forEach((finding) => {
      host.appendChild(UI.banner(finding.level === 'warn' ? 'warn' : 'info',
        finding.title, U.esc(finding.detail)));
    });

    if (summary.categories.length) {
      const card = U.el('div', { class: 'card' }, [
        U.el('h2', {}, [
          U.el('span', { html: Icons.svg('chart', { size: 17 }) }),
          U.el('span', { text: '服务分类' }),
        ]),
        U.el('div', { class: 'card-hint',
          text: '分类来自端口指纹，只是「这一类端口通常做什么」，不是权威结论。' }),
      ]);
      const bars = U.el('div', {});
      card.appendChild(bars);
      host.appendChild(card);
      Bars.render(bars, summary.categories.map((row, index) => ({
        label: row.label,
        value: row.count,
        text: row.count + ' 项 · ' + row.ports.slice(0, 6).join(', ') +
          (row.ports.length > 6 ? ' …' : ''),
        color: U.color(index, 46),
      })));
    }

    const changeCard = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('clock', { size: 17 }) }),
        U.el('span', { text: '与上次相比' }),
      ]),
    ]);
    const changes = summary.changes;
    if (!changes.has_snapshot) {
      changeCard.appendChild(U.el('div', { class: 'small muted',
        text: '还没有任何快照。刷新一次端口地图就会记下第一次。' }));
    } else if (!changes.has_previous) {
      changeCard.appendChild(U.el('div', { class: 'small muted',
        text: '这是第一次快照，还没有可比较的上一次。' }));
    } else {
      changeCard.appendChild(U.el('div', { class: 'row spread' }, [
        U.el('span', {}, [UI.badge('新增 ' + changes.added, changes.added ? 'ok' : 'neutral')]),
        U.el('span', {}, [UI.badge('消失 ' + changes.removed, changes.removed ? 'warn' : 'neutral')]),
        U.el('span', {}, [UI.badge('换了服务 ' + changes.changed, changes.changed ? 'info' : 'neutral')]),
      ]));
      changeCard.appendChild(U.el('div', { class: 'small faint mt1',
        text: '对比基准：' + (changes.latest_at_text || '—') + '（上一份快照）' }));
      const more = U.el('button', { class: 'btn sm' });
      more.appendChild(U.el('span', { text: '查看变化历史' }));
      more.addEventListener('click', () => goto('changes'));
      changeCard.appendChild(U.el('div', { class: 'btn-row mt1' }, [more]));
    }
    host.appendChild(changeCard);
  }

  /* ------------------------------------------------------------ 端口地图 */

  async function loadPorts(record) {
    State.ports = await API.get('api/services/ports?record=' + (record ? 1 : 0));
    return State.ports;
  }

  async function renderPorts(host) {
    host.innerHTML = '';
    host.appendChild(UI.banner('info', '正在采集…', '读取内核监听表'));

    let body;
    try {
      // 进入视图本身不写历史，避免来回切页把快照刷满
      body = await loadPorts(false);
    } catch (error) {
      host.innerHTML = '';
      host.appendChild(UI.banner('error', '无法读取端口地图', U.esc(error.message)));
      return;
    }

    host.innerHTML = '';

    const toolbar = U.el('div', { class: 'toolbar' }, [
      U.el('input', {
        type: 'search', placeholder: '搜索端口 / 服务名 / 地址…',
        value: State.filter.query,
      }),
      U.el('label', { class: 'small' }, [
        U.el('input', { type: 'checkbox', checked: State.filter.webOnly }), ' 只看可打开的网页服务',
      ]),
      U.el('label', { class: 'small' }, [
        U.el('input', { type: 'checkbox', checked: State.filter.listeningOnly }), ' 只看监听中',
      ]),
      U.el('span', { class: 'grow' }),
    ]);
    const search = toolbar.querySelector('input[type="search"]');
    const [webBox, listenBox] = Array.from(toolbar.querySelectorAll('input[type="checkbox"]'));
    const rerender = () => {
      const tableHost = U.byId('ports-table');
      tableHost.innerHTML = '';
      renderTableInto(tableHost, body);
    };
    search.addEventListener('input', U.debounce(() => {
      State.filter.query = search.value;
      rerender();
    }, 200));
    webBox.addEventListener('change', () => {
      State.filter.webOnly = webBox.checked; rerender();
    });
    listenBox.addEventListener('change', () => {
      State.filter.listeningOnly = listenBox.checked; rerender();
    });
    toolbar.appendChild(await refreshButton({
      onDone: (fresh) => { body = fresh; rerender(); },
    }));
    host.appendChild(toolbar);

    const exportRow = U.el('div', { class: 'btn-row mb2' }, [
      exportButton('json'), exportButton('csv'),
      await snapshotJobButton(),
    ]);
    host.appendChild(exportRow);

    const card = U.el('div', { class: 'card flush' }, [
      U.el('div', { class: 'card-head' }, [U.el('h2', { class: 'mb0' }, [
        U.el('span', { html: Icons.svg('server', { size: 17 }) }),
        U.el('span', { text: '端口地图' }),
      ])]),
    ]);
    const cardBody = U.el('div', { class: 'card-body' });
    cardBody.appendChild(U.el('div', { class: 'mt1 mb1' }, [
      U.el('span', { class: 'small muted', id: 'ports-count' }),
    ]));
    const tableHost = U.el('div', { id: 'ports-table' });
    cardBody.appendChild(tableHost);
    cardBody.appendChild(U.el('p', { class: 'small muted', text:
      '「端口」与「绑定地址」是内核表的原始事实；「服务名」按端口推断，' +
      '仅供参考 —— 任何程序都可以占用任意端口。' +
      '只绑回环地址（127.0.0.1）的服务从浏览器打不开，按钮会置灰并说明原因。' }));
    card.appendChild(cardBody);
    host.appendChild(card);

    function renderTableInto(target, data) {
      const shown = applyingFilter(data.entries);
      const counter = U.byId('ports-count');
      if (counter) {
        counter.textContent = '共 ' + data.counts.mapped + ' 条，当前显示 ' +
          shown.length + ' 条' + (data.recorded ? '（本次刷新已记入历史）' : '');
      }
      if (!shown.length) {
        target.appendChild(UI.empty('search', '没有符合条件的端口',
          data.entries.length ? '换一个关键词，或取消筛选' : '这台设备当前没有可显示的端口记录'));
        return;
      }
      target.appendChild(entriesTable(shown));
    }
    renderTableInto(tableHost, body);
  }

  function exportButton(format) {
    const button = U.el('button', { class: 'btn sm' }, [
      U.el('span', { html: Icons.svg('download', { size: 14 }) }),
      U.el('span', { text: format.toUpperCase() }),
    ]);
    button.title = '把当前端口地图导出为 ' + format.toUpperCase() +
      '（直接下载，不落盘）';
    button.addEventListener('click', () => {
      window.open(API.downloadUrl('api/services/export?format=' + format), '_blank',
        'noopener');
      UI.ok('已开始下载 ' + format.toUpperCase(),
        '导出的是刚才这一份采集结果，不会写入 NAS 上的任何目录');
    });
    return button;
  }

  /* ------------------------------------------------------------ 容器 */

  async function renderContainers(host) {
    host.innerHTML = '';
    host.appendChild(UI.banner('info', '正在读取容器清单…', ''));

    let body;
    try {
      body = await API.get('api/services/containers' + (State.containerAll ? '?all=1' : ''));
      State.containers = body;
    } catch (error) {
      host.innerHTML = '';
      host.appendChild(UI.banner('error', '无法读取容器清单', U.esc(error.message)));
      return;
    }

    host.innerHTML = '';

    const toggle = U.el('label', { class: 'small' }, [
      U.el('input', { type: 'checkbox', checked: State.containerAll }), ' 显示已退出的容器',
    ]);
    toggle.querySelector('input').addEventListener('change', (event) => {
      State.containerAll = event.target.checked;
      goto('containers');
    });
    host.appendChild(U.el('div', { class: 'toolbar' }, [
      toggle,
      U.el('span', { class: 'grow' }),
      U.el('span', { class: 'small faint', text: body.detail || '' }),
    ]));

    if (!body.available) {
      host.appendChild(UI.banner('info', '容器清单不可用（这不影响其它功能）',
        U.esc(body.detail || '系统上没有检测到 docker 命令') +
        '<ul><li>本应用把 docker 当作<strong>可选</strong>的增强能力：' +
        '端口地图、服务指纹与「打开」都不依赖它。</li>' +
        '<li>装上 docker（或把当前用户加入 docker 组）后重新打开本页即可。</li></ul>'));
      host.appendChild(UI.empty('package', '没有可显示的容器',
        '本机没有可用的 docker 命令行，所以没有容器可列。'));
      return;
    }

    host.appendChild(UI.banner('ok', 'Docker 可用',
      U.esc((body.engine && body.engine.detail) || body.detail) +
      '<br>本应用<strong>只执行 docker ps</strong> 来列清单：' +
      '不会启动、停止、重启容器，也不会 exec 进去。'));

    if (!body.containers.length) {
      host.appendChild(UI.empty('package', '没有容器',
        State.containerAll ? '这台设备上没有任何容器' : '没有运行中的容器（可勾选上方选项看已退出的）'));
      return;
    }

    const card = U.el('div', { class: 'card flush' }, [
      U.el('div', { class: 'card-head' }, [U.el('h2', { class: 'mb0' }, [
        U.el('span', { html: Icons.svg('package', { size: 17 }) }),
        U.el('span', { text: '容器（' + body.count + ' 个，其中运行中 ' + body.running + '）' }),
      ])]),
    ]);
    const wrap = U.el('div', { class: 'table-wrap' });
    const table = U.el('table', { class: 'data' }, [
      U.el('thead', {}, [U.el('tr', {}, [
        U.el('th', { text: '名称' }),
        U.el('th', { text: '镜像' }),
        U.el('th', { text: '状态' }),
        U.el('th', { text: '运行时长' }),
        U.el('th', { text: '映射端口' }),
      ])]),
    ]);
    const tbody = U.el('tbody', {});
    body.containers.forEach((container) => {
      tbody.appendChild(U.el('tr', {}, [
        U.el('td', {}, [
          U.el('div', { class: 'svc', text: container.name || '（未命名）' }),
          U.el('div', { class: 'hint-inline mono', text: container.id || '' }),
        ]),
        U.el('td', { class: 'mono small', text: container.image || '—' }),
        U.el('td', { class: 'small nowrap' }, [
          U.el('span', { class: 'dot ' + (container.state === 'running' ? 'up' : 'off') }),
          U.el('span', { text: container.status || container.state || '—' }),
        ]),
        U.el('td', { class: 'small nowrap', text: container.running_for || '—' }),
        U.el('td', { class: 'mono small', text: container.ports_text || '（未发布到宿主）' }),
      ]));
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    card.appendChild(wrap);
    host.appendChild(card);
  }

  /* ------------------------------------------------------------ 变化历史 */

  async function renderChanges(host) {
    host.innerHTML = '';
    host.appendChild(UI.banner('info', '正在读取快照…', ''));

    let body;
    let listing;
    try {
      body = await API.get('api/services/changes');
      listing = await API.get('api/services/snapshots?limit=20');
      State.changes = body;
    } catch (error) {
      host.innerHTML = '';
      host.appendChild(UI.banner('error', '无法读取变化历史', U.esc(error.message)));
      return;
    }

    host.innerHTML = '';
    host.appendChild(U.el('div', { class: 'btn-row mb2' }, [
      await refreshButton({ text: '刷新并记录一次快照' }),
      await snapshotJobButton(),
    ]));

    if (!body.has_snapshot) {
      host.appendChild(UI.empty('clock', '还没有任何快照',
        U.esc(body.detail || '刷新一次端口地图就会记下第一次') +
        '<br>每次刷新都会把当时的端口地图记进历史，之后就能看出「什么变了」。'));
      return;
    }
    if (!body.has_previous) {
      host.appendChild(UI.banner('info', '这是第一次快照，还没有可比较的上一次',
        '再刷新一次之后，这里就会列出新增、消失与换了服务名的端口。'));
    } else {
      host.appendChild(U.el('div', { class: 'small muted mb1',
        text: '对比：' + (body.previous_at_text || '—') + '（上一次）→ ' +
          (body.latest_at_text || '—') + '（最近一次）' }));

      host.appendChild(changeCard('新增的端口', 'ok', 'plus', body.added,
        '上次没有、这次出现的 —— 新服务上线，或换了绑定地址'));
      host.appendChild(changeCard('消失的端口', 'warn', 'minus', body.removed,
        '上次有、这次没有的 —— 服务停了，或不再对外监听'));
      host.appendChild(changedCard(body.changed));
    }

    const listCard = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('list', { size: 17 }) }),
        U.el('span', { text: '快照列表（共 ' + listing.count + ' 份）' }),
      ]),
      U.el('div', { class: 'card-hint',
        text: '只保留最近 ' + listing.keep + ' 份，超出后自动清理，不会无限增长。' }),
    ]);
    const wrap = U.el('div', { class: 'table-wrap' });
    const table = U.el('table', { class: 'data' }, [
      U.el('thead', {}, [U.el('tr', {}, [
        U.el('th', { text: '#' }),
        U.el('th', { text: '时间' }),
        U.el('th', { text: '监听端口' }),
        U.el('th', { text: '端口记录' }),
        U.el('th', { text: '容器' }),
        U.el('th', { text: '内核表来源' }),
        U.el('th', { text: '' }),
      ])]),
    ]);
    const tbody = U.el('tbody', {});
    listing.snapshots.forEach((snapshot) => {
      const view = U.el('button', { class: 'btn sm ghost', text: '查看' });
      view.addEventListener('click', () => showSnapshot(snapshot.id));
      tbody.appendChild(U.el('tr', {}, [
        U.el('td', { class: 'mono', text: String(snapshot.id) }),
        U.el('td', { class: 'small nowrap', text: snapshot.created_at_text }),
        U.el('td', { class: 'num', text: U.num(snapshot.listening) }),
        U.el('td', { class: 'num', text: U.num(snapshot.mapped) }),
        U.el('td', { class: 'num', text: U.num(snapshot.container_count) }),
        U.el('td', { class: 'small', text: snapshot.source }),
        U.el('td', {}, [U.el('div', { class: 'btn-row' }, [view])]),
      ]));
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    listCard.appendChild(wrap);
    host.appendChild(listCard);
  }

  function changeCard(title, kind, icon, entries, hint) {
    const card = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg(icon, { size: 17 }) }),
        U.el('span', { text: title }),
        U.el('span', {}, [UI.badge(String(entries.length), entries.length ? kind : 'neutral')]),
      ]),
      U.el('div', { class: 'card-hint', text: hint }),
    ]);
    if (!entries.length) {
      card.appendChild(U.el('div', { class: 'small faint', text: '没有' }));
      return card;
    }
    card.appendChild(entriesTable(entries, {
      note: '快照里不记录「打开地址」—— 那是按你当前访问的地址推导的，写进历史只会造假变化。',
    }));
    return card;
  }

  function changedCard(changed) {
    const card = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('refresh', { size: 17 }) }),
        U.el('span', { text: '识别结果变了' }),
        U.el('span', {}, [UI.badge(String(changed.length), changed.length ? 'info' : 'neutral')]),
      ]),
      U.el('div', { class: 'card-hint',
        text: '端口还在监听，但按端口推断出的服务名变了 —— 通常是这个端口换了主人。' }),
    ]);
    if (!changed.length) {
      card.appendChild(U.el('div', { class: 'small faint', text: '没有' }));
      return card;
    }
    const wrap = U.el('div', { class: 'table-wrap' });
    const table = U.el('table', { class: 'data' }, [
      U.el('thead', {}, [U.el('tr', {}, [
        U.el('th', { text: '端口' }), U.el('th', { text: '地址' }),
        U.el('th', { text: '上次' }), U.el('th', { text: '这次' }),
      ])]),
    ]);
    const tbody = U.el('tbody', {});
    changed.forEach((item) => {
      tbody.appendChild(U.el('tr', {}, [
        U.el('td', { class: 'mono', text: item.protocol + '/' + item.port }),
        U.el('td', { class: 'mono small', text: item.address }),
        U.el('td', { class: 'small', text: item.before || '—' }),
        U.el('td', { class: 'small', text: item.after || '—' }),
      ]));
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    card.appendChild(wrap);
    return card;
  }

  async function showSnapshot(id) {
    try {
      const body = await API.get('api/services/snapshots?id=' + encodeURIComponent(id));
      const snapshot = body.snapshot;
      const modal = UI.modal({
        title: '快照 #' + snapshot.id + ' · ' + snapshot.created_at_text,
        icon: 'clock',
        wide: true,
        bodyHtml: '<div class="small muted mb1">监听 ' + snapshot.listening +
          ' 条 · 端口记录 ' + snapshot.mapped + ' 条 · 容器 ' + snapshot.container_count +
          ' 个 · 内核表来源 ' + U.esc(snapshot.source) + '</div>',
        buttons: [{ text: '关闭' }],
      });
      modal.body.appendChild(entriesTable(snapshot.ports, {
        note: '这是入库时的原始记录，不含「打开地址」。',
      }));
    } catch (error) {
      UI.err(error, '无法读取该快照');
    }
  }

  /* ------------------------------------------------------------ 任务 */

  async function renderJobs(host) {
    host.innerHTML = '';
    const card = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('activity', { size: 17 }) }),
        U.el('span', { text: '任务' }),
      ]),
      U.el('div', { class: 'card-hint',
        text: '采集端口快照走任务队列，可以在底部任务栏看进度、取消、重试。' }),
    ]);
    card.appendChild(U.el('div', { class: 'btn-row mb2' }, [await snapshotJobButton('采集一次快照')]));
    const listHost = U.el('div', {});
    card.appendChild(listHost);
    host.appendChild(card);

    async function load() {
      let body;
      try {
        body = await API.get('api/jobs?limit=100');
      } catch (error) {
        listHost.innerHTML = '';
        listHost.appendChild(UI.banner('error', '无法读取任务列表', U.esc(error.message)));
        return;
      }
      Jobs.renderTable(listHost, body.jobs, { emptyHint: '点上面的按钮采集一次快照' });
    }
    Jobs.reload = load;
    await load();
  }

  /* ------------------------------------------------------------ 设置 */

  async function renderSettings(host) {
    host.innerHTML = '';

    let settings;
    let summary;
    try {
      const [settingsBody, summaryBody] = await Promise.all([
        API.get('api/settings'),
        API.get('api/services/summary'),
      ]);
      settings = settingsBody.settings;
      summary = summaryBody;
      State.settings = settings;
      State.summary = summary;
    } catch (error) {
      host.appendChild(UI.banner('error', '无法读取设置', U.esc(error.message)));
      return;
    }

    // ---- 采集来源（只读展示） ----
    const sources = summary.sources || {};
    const sourceCard = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('server', { size: 17 }) }),
        U.el('span', { text: '采集来源' }),
      ]),
      U.el('div', { class: 'card-hint',
        text: '本应用只从下面这些位置读取事实，全部是只读的。' }),
    ]);
    sourceCard.appendChild(U.el('dl', { class: 'kv' }, [
      U.el('dt', { text: '内核监听表' }),
      U.el('dd', { text: (sources.proc && sources.proc.proc_root) || '/proc' }),
      U.el('dt', { text: '端口 → 服务名' }),
      U.el('dd', { text: (sources.services && sources.services.path) || '/etc/services' }),
      U.el('dt', { text: '容器' }),
      U.el('dd', { text: (summary.sources.docker && summary.sources.docker.available)
        ? 'docker ps（只读）' : '不可用' }),
    ]));
    sourceCard.appendChild(U.el('p', { class: 'small muted mt1',
      text: (sources.proc && sources.proc.detail) || '' }));
    host.appendChild(sourceCard);

    // ---- 白名单 ----
    let whitelist = (settings.allowed_roots || []).slice();
    const rootsCard = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('shield', { size: 17 }) }),
        U.el('span', { text: '可访问目录（白名单）' }),
      ]),
      U.el('div', { class: 'card-hint',
        text: '本应用读用户文件的唯一途径是「导出到指定目录」。白名单初始为空，' +
          '只有你在这里添加的目录它才能写入，越界一律拒绝。' }),
    ]);
    const rootList = U.el('div', { class: 'chips mb1' });
    const renderRoots = () => {
      rootList.innerHTML = '';
      if (!whitelist.length) {
        rootList.appendChild(U.el('span', { class: 'small faint',
          text: '（当前为空：导出只能直接在浏览器里下载，不会写入 NAS）' }));
        return;
      }
      whitelist.forEach((root) => {
        const remove = U.el('button', { title: '移除', text: '×' });
        remove.addEventListener('click', async () => {
          const confirmed = await UI.confirm({
            title: '移除可访问目录',
            body: '移除后本应用将无法再写入：\n' + root + '\n\n（不会删除任何文件）',
            confirmText: '移除', danger: true,
          });
          if (!confirmed) return;
          whitelist = whitelist.filter((item) => item !== root);
          await save({ allowed_roots: whitelist });
          renderRoots();
        });
        rootList.appendChild(U.el('span', { class: 'chip' }, [
          U.el('span', { text: root, title: root }), remove,
        ]));
      });
    };
    renderRoots();

    const addBtn = U.el('button', { class: 'btn primary' }, [
      U.el('span', { html: Icons.svg('plus', { size: 15 }) }),
      U.el('span', { text: '添加目录' }),
    ]);
    addBtn.addEventListener('click', () => {
      UI.pickDir({
        title: '选择允许本应用写入的目录',
        start: whitelist[0] || '',
        onPick: async (path) => {
          if (whitelist.indexOf(path) >= 0) { UI.warn('已在列表中'); return; }
          whitelist = whitelist.concat([path]);
          await save({ allowed_roots: whitelist });
          renderRoots();
        },
      });
    });
    rootsCard.appendChild(rootList);
    rootsCard.appendChild(U.el('div', { class: 'btn-row' }, [addBtn]));
    host.appendChild(rootsCard);

    // ---- 导出目录 ----
    const exportCard = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('download', { size: 17 }) }),
        U.el('span', { text: '导出' }),
      ]),
      U.el('div', { class: 'card-hint',
        text: '不填目录时，导出直接把文件交给你下载，不在 NAS 上写任何东西。填了目录就必须' +
          '在白名单内，写进去的文件名带时间戳，同名自动加后缀、不覆盖已有文件。' }),
    ]);
    const exportInput = U.el('input', {
      type: 'text', value: settings.export_dir || '',
      placeholder: '例如 /Volume1/共享文件夹（留空 = 只下载不落盘）',
      style: 'flex:1;min-width:240px',
    });
    const pickExport = U.el('button', { class: 'btn', text: '选择目录' });
    pickExport.addEventListener('click', () => {
      UI.pickDir({
        title: '选择导出目录（必须在白名单内）',
        start: exportInput.value || whitelist[0] || '',
        onPick: (path) => { exportInput.value = path; },
      });
    });
    const saveExport = U.el('button', { class: 'btn primary', text: '保存' });
    saveExport.addEventListener('click', async () => {
      await save({ export_dir: exportInput.value.trim() });
      UI.ok('已保存', exportInput.value.trim() ? '导出将写入该目录' : '导出改为只下载');
    });
    exportCard.appendChild(U.el('div', { class: 'btn-row' }, [exportInput, pickExport, saveExport]));
    host.appendChild(exportCard);

    // ---- 容器探测 ----
    const dockerCard = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('package', { size: 17 }) }),
        U.el('span', { text: '容器探测（可选）' }),
      ]),
    ]);
    const dockerBox = U.el('input', { type: 'checkbox', checked: settings.docker_enabled !== false });
    dockerBox.addEventListener('change', async () => {
      await save({ docker_enabled: dockerBox.checked });
      UI.ok(dockerBox.checked ? '已开启容器探测' : '已关闭容器探测');
    });
    dockerCard.appendChild(U.el('label', { class: 'small' }, [dockerBox, ' 启用容器清单（docker ps）']));
    dockerCard.appendChild(U.el('p', { class: 'small muted mt1',
      text: '引擎状态：' + ((summary.sources.docker && summary.sources.docker.detail) || '—') +
        '。关闭后端口地图照常工作，容器那一栏会显示「不可用」。' }));
    host.appendChild(dockerCard);

    // ---- 快照保留 ----
    const keepCard = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('clock', { size: 17 }) }),
        U.el('span', { text: '历史快照' }),
      ]),
    ]);
    const keepInput = U.el('input', {
      type: 'number', min: '1', max: '500', value: String(settings.snapshot_keep || 50),
      style: 'width:110px',
    });
    const keepSave = U.el('button', { class: 'btn primary', text: '保存' });
    keepSave.addEventListener('click', async () => {
      const value = parseInt(keepInput.value, 10);
      if (!(value >= 1 && value <= 500)) { UI.warn('请填 1 ~ 500 之间的整数'); return; }
      await save({ snapshot_keep: value });
      UI.ok('已保存', '之后每次采集会自动裁掉多余的历史');
    });
    keepCard.appendChild(U.el('div', { class: 'btn-row' }, [
      U.el('span', { class: 'small', text: '保留最近' }), keepInput,
      U.el('span', { class: 'small', text: '次快照' }), keepSave,
    ]));
    keepCard.appendChild(U.el('p', { class: 'small muted mt1',
      text: '当前已有 ' + summary.snapshots.count + ' 份快照。' }));
    host.appendChild(keepCard);

    // ---- 关于 / 只读声明 ----
    const aboutCard = U.el('div', { class: 'card' }, [
      U.el('h2', {}, [
        U.el('span', { html: Icons.svg('info', { size: 17 }) }),
        U.el('span', { text: '只读声明与指纹说明' }),
      ]),
      U.el('p', { class: 'small', text:
        '本应用是严格只读的：只读取 /proc 的监听套接字表、/etc/services 与 docker ps 的输出。' +
        '它不会启动、停止、重启或修改任何服务与容器，不执行任何命令，也不提供任何' +
        '「执行命令」的入口。唯一的写操作是它自己的数据目录（SQLite 快照与日志）' +
        '以及你显式指定的导出目录。' }),
    ]);
    const fpBtn = U.el('button', { class: 'btn', text: '查看端口指纹表' });
    fpBtn.addEventListener('click', showFingerprints);
    const aboutBtn = U.el('button', { class: 'btn', text: '关于与隐私' });
    aboutBtn.addEventListener('click', showAbout);
    aboutCard.appendChild(U.el('div', { class: 'btn-row' }, [fpBtn, aboutBtn]));
    host.appendChild(aboutCard);

    async function save(payload) {
      try {
        await API.post('api/settings', payload);
      } catch (error) {
        UI.err(error, '保存失败');
      }
    }
  }

  async function showFingerprints() {
    try {
      const body = await API.get('api/services/fingerprints');
      const rows = body.fingerprints.map((row) =>
        '<tr><td class="mono">' + row.port + '</td><td>' + U.esc(row.name) +
        '</td><td>' + U.esc(row.kind_label) + '</td><td>' +
        (row.web ? '可打开' : '—') + '</td><td class="small">' + U.esc(row.note) +
        '</td></tr>').join('');
      UI.modal({
        title: '端口指纹表（共 ' + body.count + ' 条）',
        icon: 'hash',
        wide: true,
        bodyHtml:
          '<p class="small">' + U.esc(body.note) + '</p>' +
          '<div class="table-wrap"><table class="data"><thead><tr>' +
          '<th>端口</th><th>服务</th><th>类别</th><th>可打开</th><th>说明</th>' +
          '</tr></thead><tbody>' + rows + '</tbody></table></div>',
        buttons: [{ text: '关闭' }],
      });
    } catch (error) {
      UI.err(error, '无法读取指纹表');
    }
  }

  async function showAbout() {
    let info = {};
    try { info = await API.get('api/app'); } catch (error) { /* 用默认值 */ }
    UI.modal({
      title: '关于',
      icon: 'info',
      wide: true,
      bodyHtml:
        '<p><b>服务中心（Service Center）</b> v' + U.esc(info.version || '') + '</p>' +
        '<p class="small muted">回答「我的 TNAS 到底在跑什么」：端口地图、服务指纹、' +
        '容器清单与一键打开。全部处理都在本机离线完成。</p>' +
        '<h3 class="mt2">只读</h3>' +
        '<ul class="small"><li>不启动、停止、重启、修改任何服务或容器</li>' +
        '<li>不做 docker exec，也没有任何执行命令的入口</li>' +
        '<li>不联网、不上传任何信息</li></ul>' +
        '<h3 class="mt2">隐私</h3>' +
        '<ul class="small"><li>不收集使用统计、遥测或设备标识</li>' +
        '<li>不读取你的文件内容（导出只在你自己指定的目录里写文件）</li></ul>' +
        '<h3 class="mt2">运行时写入位置</h3>' +
        '<pre class="logview small">' +
        U.esc(info.paths ? JSON.stringify(info.paths, null, 2) : '') + '</pre>' +
        '<p class="small muted mt1">完整清单见包内 README.md 的' +
        '「运行时写入路径清单（指引 12.9.6）」，隐私政策见 PRIVACY.md。</p>',
      buttons: [{ text: '关闭' }],
    });
  }

  /* ------------------------------------------------------------ 启动 */

  async function boot() {
    Jobs.mountTaskbar(U.byId('taskbar'));
    Jobs.start(2500);

    const shell = Shell.init({
      overview: { label: '概览', icon: 'home', render: renderOverview },
      ports: { label: '端口地图', icon: 'server', render: renderPorts },
      containers: { label: '容器', icon: 'package', render: renderContainers },
      changes: { label: '变化历史', icon: 'clock', render: renderChanges },
      jobs: { label: '任务', icon: 'activity', render: renderJobs },
      settings: { label: '设置', icon: 'settings', render: renderSettings },
    }, { defaultView: 'overview' });
    window.Shell = shell;
    shellRef = shell;

    try {
      const app = await Shell.loadAppInfo();
      State.app = app;
      const meta = U.byId('source-meta');
      if (meta) {
        const docker = app && app.engines ? app.engines.docker : null;
        meta.textContent = '只读 · 端口地图' + (docker ? ' · Docker 可用' : ' · 无 Docker');
      }
    } catch (error) {
      const meta = U.byId('source-meta');
      if (meta) meta.textContent = '服务未就绪';
    }

    shell.show(shell.current() || 'overview');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
