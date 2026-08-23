/**
 * ============================================================
 *  Cloudflare Worker 文本/文件分享平台
 *  - KV 存储：分享元数据、文本内容、配置、会话、统计
 *  - R2 存储：文件二进制
 *  功能：文本分享(Markdown预览/高亮/公式)、文件分享(拖拽/进度/预览)、
 *        密码保护、过期时间、自定义后缀、访问次数限制、
 *        管理员后台、上传开关、自动过期清理、存储统计
 * ============================================================
 *
 *  环境变量(Variables):
 *    ADMIN_PASSWORD  - 管理员明文密码(首次启动自动哈希化存入KV,之后可删)
 *    TOKEN           - 可选,路径前缀(如 abc123 -> /abc123/...)
 *    EXPIRE          - 可选,默认文本过期秒数(0=永久),默认300
 *
 *  绑定(Bindings):
 *    KV  - KV Namespace (变量名固定为 KV)
 *    R2  - R2 Bucket    (变量名固定为 R2)
 * ============================================================
 */

addEventListener('fetch', event => {
  event.respondWith(
    handleRequest(event.request).catch(err => {
      // 全局错误捕获: 返回 JSON 而不是 Cloudflare 默认 HTML 错误页, 方便排查
      return new Response(
        JSON.stringify({ error: 'Worker 内部错误', detail: err.message, stack: err.stack }),
        { status: 500, headers: { 'Content-Type': 'application/json;charset=UTF-8' } }
      );
    })
  );
});

/* ========================= 常量 ========================= */
const MAX_FILE_SIZE = 98 * 1024 * 1024; // 单文件 98MB
const MAX_BODY_SIZE = 100 * 1024 * 1024; // Worker 请求体上限保护
const PBKDF2_ITER = 100000; // Cloudflare Worker PBKDF2 上限为 100000, 不可超过
const SESSION_TTL = 7 * 24 * 3600; // 管理员会话 7 天
const SHARE_PREFIX = 'share:';
const CONFIG_KEY = 'config:v1';
const STATS_KEY = 'stats:v1';
const SESSION_PREFIX = 'sess:';

/* ========================= 工具函数 ========================= */

/** 生成随机 ID */
function genId(len = 8) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => chars[b % chars.length]).join('');
}

/** 生成纯数字分享码 */
function genCode(len = 6) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => (b % 10).toString()).join('');
}

/** base64 <-> Uint8Array */
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

/** PBKDF2 密码哈希 */
async function hashPassword(password, saltB64) {
  const salt = saltB64 ? b64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, key, 256
  );
  return { salt: bytesToB64(salt), hash: bytesToB64(new Uint8Array(bits)) };
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.salt || !stored.hash) return false;
  const r = await hashPassword(password, stored.salt);
  return r.hash === stored.hash;
}

/** 读取 JSON body (带大小保护) */
async function readJson(request) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_BODY_SIZE) throw new Error('payload too large');
  return request.json();
}

/** 统一 JSON 响应 */
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json;charset=UTF-8', ...extraHeaders }
  });
}

/** HTML 响应 */
function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

/** 格式化大小 */
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

/** 路径前缀 */
function tokenPath() {
  return globalThis.TOKEN ? '/' + globalThis.TOKEN : '';
}
function P(p) { return tokenPath() + p; }

/* ========================= 数据层 ========================= */

async function getConfig() {
  let cfg = await KV.get(CONFIG_KEY, 'json');
  if (!cfg) {
    cfg = {
      textUploadEnabled: true,
      fileUploadEnabled: true,
      adminPassword: null, // {salt,hash}
      createdAt: Date.now()
    };
    // 首次启动: 从环境变量初始化管理员密码
    if (globalThis.ADMIN_PASSWORD) {
      cfg.adminPassword = await hashPassword(globalThis.ADMIN_PASSWORD);
    }
    await KV.put(CONFIG_KEY, JSON.stringify(cfg));
  }
  return cfg;
}

async function saveConfig(cfg) {
  await KV.put(CONFIG_KEY, JSON.stringify(cfg));
}

async function getStats() {
  let s = await KV.get(STATS_KEY, 'json');
  if (!s) {
    s = { totalFiles: 0, totalBytes: 0, totalShares: 0, lastCleanup: 0 };
    await KV.put(STATS_KEY, JSON.stringify(s));
  }
  return s;
}
async function saveStats(s) { await KV.put(STATS_KEY, JSON.stringify(s)); }

async function getShare(id) {
  return KV.get(SHARE_PREFIX + id, 'json');
}
async function putShare(share) {
  await KV.put(SHARE_PREFIX + share.id, JSON.stringify(share));
}
async function deleteShareRecord(id) {
  await KV.delete(SHARE_PREFIX + id);
}

/** 列出所有分享(带分页) */
async function listShares(limit = 1000) {
  const out = [];
  let cursor = undefined;
  do {
    const r = await KV.list({ prefix: SHARE_PREFIX, cursor, limit: Math.min(limit, 1000) });
    for (const k of r.keys) {
      const v = await KV.get(k.name, 'json');
      if (v) out.push(v);
    }
    cursor = r.list_complete ? undefined : r.cursor;
  } while (cursor && out.length < limit);
  return out;
}

/** 创建会话 token */
async function createSession() {
  const token = genId(32);
  await KV.put(SESSION_PREFIX + token, '1', { expirationTtl: SESSION_TTL });
  return token;
}
async function verifySession(token) {
  if (!token) return false;
  return !!(await KV.get(SESSION_PREFIX + token));
}
async function destroySession(token) {
  if (token) await KV.delete(SESSION_PREFIX + token);
}

/** 从请求提取管理员 token */
function getAuthToken(request) {
  const h = request.headers.get('Authorization') || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return null;
}

/* ========================= 自动过期清理 ========================= */

/** 整点触发清理: 遍历所有分享,删除已过期/超访问次数的 */
async function cleanupExpired() {
  const stats = await getStats();
  const now = Date.now();
  // 每小时最多清理一次
  const hour = Math.floor(now / 3600000);
  if (stats.lastCleanup === hour) return;
  stats.lastCleanup = hour;

  const shares = await listShares(5000);
  let removedBytes = 0, removedFiles = 0, removedShares = 0;

  for (const s of shares) {
    const expired = s.expireAt && s.expireAt <= now;
    const overViews = s.maxViews && s.maxViews > 0 && s.views >= s.maxViews;
    if (expired || overViews) {
      // 删除 R2 文件
      if (s.type === 'file' && s.files) {
        for (const f of s.files) {
          try { await R2.delete(f.r2key); removedBytes += f.size; removedFiles++; } catch (e) {}
        }
      }
      await deleteShareRecord(s.id);
      removedShares++;
    }
  }

  stats.totalFiles = Math.max(0, stats.totalFiles - removedFiles);
  stats.totalBytes = Math.max(0, stats.totalBytes - removedBytes);
  stats.totalShares = Math.max(0, stats.totalShares - removedShares);
  await saveStats(stats);
}

/* ========================= 分享创建 ========================= */

/**
 * 创建文本分享
 * body: { content, title?, password?, expireMinutes?, customSuffix?, maxViews? }
 */
async function createTextShare(body, cfg) {
  if (!cfg.textUploadEnabled) throw new Error('文本分享已被管理员关闭');
  const content = typeof body.content === 'string' ? body.content : '';
  if (!content.trim()) throw new Error('内容不能为空');
  if (content.length > 5 * 1024 * 1024) throw new Error('文本过大(>5MB)');

  let id = genCode(6);
  if (body.customSuffix) {
    const suf = String(body.customSuffix).trim().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32);
    if (suf) {
      if (await getShare(suf)) throw new Error('该分享号已被占用');
      id = suf;
    }
  } else {
    while (await getShare(id)) id = genCode(6);
  }

  const now = Date.now();
  const expireMinutes = Number(body.expireMinutes);
  const share = {
    id,
    type: 'text',
    title: (body.title || '').slice(0, 120),
    content,
    password: body.password ? await hashPassword(body.password) : null,
    expireAt: (expireMinutes && expireMinutes > 0) ? now + expireMinutes * 60000 : null,
    maxViews: Number(body.maxViews) > 0 ? Number(body.maxViews) : null,
    views: 0,
    createdAt: now
  };
  await putShare(share);
  const stats = await getStats();
  stats.totalShares++;
  await saveStats(stats);
  return share;
}

/**
 * 创建文件分享(metadata 先存,文件通过 /api/upload 分片或直接传)
 * 这里采用: 前端先 POST /api/share/file 拿到 shareId, 再逐个 PUT /api/upload/<shareId>/<index>
 */
async function createFileShareMeta(body, cfg) {
  if (!cfg.fileUploadEnabled) throw new Error('文件分享已被管理员关闭');
  const files = Array.isArray(body.files) ? body.files : [];
  if (!files.length) throw new Error('没有文件');

  let id = genCode(6);
  if (body.customSuffix) {
    const suf = String(body.customSuffix).trim().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32);
    if (suf) {
      if (await getShare(suf)) throw new Error('该分享号已被占用');
      id = suf;
    }
  } else {
    while (await getShare(id)) id = genCode(6);
  }

  const now = Date.now();
  const expireMinutes = Number(body.expireMinutes);
  const totalSize = files.reduce((a, f) => a + (Number(f.size) || 0), 0);

  const share = {
    id,
    type: 'file',
    title: (body.title || '').slice(0, 120),
    files: files.map((f, i) => ({
      index: i,
      name: String(f.name || 'file').slice(0, 200),
      size: Number(f.size) || 0,
      type: String(f.type || '').slice(0, 100),
      r2key: `${id}/${i}-${genId(4)}`,
      uploaded: false
    })),
    totalSize,
    password: body.password ? await hashPassword(body.password) : null,
    expireAt: (expireMinutes && expireMinutes > 0) ? now + expireMinutes * 60000 : null,
    maxViews: Number(body.maxViews) > 0 ? Number(body.maxViews) : null,
    maxDownloads: Number(body.maxDownloads) > 0 ? Number(body.maxDownloads) : null,
    downloads: 0,
    views: 0,
    createdAt: now,
    ready: false // 所有文件上传完成后置 true
  };
  await putShare(share);
  const stats = await getStats();
  stats.totalShares++;
  await saveStats(stats);
  return share;
}

/* ========================= 主路由 ========================= */

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const tp = tokenPath();

  // 后台异步清理(整点)
  // 注意: 不能 await, 否则拖慢响应
  cleanupExpired().catch(() => {});

  // ---------- 兼容旧版简单剪贴板 ----------
  if (path === P('/save') && request.method === 'POST') {
    const content = await request.text();
    if (!content) return new Response('empty', { status: 400 });
    let expireTime = Number(globalThis.EXPIRE ?? 300);
    const opt = {};
    if (expireTime !== 0) opt.expirationTtl = expireTime < 60 ? 60 : expireTime;
    try { await KV.put('clipboard', content, opt); return new Response('saved'); }
    catch (e) { return new Response('failed', { status: 500 }); }
  }
  if (path === P('/read') && request.method === 'GET') {
    const c = await KV.get('clipboard');
    return c ? new Response(c) : new Response(null, { status: 400 });
  }
  if (path === P('/clear')) {
    await KV.delete('clipboard');
    return new Response('cleared');
  }

  // ---------- PWA manifest ----------
  if (path === P('/manifest.json')) {
    return json({
      name: '在线分享', short_name: '分享',
      start_url: P('/'), display: 'standalone',
      background_color: '#f4f4f4', theme_color: '#007bff',
      icons: [{ src: 'https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/e2/ac/0a/e2ac0a63-9c11-2fd0-9d59-e5b4b512545f/AppIcon-0-0-1x_U007emarketing-0-8-0-85-220.png/400x400ia-75.webp', sizes: '192x192', type: 'image/webp' }]
    });
  }

  // ---------- PWA Service Worker ----------
  if (path === P('/sw.js')) {
    const sw = `
const CACHE = 'share-v1';
const CDN = [
  'https://cdn.jsdelivr.net/npm/marked/marked.min.js',
  'https://cdn.jsdelivr.net/npm/highlight.js@11/styles/github.min.css',
  'https://cdn.jsdelivr.net/npm/highlight.js@11/lib/highlight.min.js',
  'https://cdn.jsdelivr.net/npm/katex@0.16/dist/katex.min.css',
  'https://cdn.jsdelivr.net/npm/katex@0.16/dist/katex.min.js',
];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(CDN)).catch(()=>{}));
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  // CDN 资源: 缓存优先
  if (CDN.some(u => req.url.startsWith(u))) {
    e.respondWith(caches.match(req).then(r => r || fetch(req).then(res => {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(req, copy)).catch(()=>{});
      return res;
    }).catch(()=>caches.match(req))));
    return;
  }
  // 同源导航请求: 网络优先, 失败回退缓存
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req).then(res => {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(req, copy)).catch(()=>{});
      return res;
    }).catch(() => caches.match(req).then(r => r || caches.match('./'))));
  }
});
`;
    return new Response(sw, { headers: { 'Content-Type': 'application/javascript;charset=UTF-8', 'Cache-Control': 'no-cache' } });
  }

  // ---------- API 路由 ----------
  if (path.startsWith(P('/api/'))) {
    return handleAPI(request, path);
  }

  // ---------- 管理员后台 ----------
  if (path === P('/admin')) {
    return html(adminPage());
  }

  // ---------- 查看分享 ----------
  // 形如 /<id> 或 /<token>/<id>
  let shareId = null;
  if (tp) {
    if (path.startsWith(tp + '/') && path.length > tp.length + 1) {
      shareId = path.slice(tp.length + 1).split('/')[0];
    }
  } else {
    if (path !== '/' && path !== '') {
      shareId = path.slice(1).split('/')[0];
    }
  }

  if (shareId) {
    // 排除保留字
    if (!['api','admin','save','read','clear','manifest.json','static'].includes(shareId)) {
      const share = await getShare(shareId);
      if (share) return html(viewPage(share));
      // 不存在 fallthrough 到 404
    }
  }

  // ---------- 主页 ----------
  if (path === P('/') || path === (tp || '/')) {
    return html(homePage());
  }

  return new Response(null, { status: 404 });
}

/* ========================= API 处理 ========================= */

async function handleAPI(request, path) {
  const method = request.method;
  const url = new URL(request.url);
  const cfg = await getConfig();

  // ---- 管理员登录 ----
  if (path === P('/api/admin/login') && method === 'POST') {
    const body = await readJson(request);
    if (!cfg.adminPassword) return json({ error: '管理员未初始化,请先设置 ADMIN_PASSWORD 环境变量' }, 400);
    const ok = await verifyPassword(body.password || '', cfg.adminPassword);
    if (!ok) return json({ error: '密码错误' }, 401);
    const token = await createSession();
    return json({ token });
  }

  // ---- 管理员登出 ----
  if (path === P('/api/admin/logout') && method === 'POST') {
    await destroySession(getAuthToken(request));
    return json({ ok: true });
  }

  // 以下接口需要管理员权限
  const adminPaths = [
    P('/api/admin/shares'), P('/api/admin/config'), P('/api/admin/stats'),
  ];
  const isAdminApi = adminPaths.some(p => path.startsWith(p)) ||
    path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[^/]+/(delete|password|edit|toggle-upload)$'));

  let isAdmin = false;
  if (isAdminApi) {
    isAdmin = await verifySession(getAuthToken(request));
    if (!isAdmin) return json({ error: '未授权' }, 401);
  }

  // ---- 管理员: 分享列表 ----
  if (path === P('/api/admin/shares') && method === 'GET') {
    const list = await listShares(2000);
    // 按创建时间倒序
    list.sort((a, b) => b.createdAt - a.createdAt);
    return json({ shares: list.map(s => slimShare(s)) });
  }

  // ---- 管理员: 配置读写 ----
  if (path === P('/api/admin/config') && method === 'GET') {
    return json({
      textUploadEnabled: cfg.textUploadEnabled,
      fileUploadEnabled: cfg.fileUploadEnabled,
      hasAdminPassword: !!cfg.adminPassword
    });
  }
  if (path === P('/api/admin/config') && method === 'PUT') {
    const body = await readJson(request);
    if (typeof body.textUploadEnabled === 'boolean') cfg.textUploadEnabled = body.textUploadEnabled;
    if (typeof body.fileUploadEnabled === 'boolean') cfg.fileUploadEnabled = body.fileUploadEnabled;
    if (body.newAdminPassword) {
      cfg.adminPassword = await hashPassword(body.newAdminPassword);
    }
    await saveConfig(cfg);
    return json({ ok: true });
  }

  // ---- 管理员: 统计 ----
  if (path === P('/api/admin/stats') && method === 'GET') {
    const stats = await getStats();
    return json({
      totalShares: stats.totalShares,
      totalFiles: stats.totalFiles,
      totalBytes: stats.totalBytes,
      totalBytesHuman: formatSize(stats.totalBytes),
      // R2 免费额度参考 10GB,可自行调整
      quotaBytes: 10 * 1024 * 1024 * 1024,
      usagePercent: ((stats.totalBytes / (10 * 1024 * 1024 * 1024)) * 100).toFixed(2)
    });
  }

  // ---- 创建文本分享 ----
  if (path === P('/api/share/text') && method === 'POST') {
    try {
      const body = await readJson(request);
      const share = await createTextShare(body, cfg);
      return json({ ok: true, id: share.id, url: P('/' + share.id) });
    } catch (e) {
      return json({ error: e.message }, 400);
    }
  }

  // ---- 创建文件分享(元数据) ----
  if (path === P('/api/share/file') && method === 'POST') {
    try {
      const body = await readJson(request);
      const share = await createFileShareMeta(body, cfg);
      return json({ ok: true, id: share.id, url: P('/' + share.id), files: share.files });
    } catch (e) {
      return json({ error: e.message }, 400);
    }
  }

  // ---- 上传单个文件 PUT /api/upload/<shareId>/<index> ----
  const uploadMatch = path.match(new RegExp('^' + P('/api/upload/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)/(\\d+)$'));
  if (uploadMatch && method === 'PUT') {
    const shareId = uploadMatch[1];
    const index = Number(uploadMatch[2]);
    const share = await getShare(shareId);
    if (!share || share.type !== 'file') return json({ error: '分享不存在' }, 404);
    const fileMeta = share.files.find(f => f.index === index);
    if (!fileMeta) return json({ error: '文件索引错误' }, 400);

    const len = Number(request.headers.get('content-length') || 0);
    if (len > MAX_FILE_SIZE) return json({ error: '文件超过 98MB 限制' }, 413);

    // 流式写入 R2
    await R2.put(fileMeta.r2key, request.body, {
      httpMetadata: { contentType: fileMeta.type || 'application/octet-stream' }
    });
    fileMeta.uploaded = true;
    fileMeta.size = len || fileMeta.size;
    // 检查是否全部上传完成
    share.ready = share.files.every(f => f.uploaded);
    share.totalSize = share.files.reduce((a, f) => a + f.size, 0);
    await putShare(share);

    const stats = await getStats();
    stats.totalFiles++;
    stats.totalBytes += fileMeta.size;
    await saveStats(stats);

    return json({ ok: true, ready: share.ready });
  }

  // ---- 获取分享元数据(含密码校验) ----
  const getMatch = path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)$'));
  if (getMatch && method === 'GET') {
    const shareId = getMatch[1];
    const share = await getShare(shareId);
    if (!share) return json({ error: '不存在' }, 404);
    // 过期/超次数检查
    if (share.expireAt && share.expireAt <= Date.now()) {
      await deleteShareRecord(shareId); return json({ error: '分享已过期' }, 410);
    }
    if (share.maxViews && share.maxViews > 0 && share.views >= share.maxViews) {
      return json({ error: '访问次数已用完' }, 410);
    }
    // 需要密码
    if (share.password) {
      const pwd = url.searchParams.get('password') || request.headers.get('X-Share-Password');
      if (!pwd || !(await verifyPassword(pwd, share.password))) {
        return json({ needPassword: true, type: share.type, title: share.title });
      }
    }
    // 计数 +1
    share.views = (share.views || 0) + 1;
    await putShare(share);

    return json(slimShare(share, true));
  }

  // ---- 校验分享密码 ----
  const pwdMatch = path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)/verify$'));
  if (pwdMatch && method === 'POST') {
    const shareId = pwdMatch[1];
    const share = await getShare(shareId);
    if (!share) return json({ error: '不存在' }, 404);
    const body = await readJson(request);
    if (!share.password) return json({ ok: true });
    const ok = await verifyPassword(body.password || '', share.password);
    if (!ok) return json({ error: '密码错误' }, 401);
    return json({ ok: true });
  }

  // ---- 下载/预览文件 GET /api/share/<id>/file/<index> ----
  const dlMatch = path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)/file/(\\d+)$'));
  if (dlMatch && method === 'GET') {
    const shareId = dlMatch[1];
    const index = Number(dlMatch[2]);
    const share = await getShare(shareId);
    if (!share) return new Response('not found', { status: 404 });
    if (share.password) {
      const pwd = url.searchParams.get('password');
      if (!pwd || !(await verifyPassword(pwd, share.password))) {
        return new Response('需要密码', { status: 401 });
      }
    }
    if (share.expireAt && share.expireAt <= Date.now()) return new Response('expired', { status: 410 });
    const f = share.files.find(x => x.index === index);
    if (!f) return new Response('not found', { status: 404 });

    const obj = await R2.get(f.r2key);
    if (!obj) return new Response('not found', { status: 404 });

    // 下载次数限制
    if (share.maxDownloads && share.maxDownloads > 0) {
      if ((share.downloads || 0) >= share.maxDownloads) {
        return new Response('下载次数已用完', { status: 410 });
      }
      share.downloads = (share.downloads || 0) + 1;
      await putShare(share);
    }

    const headers = new Headers();
    // 手动设置 Content-Type, 不使用 writeHttpMetadata(可能写入不可控的头导致浏览器拒绝下载)
    const contentType = f.type || 'application/octet-stream';
    headers.set('Content-Type', contentType);
    headers.set('Content-Length', obj.size.toString());
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('Accept-Ranges', 'bytes');
    // 带密码的动态内容不使用公共缓存
    headers.set('Cache-Control', 'private, no-store');
    // Content-Disposition: 同时提供 filename(ASCII fallback) 和 filename*(RFC5987 中文)
    const asciiName = f.name.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
    const inline = /^(image\/|audio\/|video\/|application\/pdf|text\/)/.test(f.type);
    const dispType = (!inline || url.searchParams.get('download') === '1') ? 'attachment' : 'inline';
    headers.set('Content-Disposition', `${dispType}; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(f.name)}`);
    return new Response(obj.body, { headers });
  }

  // ---- 管理员: 删除分享 ----
  const delMatch = path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)/delete$'));
  if (delMatch && method === 'POST') {
    const shareId = delMatch[1];
    const share = await getShare(shareId);
    if (!share) return json({ error: '不存在' }, 404);
    let removedBytes = 0, removedFiles = 0;
    if (share.type === 'file' && share.files) {
      for (const f of share.files) {
        try { await R2.delete(f.r2key); removedBytes += f.size; removedFiles++; } catch (e) {}
      }
    }
    await deleteShareRecord(shareId);
    const stats = await getStats();
    stats.totalShares = Math.max(0, stats.totalShares - 1);
    stats.totalFiles = Math.max(0, stats.totalFiles - removedFiles);
    stats.totalBytes = Math.max(0, stats.totalBytes - removedBytes);
    await saveStats(stats);
    return json({ ok: true });
  }

  // ---- 管理员: 修改/移除分享密码 ----
  const pwdEditMatch = path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)/password$'));
  if (pwdEditMatch && method === 'PUT') {
    const shareId = pwdEditMatch[1];
    const share = await getShare(shareId);
    if (!share) return json({ error: '不存在' }, 404);
    const body = await readJson(request);
    if (body.password && String(body.password).trim()) {
      share.password = await hashPassword(String(body.password).trim());
    } else {
      share.password = null; // 清空密码
    }
    await putShare(share);
    return json({ ok: true, hasPassword: !!share.password });
  }

  // ---- 管理员: 修改次数限制(访问次数/下载次数) ----
  const limitsMatch = path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)/limits$'));
  if (limitsMatch && method === 'PUT') {
    const shareId = limitsMatch[1];
    const share = await getShare(shareId);
    if (!share) return json({ error: '不存在' }, 404);
    const body = await readJson(request);
    if (body.maxViews !== undefined) {
      const v = Number(body.maxViews);
      share.maxViews = v > 0 ? v : null; // 0 或空 = 不限
    }
    if (body.maxDownloads !== undefined) {
      const v = Number(body.maxDownloads);
      share.maxDownloads = v > 0 ? v : null;
    }
    await putShare(share);
    return json({ ok: true, maxViews: share.maxViews, maxDownloads: share.maxDownloads });
  }

  // ---- 管理员: 修改分享号 ----
  const renameMatch = path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)/rename$'));
  if (renameMatch && method === 'PUT') {
    const oldId = renameMatch[1];
    const share = await getShare(oldId);
    if (!share) return json({ error: '不存在' }, 404);
    const body = await readJson(request);
    const newId = String(body.newId || '').trim().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32);
    if (!newId) return json({ error: '分享号不能为空' }, 400);
    if (newId === oldId) return json({ ok: true, id: oldId });
    if (await getShare(newId)) return json({ error: '该分享号已被占用' }, 400);
    // 保留字检查
    if (['api','admin','save','read','clear','manifest.json','static','sw.js'].includes(newId)) {
      return json({ error: '该分享号为系统保留字' }, 400);
    }
    share.id = newId;
    await putShare(share); // 存入新 key
    await deleteShareRecord(oldId); // 删除旧 key
    return json({ ok: true, id: newId });
  }

  // ---- 管理员: 编辑文本内容 ----
  const editMatch = path.match(new RegExp('^' + P('/api/share/').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^/]+)/edit$'));
  if (editMatch && method === 'PUT') {
    const shareId = editMatch[1];
    const share = await getShare(shareId);
    if (!share || share.type !== 'text') return json({ error: '不存在或非文本' }, 404);
    const body = await readJson(request);
    if (typeof body.content === 'string') share.content = body.content;
    if (typeof body.title === 'string') share.title = body.title.slice(0, 120);
    await putShare(share);
    return json({ ok: true });
  }

  return json({ error: 'not found' }, 404);
}

/** 精简分享对象(去掉敏感字段) */
function slimShare(s, includeContent = false) {
  const out = {
    id: s.id,
    type: s.type,
    title: s.title,
    createdAt: s.createdAt,
    expireAt: s.expireAt,
    maxViews: s.maxViews,
    views: s.views,
    hasPassword: !!s.password,
    ready: s.ready
  };
  if (s.type === 'text') {
    if (includeContent) out.content = s.content;
  } else {
    out.files = s.files.map(f => ({ index: f.index, name: f.name, size: f.size, type: f.type, uploaded: f.uploaded }));
    out.totalSize = s.totalSize;
    out.maxDownloads = s.maxDownloads;
    out.downloads = s.downloads;
  }
  return out;
}

/* ========================= 前端页面 ========================= */

/** 通用头部资源 */
const COMMON_HEAD = `
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#007bff" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#1a1d27" media="(prefers-color-scheme: dark)">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<link rel="manifest" href="${P('/manifest.json')}">
<link rel="apple-touch-icon" href="https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/e2/ac/0a/e2ac0a63-9c11-2fd0-9d59-e5b4b512545f/AppIcon-0-0-1x_U007emarketing-0-8-0-85-220.png/400x400ia-75.webp">
<script>
// 主题初始化(在CSS加载前执行, 防止闪烁)
(function(){
  var t = localStorage.getItem('theme');
  if(!t) t = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);
})();
// PWA Service Worker 注册
if('serviceWorker' in navigator) {
  window.addEventListener('load', function(){
    navigator.serviceWorker.register('${P('/sw.js')}').catch(function(){});
  });
}
</script>
`;

/** 主页 */
function homePage() {
  return `<!DOCTYPE html><html lang="zh-CN"><head>
${COMMON_HEAD}
<title>在线分享 - 文本与文件</title>
<style>${HOME_CSS}</style>
</head><body>
<div class="container">
  <header class="topbar">
    <h1>📤 在线分享</h1>
    <nav class="tabs">
      <button class="tab active" data-tab="text">📝 文本分享</button>
      <button class="tab" data-tab="file">📁 文件分享</button>
    </nav>
    <a class="admin-link" href="${P('/admin')}">管理后台</a>
    <button class="theme-toggle" id="theme-toggle" title="切换主题">🌙</button>
  </header>

  <!-- 提取分享 -->
  <div class="extract-bar">
    <span class="extract-icon">🔑</span>
    <input id="extract-code" type="text" placeholder="输入分享号，提取文本/文件" maxlength="32" autocomplete="off">
    <button id="btn-extract" class="btn-extract">提取</button>
  </div>

  <!-- 文本分享面板 -->
  <section id="panel-text" class="panel active">
    <div class="row">
      <input id="text-title" type="text" placeholder="标题(可选)" maxlength="120">
    </div>
    <div class="editor-wrap">
      <div class="editor-pane">
        <div class="pane-label">编辑 (Markdown)</div>
        <textarea id="text-content" placeholder="在此输入文本,支持 Markdown 语法..."></textarea>
        <div class="resize-handle" id="resize-handle" title="拖动调整编辑器高度"></div>
      </div>
      <div class="preview-pane">
        <div class="pane-label">实时预览</div>
        <div id="preview" class="markdown-body"></div>
      </div>
    </div>
    <div class="options">
      <label>密码 <input id="text-password" type="text" placeholder="留空=无密码"></label>
      <label>过期(分钟) <input id="text-expire" type="number" min="1" placeholder="留空=永久"></label>
      <label>自定义分享号 <input id="text-suffix" type="text" placeholder="如 mynote（留空随机）" maxlength="32"></label>
      <label>访问次数 <input id="text-views" type="number" min="1" placeholder="留空=不限"></label>
    </div>
    <button id="btn-create-text" class="btn-primary">生成分享号</button>
    <div id="text-result" class="result"></div>
  </section>

  <!-- 文件分享面板 -->
  <section id="panel-file" class="panel">
    <div class="row">
      <input id="file-title" type="text" placeholder="分享标题(可选)" maxlength="120">
    </div>
    <div id="drop-zone" class="drop-zone">
      <div class="drop-inner">
        <div class="drop-icon">☁️</div>
        <div>拖拽文件到此处,或 <label class="file-label">点击选择<input id="file-input" type="file" multiple hidden></label></div>
        <div class="drop-hint">单文件最大 98MB,支持多文件</div>
      </div>
    </div>
    <div id="file-list" class="file-list"></div>
    <div class="options">
      <label>密码 <input id="file-password" type="text" placeholder="留空=无密码"></label>
      <label>过期(分钟) <input id="file-expire" type="number" min="1" placeholder="留空=永久"></label>
      <label>自定义分享号 <input id="file-suffix" type="text" placeholder="如 myfiles（留空随机）" maxlength="32"></label>
      <label>访问次数 <input id="file-views" type="number" min="1" placeholder="留空=不限"></label>
      <label>下载次数 <input id="file-downloads" type="number" min="1" placeholder="留空=不限"></label>
    </div>
    <button id="btn-create-file" class="btn-primary">开始上传并生成分享号</button>
    <button id="btn-cancel-upload" class="btn-danger" style="display:none;margin-left:8px">取消上传</button>
    <div id="file-result" class="result"></div>
  </section>
</div>

<!-- CDN: Markdown 解析 + 代码高亮 + 公式 -->
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/highlight.js@11/styles/github.min.css">
<script src="https://cdn.jsdelivr.net/npm/highlight.js@11/lib/highlight.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16/dist/katex.min.css">
<script src="https://cdn.jsdelivr.net/npm/katex@0.16/dist/katex.min.js"></script>
<script>
const API = {
  text: '${P('/api/share/text')}',
  file: '${P('/api/share/file')}',
  upload: (id, i) => '${P('/api/upload')}/' + id + '/' + i,
};
</script>
<script>${HOME_JS}</script>
</body></html>`;
}

const HOME_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:linear-gradient(135deg,#eef2ff 0%,#f5f7fa 50%,#f0f9ff 100%);color:#1e293b;line-height:1.6;min-height:100vh;transition:background .4s ease,color .3s ease}
.container{max-width:1100px;margin:0 auto;padding:24px 20px}
.topbar{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.topbar h1{font-size:24px;font-weight:700;background:linear-gradient(135deg,#007bff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.tabs{display:flex;gap:8px;background:#fff;padding:4px;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.tab{padding:8px 18px;border:none;background:transparent;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500;color:#64748b;transition:all .25s ease}
.tab.active{background:linear-gradient(135deg,#007bff,#4f46e5);color:#fff;box-shadow:0 2px 8px rgba(0,123,255,.35)}
.tab:not(.active):hover{background:#f1f5f9;color:#334155}
.admin-link{margin-left:auto;color:#007bff;text-decoration:none;font-size:14px}
.extract-bar{display:flex;align-items:center;gap:12px;margin-bottom:20px;background:linear-gradient(135deg,#fff 0%,#f0f7ff 100%);padding:16px 18px;border-radius:14px;box-shadow:0 4px 20px rgba(0,123,255,.1),0 1px 4px rgba(0,0,0,.04);border:1.5px solid #dbeafe;transition:all .3s ease}
.extract-icon{font-size:24px}
.extract-bar input{flex:1;padding:12px 16px;border:1.5px solid #cbd5e1;border-radius:10px;font-size:16px;outline:none;transition:all .25s ease;background:#fff;font-weight:500;letter-spacing:1px}
.extract-bar input:focus{border-color:#007bff;box-shadow:0 0 0 4px rgba(0,123,255,.12)}
.btn-extract{padding:12px 32px;background:linear-gradient(135deg,#10b981,#059669);color:#fff;border:none;border-radius:10px;cursor:pointer;font-size:15px;font-weight:600;transition:all .25s ease;box-shadow:0 2px 10px rgba(16,185,129,.3)}
.btn-extract:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(16,185,129,.45)}
.btn-extract:active{transform:translateY(0)}
.share-code-display{font-size:34px;font-weight:800;letter-spacing:8px;color:#007bff;text-align:center;margin:12px 0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:linear-gradient(135deg,#eff6ff,#dbeafe);padding:18px;border-radius:14px;user-select:all;border:2px solid #bfdbfe;box-shadow:inset 0 1px 3px rgba(0,0,0,.04)}
.result button{padding:7px 16px;border:1.5px solid #cbd5e1;background:#fff;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;transition:all .2s ease;color:#475569}
.result button:hover{background:#f8fafc;border-color:#94a3b8;color:#1e293b}
.panel{display:none;background:#fff;border-radius:16px;padding:24px;box-shadow:0 4px 24px rgba(0,0,0,.06),0 1px 4px rgba(0,0,0,.04);border:1px solid rgba(255,255,255,.8);transition:all .3s ease}
.panel.active{display:block;animation:fadeIn .3s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.row{margin-bottom:14px}
.row input{width:100%;padding:11px 14px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:14px;outline:none;transition:all .25s ease;background:#f8fafc}
.row input:focus{border-color:#007bff;background:#fff;box-shadow:0 0 0 4px rgba(0,123,255,.1)}
.editor-wrap{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;min-height:360px}
.editor-pane,.preview-pane{display:flex;flex-direction:column;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;background:#fff}
.pane-label{padding:6px 12px;background:#f3f4f6;font-size:12px;color:#666;border-bottom:1px solid #e5e7eb}
#text-content{flex:1;width:100%;border:none;outline:none;padding:12px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;resize:none;min-height:320px}
.preview-pane #preview{flex:1;padding:16px;overflow-y:auto;max-height:600px}
.resize-handle{height:6px;background:transparent;cursor:ns-resize;border-top:1px dashed #ccc}
.options{display:flex;flex-wrap:wrap;gap:14px;margin:16px 0;padding:14px;background:#f8fafc;border-radius:12px;border:1px solid #e2e8f0}
.options label{font-size:12px;color:#64748b;display:flex;flex-direction:column;gap:5px;font-weight:500}
.options input{padding:8px 12px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:13px;outline:none;transition:all .25s ease;background:#fff;width:150px}
.options input:focus{border-color:#007bff;box-shadow:0 0 0 3px rgba(0,123,255,.1)}
.btn-primary{padding:12px 28px;background:linear-gradient(135deg,#007bff,#4f46e5);color:#fff;border:none;border-radius:10px;cursor:pointer;font-size:15px;font-weight:600;transition:all .25s ease;box-shadow:0 2px 10px rgba(0,123,255,.3)}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(0,123,255,.45)}
.btn-primary:active{transform:translateY(0)}
.btn-primary:disabled{background:#cbd5e1;cursor:not-allowed;transform:none;box-shadow:none}
.btn-danger{padding:12px 24px;background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;border:none;border-radius:10px;cursor:pointer;font-size:15px;font-weight:600;transition:all .25s ease;box-shadow:0 2px 10px rgba(239,68,68,.3)}
.btn-danger:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(239,68,68,.45)}
.btn-danger:active{transform:translateY(0)}
.result{margin-top:16px;padding:18px;background:linear-gradient(135deg,#f0fdf4,#dcfce7);border:1.5px solid #bbf7d0;border-radius:14px;display:none;animation:fadeIn .3s ease}
.result.show{display:block}
.result a{color:#007bff;text-decoration:none;font-weight:500}
.result a:hover{text-decoration:underline}
.result.show{display:block}
.result a{color:#007bff;word-break:break-all}
.drop-zone{border:2px dashed #cbd5e1;border-radius:14px;padding:44px 20px;text-align:center;background:linear-gradient(180deg,#f8fafc 0%,#f1f5f9 100%);transition:all .3s ease;cursor:pointer}
.drop-zone:hover{border-color:#94a3b8;background:#f1f5f9}
.drop-zone.drag{border-color:#007bff;background:linear-gradient(180deg,#eff6ff 0%,#dbeafe 100%);transform:scale(1.01);box-shadow:0 4px 20px rgba(0,123,255,.15)}
.drop-icon{font-size:44px;margin-bottom:10px;filter:drop-shadow(0 2px 4px rgba(0,0,0,.1))}
.file-label{color:#007bff;cursor:pointer;text-decoration:none;font-weight:500}
.file-label:hover{text-decoration:underline}
.drop-hint{font-size:12px;color:#94a3b8;margin-top:8px}
.file-list{margin:14px 0}
.file-item{display:flex;align-items:center;gap:12px;padding:12px 16px;background:#fff;border-radius:12px;margin-bottom:8px;border:1px solid #e2e8f0;transition:all .25s ease;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.file-item:hover{border-color:#cbd5e1;box-shadow:0 4px 12px rgba(0,0,0,.08);transform:translateX(2px)}
.file-icon{font-size:24px;width:40px;height:40px;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#f1f5f9,#e2e8f0);border-radius:10px;flex-shrink:0}
.file-name{flex:1;font-size:14px;font-weight:500;color:#1e293b;word-break:break-all;min-width:0}
.file-size{font-size:12px;color:#94a3b8;min-width:60px;text-align:right;flex-shrink:0}
.file-progress{width:110px;height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden;flex-shrink:0}
.file-progress .bar{height:100%;background:linear-gradient(90deg,#007bff,#4f46e5);width:0;transition:width .2s ease;border-radius:4px}
.file-speed{font-size:11px;color:#64748b;min-width:70px;text-align:right;flex-shrink:0;font-variant-numeric:tabular-nums}
.file-cancel{background:none;border:none;color:#94a3b8;cursor:pointer;font-size:20px;padding:0 6px;transition:all .2s ease;line-height:1;border-radius:4px}
.file-cancel:hover{color:#ef4444;background:#fef2f2}
/* Markdown 样式 */
.markdown-body h1,.markdown-body h2,.markdown-body h3{margin:16px 0 8px;font-weight:600}
.markdown-body h1{font-size:1.6em;border-bottom:1px solid #eee;padding-bottom:6px}
.markdown-body h2{font-size:1.35em}
.markdown-body h3{font-size:1.15em}
.markdown-body p{margin:8px 0}
.markdown-body ul,.markdown-body ol{padding-left:24px;margin:8px 0}
.markdown-body li{margin:4px 0}
.markdown-body li ul,.markdown-body li ol{margin:2px 0}
.markdown-body blockquote{border-left:4px solid #dfe2e5;padding:4px 16px;color:#6a737d;background:#f6f8fa;margin:8px 0;border-radius:0 6px 6px 0}
.markdown-body code{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:0.9em;font-family:ui-monospace,monospace}
.markdown-body pre{background:#f6f8fa;padding:12px;border-radius:8px;overflow-x:auto;margin:8px 0}
.markdown-body pre code{background:none;padding:0}
.markdown-body table{border-collapse:collapse;margin:10px 0;width:100%}
.markdown-body th,.markdown-body td{border:1px solid #dfe2e5;padding:6px 12px;text-align:left}
.markdown-body th{background:#f3f4f6;font-weight:600}
.markdown-body tr:nth-child(even){background:#fafbfc}
.markdown-body img{max-width:100%;border-radius:6px}
.markdown-body a{color:#007bff}
.markdown-body hr{border:none;border-top:1px solid #eee;margin:16px 0}
@media(max-width:768px){.editor-wrap{grid-template-columns:1fr}.options input{width:100%}}
/* ===== 主题切换按钮 ===== */
.theme-toggle{background:none;border:1px solid #ddd;border-radius:8px;padding:6px 10px;cursor:pointer;font-size:16px;margin-left:8px}
/* ===== 暗黑模式 ===== */
[data-theme="dark"] body{background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%);color:#e2e8f0}
[data-theme="dark"] .panel,[data-theme="dark"] .extract-bar{background:linear-gradient(135deg,#1e293b 0%,#1a1d27 100%);border-color:#334155;box-shadow:0 4px 24px rgba(0,0,0,.4),0 1px 4px rgba(0,0,0,.3)}
[data-theme="dark"] .extract-bar input{background:#0f172a;color:#e2e8f0;border-color:#334155}
[data-theme="dark"] .extract-bar input:focus{border-color:#4d9fff;box-shadow:0 0 0 4px rgba(77,159,255,.15)}
[data-theme="dark"] .tabs{background:#1e293b;box-shadow:0 1px 4px rgba(0,0,0,.3)}
[data-theme="dark"] .tab{color:#94a3b8}
[data-theme="dark"] .tab.active{background:linear-gradient(135deg,#4d9fff,#6366f1);box-shadow:0 2px 10px rgba(77,159,255,.4)}
[data-theme="dark"] .tab:not(.active):hover{background:#334155;color:#e2e8f0}
[data-theme="dark"] .row input,[data-theme="dark"] .options input,[data-theme="dark"] #text-content{background:#0f172a;color:#e2e8f0;border-color:#334155}
[data-theme="dark"] .row input:focus,[data-theme="dark"] .options input:focus{border-color:#4d9fff;box-shadow:0 0 0 4px rgba(77,159,255,.12);background:#1e293b}
[data-theme="dark"] .editor-pane,[data-theme="dark"] .preview-pane{background:#1e293b;border-color:#334155}
[data-theme="dark"] .pane-label{background:#334155;color:#94a3b8;border-color:#334155}
[data-theme="dark"] .result{background:linear-gradient(135deg,#14532d,#166534);border-color:#166534;color:#e2e8f0}
[data-theme="dark"] .result button{background:#1e293b;color:#e2e8f0;border-color:#334155}
[data-theme="dark"] .result button:hover{background:#334155}
[data-theme="dark"] .drop-zone{background:linear-gradient(180deg,#1e293b 0%,#0f172a 100%);border-color:#334155}
[data-theme="dark"] .drop-zone:hover{border-color:#475569}
[data-theme="dark"] .drop-zone.drag{border-color:#4d9fff;background:linear-gradient(180deg,#1e3a5f 0%,#0f172a 100%)}
[data-theme="dark"] .file-item{background:#1e293b;border-color:#334155;box-shadow:0 1px 3px rgba(0,0,0,.3)}
[data-theme="dark"] .file-item:hover{border-color:#475569;box-shadow:0 4px 12px rgba(0,0,0,.4)}
[data-theme="dark"] .file-icon{background:linear-gradient(135deg,#334155,#1e293b)}
[data-theme="dark"] .file-name{color:#e2e8f0}
[data-theme="dark"] .file-size{color:#94a3b8}
[data-theme="dark"] .file-progress{background:#334155}
[data-theme="dark"] .file-progress .bar{background:linear-gradient(90deg,#4d9fff,#6366f1)}
[data-theme="dark"] .file-speed{color:#94a3b8}
[data-theme="dark"] .share-code-display{background:linear-gradient(135deg,#1e3a5f,#0f172a);border-color:#1e40af;color:#4d9fff;box-shadow:inset 0 1px 3px rgba(0,0,0,.3)}
[data-theme="dark"] .options{background:#0f172a;border-color:#334155}
[data-theme="dark"] .options label{color:#94a3b8}
[data-theme="dark"] .markdown-body{color:#e2e8f0}
[data-theme="dark"] .markdown-body h1,[data-theme="dark"] .markdown-body h2,[data-theme="dark"] .markdown-body h3{color:#f1f5f9}
[data-theme="dark"] .markdown-body h1{border-color:#334155}
[data-theme="dark"] .markdown-body blockquote{background:#0f172a;border-color:#334155;color:#94a3b8}
[data-theme="dark"] .markdown-body code{background:#334155;color:#e2e8f0}
[data-theme="dark"] .markdown-body pre{background:#0d1117}
[data-theme="dark"] .markdown-body pre code{background:none}
[data-theme="dark"] .markdown-body th{background:#334155}
[data-theme="dark"] .markdown-body th,[data-theme="dark"] .markdown-body td{border-color:#334155}
[data-theme="dark"] .markdown-body tr:nth-child(even){background:#0f172a}
[data-theme="dark"] .markdown-body hr{border-color:#334155}
[data-theme="dark"] .theme-toggle{border-color:#334155;color:#e2e8f0;background:#1e293b}
[data-theme="dark"] .admin-link{color:#4d9fff}
[data-theme="dark"] .btn-danger{background:linear-gradient(135deg,#dc2626,#991b1b)}
[data-theme="dark"] .btn-danger:hover{background:linear-gradient(135deg,#ef4444,#dc2626)}
`;

const HOME_JS = `
// ========== 提取分享(输入分享号跳转) ==========
function doExtract(){
  const code = document.getElementById('extract-code').value.trim();
  if(!code){ alert('请输入分享号'); return; }
  location.href = '${P('/')}' + encodeURIComponent(code);
}
document.getElementById('btn-extract').onclick = doExtract;
document.getElementById('extract-code').addEventListener('keydown', e => {
  if(e.key === 'Enter') doExtract();
});

// ========== 主题切换 ==========
(function(){
  const btn = document.getElementById('theme-toggle');
  function updateIcon(){ btn.textContent = document.documentElement.getAttribute('data-theme')==='dark' ? '☀️' : '🌙'; }
  updateIcon();
  btn.onclick = () => {
    const cur = document.documentElement.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateIcon();
  };
})();

// ========== Tab 切换 ==========
document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('panel-' + t.dataset.tab).classList.add('active');
  };
});

// ========== Markdown 渲染配置 ==========
marked.setOptions({
  breaks: true,
  gfm: true,
  highlight: function(code, lang) {
    try { return hljs.highlightAuto(code, [lang]).value; } catch(e){ return code; }
  }
});

function renderMarkdown(text) {
  // 处理数学公式 $...$ 和 $$...$$ (先占位避免 marked 转义)
  const blocks = [];
  text = text.replace(/\\$\\$([\\s\\S]+?)\\$\\$/g, (m, p1) => {
    blocks.push({type:'block', src:p1});
    return '@@KATEXBLOCK' + (blocks.length-1) + '@@';
  });
  text = text.replace(/\\$([^\\n$]+?)\\$/g, (m, p1) => {
    blocks.push({type:'inline', src:p1});
    return '@@KATEXINLINE' + (blocks.length-1) + '@@';
  });
  let html = marked.parse(text);
  html = html.replace(/@@KATEXBLOCK(\\d+)@@/g, (m, i) => {
    try { return '<div class="katex-block">' + katex.renderToString(blocks[i].src, {displayMode:true, throwOnError:false}) + '</div>'; }
    catch(e){ return '<pre>' + blocks[i].src + '</pre>'; }
  });
  html = html.replace(/@@KATEXINLINE(\\d+)@@/g, (m, i) => {
    try { return katex.renderToString(blocks[i].src, {displayMode:false, throwOnError:false}); }
    catch(e){ return '$' + blocks[i].src + '$'; }
  });
  return html;
}

const ta = document.getElementById('text-content');
const preview = document.getElementById('preview');
let renderTimer;
ta.addEventListener('input', () => {
  clearTimeout(renderTimer);
  renderTimer = setTimeout(() => { preview.innerHTML = renderMarkdown(ta.value); }, 150);
});
preview.innerHTML = renderMarkdown(ta.value);

// ========== 编辑器高度双向拉伸 ==========
(function(){
  const handle = document.getElementById('resize-handle');
  const wrap = document.querySelector('.editor-wrap');
  let dragging = false, startY, startH;
  handle.addEventListener('mousedown', e => { dragging=true; startY=e.clientY; startH=ta.offsetHeight; document.body.style.cursor='ns-resize'; e.preventDefault(); });
  document.addEventListener('mousemove', e => { if(!dragging) return; const h = Math.max(200, startH + (e.clientY-startY)); ta.style.height = h+'px'; });
  document.addEventListener('mouseup', () => { dragging=false; document.body.style.cursor=''; });
})();

// ========== 同步滚动 ==========
(function(){
  let syncing = false;
  ta.addEventListener('scroll', () => {
    if(syncing) return; syncing=true;
    const ratio = ta.scrollTop / (ta.scrollHeight - ta.clientHeight || 1);
    preview.scrollTop = ratio * (preview.scrollHeight - preview.clientHeight);
    setTimeout(()=>syncing=false,50);
  });
  preview.addEventListener('scroll', () => {
    if(syncing) return; syncing=true;
    const ratio = preview.scrollTop / (preview.scrollHeight - preview.clientHeight || 1);
    ta.scrollTop = ratio * (ta.scrollHeight - ta.clientHeight);
    setTimeout(()=>syncing=false,50);
  });
})();

// ========== 创建文本分享 ==========
document.getElementById('btn-create-text').onclick = async () => {
  const btn = document.getElementById('btn-create-text');
  const result = document.getElementById('text-result');
  const content = ta.value;
  if(!content.trim()){ alert('内容不能为空'); return; }
  btn.disabled = true; btn.textContent = '生成中...';
  try {
    const r = await fetch(API.text, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        content,
        title: document.getElementById('text-title').value,
        password: document.getElementById('text-password').value || undefined,
        expireMinutes: Number(document.getElementById('text-expire').value) || undefined,
        customSuffix: document.getElementById('text-suffix').value || undefined,
        maxViews: Number(document.getElementById('text-views').value) || undefined
      })
    });
    const data = await r.json();
    if(!r.ok) throw new Error(data.error || '失败');
    const url = location.origin + data.url;
    result.classList.add('show');
    result.innerHTML = '<div style="text-align:center;font-size:14px;color:#28a745;margin-bottom:6px">✅ 分享已创建，记住你的分享号！</div>'+
      '<div class="share-code-display">'+data.id+'</div>'+
      '<div style="text-align:center;font-size:12px;color:#888;margin-bottom:10px">凭此分享号在主页输入即可提取</div>'+
      '<div style="text-align:center;display:flex;gap:8px;justify-content:center;flex-wrap:wrap">'+
        '<button onclick="navigator.clipboard.writeText(\\''+data.id+'\\').then(()=>this.textContent=\\'已复制分享号\\')">复制分享号</button>'+
        '<a href="'+url+'" target="_blank"><button>打开链接</button></a>'+
      '</div>';
  } catch(e) {
    alert('错误: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = '生成分享号';
  }
};

// ========== 文件上传 ==========
let selectedFiles = [];
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileListEl = document.getElementById('file-list');

function fileIcon(type, name){
  if(type.startsWith('image/')) return '🖼️';
  if(type.startsWith('video/')) return '🎬';
  if(type.startsWith('audio/')) return '🎵';
  if(type.includes('pdf')) return '📕';
  if(/zip|rar|7z|tar|gz/.test(name)) return '🗜️';
  if(/doc|docx/.test(name)) return '📘';
  if(/xls|xlsx|csv/.test(name)) return '📗';
  if(/ppt|pptx/.test(name)) return '📙';
  return '📄';
}

function renderFileList(){
  fileListEl.innerHTML = '';
  selectedFiles.forEach((f, i) => {
    const div = document.createElement('div');
    div.className = 'file-item';
    div.innerHTML = '<span class="file-icon">'+fileIcon(f.type,f.name)+'</span>'+
      '<span class="file-name">'+f.name+'</span>'+
      '<span class="file-size">'+(f.size/1024/1024).toFixed(2)+'MB</span>'+
      '<span class="file-progress"><div class="bar" id="prog-'+i+'"></div></span>'+
      '<span class="file-speed" id="speed-'+i+'"></span>'+
      '<button class="file-cancel" data-i="'+i+'">×</button>';
    fileListEl.appendChild(div);
  });
  fileListEl.querySelectorAll('.file-cancel').forEach(b => {
    b.onclick = () => { selectedFiles.splice(Number(b.dataset.i),1); renderFileList(); };
  });
}

function addFiles(files){
  for(const f of files){
    if(f.size > 98*1024*1024){ alert('文件 '+f.name+' 超过 98MB'); continue; }
    selectedFiles.push(f);
  }
  renderFileList();
}

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('drag'); addFiles(e.dataTransfer.files); });
fileInput.addEventListener('change', e => addFiles(e.target.files));

document.getElementById('btn-create-file').onclick = async () => {
  if(!selectedFiles.length){ alert('请先选择文件'); return; }
  const btn = document.getElementById('btn-create-file');
  const result = document.getElementById('file-result');
  btn.disabled = true; btn.textContent = '上传中...';

  // 1. 创建元数据
  let shareId;
  try {
    const r = await fetch(API.file, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        title: document.getElementById('file-title').value,
        password: document.getElementById('file-password').value || undefined,
        expireMinutes: Number(document.getElementById('file-expire').value) || undefined,
        customSuffix: document.getElementById('file-suffix').value || undefined,
        maxViews: Number(document.getElementById('file-views').value) || undefined,
        maxDownloads: Number(document.getElementById('file-downloads').value) || undefined,
        files: selectedFiles.map(f => ({name:f.name, size:f.size, type:f.type}))
      })
    });
    const data = await r.json();
    if(!r.ok) throw new Error(data.error || '创建失败');
    shareId = data.id;
  } catch(e) {
    alert('错误: ' + e.message);
    btn.disabled = false; btn.textContent = '开始上传并生成链接';
    return;
  }

  // 2. 逐个上传(支持取消)
  let allOk = true;
  let uploadCancelled = false;
  const activeXhrs = [];
  const cancelBtn = document.getElementById('btn-cancel-upload');
  cancelBtn.style.display = 'inline-block';
  cancelBtn.onclick = () => {
    if(confirm('确认取消上传？已上传的文件将被丢弃。')){
      uploadCancelled = true;
      activeXhrs.forEach(x => { try{ x.abort(); }catch(e){} });
    }
  };

  for(let i=0;i<selectedFiles.length;i++){
    if(uploadCancelled) break;
    const f = selectedFiles[i];
    const bar = document.getElementById('prog-'+i);
    const speedEl = document.getElementById('speed-'+i);
    try {
      await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        activeXhrs.push(xhr);
        xhr.open('PUT', API.upload(shareId, i));
        let speedTimer = null;
        xhr.upload.onprogress = e => {
          if(e.lengthComputable){
            const pct = (e.loaded/e.total*100).toFixed(0);
            if(bar) bar.style.width = pct+'%';
          }
        };
        // 速度计算
        let lastLoaded=0, lastTime=Date.now();
        speedTimer = setInterval(()=>{
          const now=Date.now(); const dt=(now-lastTime)/1000;
          if(dt>0 && speedEl && bar){
            const loaded = parseFloat(bar.style.width||'0')/100 * f.size;
            const speed = (loaded-lastLoaded)/dt/1024;
            if(speed>0) speedEl.textContent = speed.toFixed(0)+'KB/s';
            lastLoaded=loaded; lastTime=now;
          }
        },500);
        xhr.onload = () => { clearInterval(speedTimer); xhr.status===200 ? resolve() : reject(new Error('HTTP '+xhr.status)); };
        xhr.onerror = () => { clearInterval(speedTimer); reject(new Error('网络错误')); };
        xhr.onabort = () => { clearInterval(speedTimer); reject(new Error('已取消')); };
        xhr.send(f);
      });
      if(bar) bar.style.width='100%';
      if(speedEl) speedEl.textContent = '完成';
    } catch(e) {
      if(uploadCancelled || e.message === '已取消'){
        allOk = false;
        break;
      }
      allOk = false;
      alert('文件 '+f.name+' 上传失败: '+e.message);
      break;
    }
  }

  cancelBtn.style.display = 'none';
  cancelBtn.onclick = null;

  if(uploadCancelled){
    result.classList.add('show');
    result.innerHTML = '<div style="text-align:center;color:#f59e0b">⚠️ 上传已取消</div>';
    // 清理已创建的分享元数据(异步,不阻塞)
    fetch(API.file.replace('/file','/share/'+shareId+'/delete'), {method:'POST', headers:{'Authorization':'Bearer '+(localStorage.getItem('admin_token')||'')}}).catch(()=>{});
  } else if(allOk){
    const url = location.origin + '${P('/')}' + shareId;
    result.classList.add('show');
    result.innerHTML = '<div style="text-align:center;font-size:14px;color:#28a745;margin-bottom:6px">✅ 上传完成，记住你的分享号！</div>'+
      '<div class="share-code-display">'+shareId+'</div>'+
      '<div style="text-align:center;font-size:12px;color:#888;margin-bottom:10px">凭此分享号在主页输入即可提取下载</div>'+
      '<div style="text-align:center;display:flex;gap:8px;justify-content:center;flex-wrap:wrap">'+
        '<button onclick="navigator.clipboard.writeText(\\''+shareId+'\\').then(()=>this.textContent=\\'已复制分享号\\')">复制分享号</button>'+
        '<a href="'+url+'" target="_blank"><button>打开链接</button></a>'+
      '</div>';
  }
  btn.disabled = false; btn.textContent = '开始上传并生成链接';
};
`;

/** 查看分享页 */
function viewPage(share) {
  const isText = share.type === 'text';
  return `<!DOCTYPE html><html lang="zh-CN"><head>
${COMMON_HEAD}
<title>${share.title ? share.title + ' - ' : ''}分享</title>
<style>${VIEW_CSS}</style>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/highlight.js@11/styles/github.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16/dist/katex.min.css">
</head><body>
<div class="view-container">
  <!-- 快速提取其他分享 -->
  <div class="mini-extract">
    <input id="mini-extract-code" type="text" placeholder="输入分享号提取其他分享" maxlength="32" autocomplete="off">
    <button id="mini-extract-btn">提取</button>
    <a href="${P('/')}" class="back-home">← 回主页</a>
    <button class="theme-toggle" id="theme-toggle" title="切换主题" style="margin-left:auto">🌙</button>
  </div>
  <header class="view-header">
    <h1 id="share-title">加载中...</h1>
    <div class="meta" id="share-meta"></div>
    <div class="share-code-badge" id="share-code-badge"></div>
  </header>

  <!-- 密码输入 -->
  <div id="pwd-box" class="pwd-box" style="display:none">
    <p>🔒 此分享需要密码</p>
    <input id="pwd-input" type="password" placeholder="请输入密码">
    <button id="pwd-submit">确认</button>
  </div>

  <!-- 文本内容 -->
  <div id="text-view" style="display:none">
    <div class="md-toolbar">
      <button id="toggle-edit" class="btn-sm" style="display:none">编辑(管理员)</button>
      <button id="copy-text" class="btn-sm">复制全文</button>
    </div>
    <div id="md-content" class="markdown-body"></div>
    <textarea id="md-editor" style="display:none" class="md-editor"></textarea>
  </div>

  <!-- 文件列表 -->
  <div id="file-view" style="display:none">
    <div id="files-container"></div>
    <div id="preview-modal" class="modal" style="display:none">
      <div class="modal-content">
        <span class="modal-close" id="modal-close">×</span>
        <div id="modal-body"></div>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/highlight.js@11/lib/highlight.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/katex@0.16/dist/katex.min.js"></script>
<script>
const SHARE_ID = '${share.id}';
const API_BASE = '${P('/api/share')}/' + SHARE_ID;
const FILE_BASE = '${P('/api/share')}/' + SHARE_ID + '/file/';
</script>
<script>${VIEW_JS}</script>
</body></html>`;
}

const VIEW_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:linear-gradient(135deg,#eef2ff 0%,#f5f7fa 50%,#f0f9ff 100%);color:#1e293b;line-height:1.7;min-height:100vh;transition:background .4s ease,color .3s ease}
.view-container{max-width:900px;margin:0 auto;padding:24px 20px}
.mini-extract{display:flex;gap:10px;align-items:center;margin-bottom:18px;background:#fff;padding:12px 14px;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);border:1px solid rgba(255,255,255,.8);transition:all .3s ease}
.mini-extract input{flex:1;padding:9px 13px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:14px;outline:none;transition:all .25s ease;background:#f8fafc}
.mini-extract input:focus{border-color:#007bff;background:#fff;box-shadow:0 0 0 3px rgba(0,123,255,.1)}
.mini-extract button{padding:8px 18px;background:#28a745;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:13px}
.mini-extract button:hover{background:#218838}
.back-home{color:#007bff;text-decoration:none;font-size:13px;white-space:nowrap}
.share-code-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:#f0f7ff;border:1px solid #c5d8f0;border-radius:20px;font-size:13px;color:#007bff;font-family:ui-monospace,monospace;letter-spacing:2px}
.view-header{margin-bottom:20px}
.view-header h1{font-size:22px;margin-bottom:6px;word-break:break-word}
.meta{font-size:13px;color:#888}
.meta span{margin-right:14px}
.pwd-box{background:#fff;padding:28px;border-radius:14px;text-align:center;box-shadow:0 4px 20px rgba(0,0,0,.08);border:1px solid #e2e8f0;max-width:380px;margin:40px auto}
.pwd-box p{margin-bottom:14px;font-size:15px;color:#475569;font-weight:500}
.pwd-box input{padding:11px 15px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:14px;width:240px;margin-right:8px;outline:none;transition:all .25s ease;background:#f8fafc}
.pwd-box input:focus{border-color:#007bff;background:#fff;box-shadow:0 0 0 4px rgba(0,123,255,.1)}
.pwd-box button{padding:11px 22px;background:linear-gradient(135deg,#007bff,#4f46e5);color:#fff;border:none;border-radius:10px;cursor:pointer;font-size:14px;font-weight:600;transition:all .25s ease;box-shadow:0 2px 8px rgba(0,123,255,.3)}
.pwd-box button:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,123,255,.45)}
.md-toolbar{margin-bottom:10px;display:flex;gap:8px}
.btn-sm{padding:6px 14px;background:#fff;border:1px solid #ddd;border-radius:6px;cursor:pointer;font-size:13px}
.btn-sm:hover{background:#f3f4f6}
#md-content{background:#fff;padding:32px;border-radius:14px;box-shadow:0 4px 20px rgba(0,0,0,.06);min-height:200px;border:1px solid rgba(255,255,255,.8);transition:all .3s ease}
.md-editor{width:100%;min-height:400px;padding:16px;border:1px solid #ddd;border-radius:12px;font-family:ui-monospace,monospace;font-size:14px;resize:vertical}
/* Markdown */
.markdown-body h1,.markdown-body h2,.markdown-body h3{margin:18px 0 10px;font-weight:600}
.markdown-body h1{font-size:1.7em;border-bottom:1px solid #eee;padding-bottom:8px}
.markdown-body h2{font-size:1.4em}
.markdown-body h3{font-size:1.15em}
.markdown-body p{margin:10px 0}
.markdown-body ul,.markdown-body ol{padding-left:26px;margin:10px 0}
.markdown-body li{margin:5px 0}
.markdown-body blockquote{border-left:4px solid #dfe2e5;padding:6px 18px;color:#6a737d;background:#f6f8fa;margin:10px 0;border-radius:0 6px 6px 0}
.markdown-body code{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:0.9em;font-family:ui-monospace,monospace}
.markdown-body pre{background:#f6f8fa;padding:14px;border-radius:8px;overflow-x:auto;margin:10px 0}
.markdown-body pre code{background:none;padding:0}
.markdown-body table{border-collapse:collapse;margin:12px 0;width:100%}
.markdown-body th,.markdown-body td{border:1px solid #dfe2e5;padding:8px 14px;text-align:left}
.markdown-body th{background:#f3f4f6;font-weight:600}
.markdown-body tr:nth-child(even){background:#fafbfc}
.markdown-body img{max-width:100%;border-radius:6px}
.markdown-body a{color:#007bff}
.markdown-body hr{border:none;border-top:1px solid #eee;margin:18px 0}
.katex-block{overflow-x:auto;padding:8px 0;text-align:center}
/* 文件 */
.file-card{display:flex;align-items:center;gap:14px;padding:14px 18px;background:#fff;border-radius:12px;margin-bottom:10px;box-shadow:0 2px 10px rgba(0,0,0,.05);border:1px solid #e2e8f0;transition:all .25s ease}
.file-card:hover{transform:translateX(3px);box-shadow:0 4px 16px rgba(0,0,0,.1);border-color:#cbd5e1}
.file-card .ficon{font-size:26px;width:44px;height:44px;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#f1f5f9,#e2e8f0);border-radius:10px;flex-shrink:0}
.file-card .finfo{flex:1;min-width:0}
.file-card .fname{font-size:14px;font-weight:600;color:#1e293b;word-break:break-all}
.file-card .fsize{font-size:12px;color:#94a3b8;margin-top:3px}
.file-card .fbtns{display:flex;gap:8px;flex-shrink:0}
.file-card button{padding:7px 14px;border:1.5px solid #e2e8f0;background:#fff;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;color:#475569;transition:all .2s ease}
.file-card button:hover{background:#f8fafc;border-color:#cbd5e1;color:#1e293b}
.file-card button.primary{background:linear-gradient(135deg,#007bff,#4f46e5);color:#fff;border-color:transparent;box-shadow:0 2px 8px rgba(0,123,255,.3)}
.file-card button.primary:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,123,255,.4)}
.btn-download{display:inline-block;padding:7px 16px;background:linear-gradient(135deg,#007bff,#4f46e5);color:#fff;border:1px solid transparent;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;text-decoration:none;line-height:1.4;transition:all .2s ease;box-shadow:0 2px 8px rgba(0,123,255,.3)}
.btn-download:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,123,255,.45)}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;z-index:999;padding:20px}
.modal-content{position:relative;max-width:95vw;max-height:95vh;background:#fff;border-radius:12px;overflow:hidden}
.modal-close{position:absolute;top:10px;right:14px;font-size:28px;color:#fff;cursor:pointer;z-index:10;text-shadow:0 0 4px #000}
#modal-body{max-width:95vw;max-height:95vh;overflow:auto}
#modal-body img,#modal-body video{max-width:95vw;max-height:90vh;display:block}
#modal-body audio{width:400px;max-width:90vw;padding:20px}
/* ===== 暗黑模式 ===== */
[data-theme="dark"] body{background:#0f1117;color:#e4e6eb}
[data-theme="dark"] .mini-extract,[data-theme="dark"] .pwd-box,[data-theme="dark"] #md-content{background:#1a1d27;border-color:#2d3139;box-shadow:0 2px 12px rgba(0,0,0,.3)}
[data-theme="dark"] .mini-extract input{background:#0f1117;color:#e4e6eb;border-color:#3a3f4b}
[data-theme="dark"] .pwd-box input{background:#0f1117;color:#e4e6eb;border-color:#3a3f4b}
[data-theme="dark"] .file-card{background:#1a1d27;box-shadow:0 1px 6px rgba(0,0,0,.3)}
[data-theme="dark"] .file-card button{background:#252830;color:#e4e6eb;border-color:#3a3f4b}
[data-theme="dark"] .btn-download{background:#4d9fff;border-color:#4d9fff}
[data-theme="dark"] .share-code-badge{background:#1a2535;border-color:#3a5a8a;color:#4d9fff}
[data-theme="dark"] .meta{color:#a0a3ab}
[data-theme="dark"] .md-editor{background:#0f1117;color:#e4e6eb;border-color:#3a3f4b}
[data-theme="dark"] .btn-sm{background:#252830;color:#e4e6eb;border-color:#3a3f4b}
[data-theme="dark"] .markdown-body{color:#e4e6eb}
[data-theme="dark"] .markdown-body h1,[data-theme="dark"] .markdown-body h2,[data-theme="dark"] .markdown-body h3{color:#e4e6eb}
[data-theme="dark"] .markdown-body h1{border-color:#2d3139}
[data-theme="dark"] .markdown-body blockquote{background:#151820;border-color:#3a3f4b;color:#a0a3ab}
[data-theme="dark"] .markdown-body code{background:#252830}
[data-theme="dark"] .markdown-body pre{background:#0d1117}
[data-theme="dark"] .markdown-body pre code{background:none}
[data-theme="dark"] .markdown-body th{background:#252830}
[data-theme="dark"] .markdown-body th,[data-theme="dark"] .markdown-body td{border-color:#2d3139}
[data-theme="dark"] .markdown-body tr:nth-child(even){background:#151820}
[data-theme="dark"] .markdown-body hr{border-color:#2d3139}
[data-theme="dark"] .back-home{color:#4d9fff}
[data-theme="dark"] .modal-content{background:#1a1d27}
`;

const VIEW_JS = `
let currentPassword = null;

function fmtTime(ts){ if(!ts) return '永久'; const d=new Date(ts); return d.toLocaleString('zh-CN'); }
function fmtSize(b){ if(b<1024)return b+'B'; if(b<1048576)return (b/1024).toFixed(1)+'KB'; return (b/1048576).toFixed(2)+'MB'; }

// 迷你提取框
document.getElementById('mini-extract-btn').onclick = () => {
  const code = document.getElementById('mini-extract-code').value.trim();
  if(code) location.href = '${P('/')}' + encodeURIComponent(code);
};
document.getElementById('mini-extract-code').addEventListener('keydown', e => {
  if(e.key === 'Enter') document.getElementById('mini-extract-btn').click();
});
// 主题切换
(function(){
  const btn = document.getElementById('theme-toggle');
  if(!btn) return;
  function updateIcon(){ btn.textContent = document.documentElement.getAttribute('data-theme')==='dark' ? '☀️' : '🌙'; }
  updateIcon();
  btn.onclick = () => {
    const cur = document.documentElement.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateIcon();
  };
})();

async function loadShare(pwd){
  const url = API_BASE + (pwd ? '?password='+encodeURIComponent(pwd) : '');
  const r = await fetch(url);
  const data = await r.json();
  if(r.status===401 || data.needPassword){
    document.getElementById('pwd-box').style.display='block';
    document.getElementById('share-title').textContent = '🔒 密码保护的分享';
    return;
  }
  if(!r.ok){ alert(data.error||'加载失败'); return; }
  currentPassword = pwd;
  renderShare(data);
}

function renderShare(s){
  document.getElementById('pwd-box').style.display='none';
  document.getElementById('share-title').textContent = s.title || (s.type==='text'?'📝 文本分享':'📁 文件分享');
  const meta = document.getElementById('share-meta');
  meta.innerHTML = '<span>创建: '+fmtTime(s.createdAt)+'</span>'+
    '<span>过期: '+fmtTime(s.expireAt)+'</span>'+
    '<span>浏览: '+(s.views||0)+(s.maxViews?'/'+s.maxViews:'')+'</span>'+
    (s.hasPassword?'<span>🔒 已加密</span>':'');
  // 显示分享号徽章
  document.getElementById('share-code-badge').textContent = '分享号: ' + s.id;
  document.getElementById('share-code-badge').style.display = 'inline-block';

  if(s.type==='text'){
    document.getElementById('text-view').style.display='block';
    document.getElementById('md-content').innerHTML = renderMd(s.content);
    document.getElementById('md-editor').value = s.content;
    document.getElementById('copy-text').onclick = () => {
      navigator.clipboard.writeText(s.content).then(()=>alert('已复制'));
    };
    // 管理员编辑按钮(本地有 token 才显示)
    const tok = localStorage.getItem('admin_token');
    if(tok){
      const btn = document.getElementById('toggle-edit');
      btn.style.display='inline-block';
      btn.onclick = () => {
        const ed = document.getElementById('md-editor');
        const prev = document.getElementById('md-content');
        if(ed.style.display==='none'){
          ed.style.display='block'; prev.style.display='none'; btn.textContent='保存';
        } else {
          fetch(API_BASE+'/edit', {method:'PUT', headers:{'Content-Type':'application/json','Authorization':'Bearer '+tok}, body:JSON.stringify({content:ed.value})})
            .then(r=>r.json()).then(d=>{ if(d.ok){ prev.innerHTML=renderMd(ed.value); s.content=ed.value; alert('已保存'); } else alert(d.error); });
          ed.style.display='none'; prev.style.display='block'; btn.textContent='编辑(管理员)';
        }
      };
    }
  } else {
    document.getElementById('file-view').style.display='block';
    renderFiles(s);
  }
}

function renderMd(text){
  marked.setOptions({breaks:true,gfm:true,highlight:(c,l)=>{try{return hljs.highlightAuto(c,[l]).value}catch(e){return c}}});
  const blocks=[];
  text = text.replace(/\\$\\$([\\s\\S]+?)\\$\\$/g,(m,p)=>{blocks.push({t:'b',s:p});return '@@B'+(blocks.length-1)+'@@';});
  text = text.replace(/\\$([^\\n$]+?)\\$/g,(m,p)=>{blocks.push({t:'i',s:p});return '@@I'+(blocks.length-1)+'@@';});
  let h = marked.parse(text);
  h = h.replace(/@@B(\\d+)@@/g,(m,i)=>{try{return '<div class="katex-block">'+katex.renderToString(blocks[i].s,{displayMode:true,throwOnError:false})+'</div>'}catch(e){return '<pre>'+blocks[i].s+'</pre>'}});
  h = h.replace(/@@I(\\d+)@@/g,(m,i)=>{try{return katex.renderToString(blocks[i].s,{displayMode:false,throwOnError:false})}catch(e){return '$'+blocks[i].s+'$'}});
  return h;
}

function ficon(type,name){
  if(type.startsWith('image/'))return '🖼️';
  if(type.startsWith('video/'))return '🎬';
  if(type.startsWith('audio/'))return '🎵';
  if(type.includes('pdf'))return '📕';
  return '📄';
}

function renderFiles(s){
  const c = document.getElementById('files-container');
  c.innerHTML = '';
  if(s.maxDownloads) c.innerHTML += '<p style="color:#888;font-size:13px;margin-bottom:8px">下载次数限制: '+(s.downloads||0)+'/'+s.maxDownloads+'</p>';
  s.files.forEach(f => {
    const pwdQ = currentPassword ? '?password='+encodeURIComponent(currentPassword) : '';
    const url = FILE_BASE + f.index + pwdQ;
    const dlUrl = FILE_BASE + f.index + (currentPassword?'?password='+encodeURIComponent(currentPassword)+'&':'?')+'download=1';
    const card = document.createElement('div');
    card.className='file-card';
    card.innerHTML = '<div class="ficon">'+ficon(f.type,f.name)+'</div>'+
      '<div class="finfo"><div class="fname">'+f.name+'</div><div class="fsize">'+fmtSize(f.size)+(f.type?' · '+f.type:'')+'</div></div>'+
      '<div class="fbtns">'+
        (/^(image|video|audio|application\\/pdf)/.test(f.type) ? '<button onclick="previewFile(\\''+url+'\\',\\''+f.type+'\\',\\''+f.name.replace(/'/g,"")+'\\')">预览</button>' : '')+
        '<a class="btn-download" href="'+dlUrl+'">下载</a>'+
      '</div>';
    c.appendChild(card);
  });
}

window.previewFile = function(url, type, name){
  const modal = document.getElementById('preview-modal');
  const body = document.getElementById('modal-body');
  body.innerHTML = '';
  if(type.startsWith('image/')){
    body.innerHTML = '<img src="'+url+'" alt="'+name+'">';
  } else if(type.startsWith('video/')){
    body.innerHTML = '<video src="'+url+'" controls autoplay></video>';
  } else if(type.startsWith('audio/')){
    body.innerHTML = '<audio src="'+url+'" controls autoplay></audio>';
  } else if(type==='application/pdf'){
    body.innerHTML = '<iframe src="'+url+'" style="width:90vw;height:90vh;border:none"></iframe>';
  }
  modal.style.display='flex';
};
document.getElementById('modal-close').onclick = () => document.getElementById('preview-modal').style.display='none';
document.getElementById('preview-modal').onclick = e => { if(e.target.id==='preview-modal') e.target.style.display='none'; };

document.getElementById('pwd-submit').onclick = () => {
  const pwd = document.getElementById('pwd-input').value;
  if(pwd) loadShare(pwd);
};
document.getElementById('pwd-input').addEventListener('keydown', e => { if(e.key==='Enter') document.getElementById('pwd-submit').click(); });

loadShare();
`;

/** 管理员后台页 */
function adminPage() {
  return `<!DOCTYPE html><html lang="zh-CN"><head>
${COMMON_HEAD}
<title>管理后台</title>
<style>${ADMIN_CSS}</style>
</head><body>
<div class="admin-container">
  <header class="admin-top">
    <h1>⚙️ 管理后台</h1>
    <div style="display:flex;align-items:center;gap:12px">
      <a href="${P('/')}" class="back">← 返回首页</a>
      <button class="theme-toggle" id="theme-toggle" title="切换主题">🌙</button>
    </div>
  </header>

  <!-- 登录 -->
  <div id="login-box" class="login-box">
    <h2>管理员登录</h2>
    <input id="login-pwd" type="password" placeholder="请输入管理员密码">
    <button id="login-btn">登录</button>
    <p id="login-err" class="err"></p>
  </div>

  <!-- 主面板 -->
  <div id="admin-main" style="display:none">
    <!-- 统计卡片 -->
    <div class="stats-grid" id="stats-grid"></div>

    <!-- 配置开关 -->
    <div class="card">
      <h3>上传控制</h3>
      <div class="switch-row">
        <label>文本分享功能</label>
        <label class="switch"><input type="checkbox" id="cfg-text"><span class="slider"></span></label>
      </div>
      <div class="switch-row">
        <label>文件分享功能</label>
        <label class="switch"><input type="checkbox" id="cfg-file"><span class="slider"></span></label>
      </div>
      <div class="switch-row">
        <label>修改管理员密码</label>
        <div style="display:flex;gap:6px">
          <input id="new-admin-pwd" type="password" placeholder="新密码" style="padding:6px 10px;border:1px solid #ddd;border-radius:6px">
          <button id="btn-change-pwd" class="btn-sm">修改</button>
        </div>
      </div>
      <button id="btn-save-cfg" class="btn-primary">保存配置</button>
      <button id="btn-logout" class="btn-danger">退出登录</button>
    </div>

    <!-- 分享列表 -->
    <div class="card">
      <div class="card-head">
        <h3>分享列表</h3>
        <div class="filters">
          <button class="filter-btn active" data-filter="all">全部</button>
          <button class="filter-btn" data-filter="text">文本</button>
          <button class="filter-btn" data-filter="file">文件</button>
          <button id="btn-refresh" class="btn-sm">刷新</button>
        </div>
      </div>
      <div class="table-wrap">
        <table class="share-table">
          <thead><tr>
            <th>ID/标题</th><th>类型</th><th>大小</th><th>浏览</th>
            <th>密码</th><th>过期</th><th>创建时间</th><th>操作</th>
          </tr></thead>
          <tbody id="share-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- 编辑分享模态框 -->
  <div id="edit-modal" class="modal-overlay" style="display:none">
    <div class="modal-box">
      <div class="modal-header">
        <h3>编辑分享 <span id="edit-share-id" style="font-size:13px;color:#888"></span></h3>
        <span class="modal-close-btn" id="edit-modal-close">×</span>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label>分享号（修改后访问链接会变）</label>
          <input type="text" id="edit-shareid" placeholder="输入新分享号" maxlength="32">
        </div>
        <div class="form-group">
          <label>访问密码（留空=无密码）</label>
          <input type="text" id="edit-password" placeholder="输入新密码，留空移除密码">
        </div>
        <div class="form-group">
          <label>最大访问次数（0=不限）</label>
          <input type="number" id="edit-max-views" min="0" placeholder="0">
          <small style="color:#888">当前已访问: <span id="edit-current-views">0</span> 次</small>
        </div>
        <div class="form-group" id="edit-downloads-group">
          <label>最大下载次数（0=不限）</label>
          <input type="number" id="edit-max-downloads" min="0" placeholder="0">
          <small style="color:#888">当前已下载: <span id="edit-current-downloads">0</span> 次</small>
        </div>
      </div>
      <div class="modal-footer">
        <button id="edit-cancel" class="btn-sm">取消</button>
        <button id="edit-save" class="btn-primary">保存</button>
      </div>
    </div>
  </div>
</div>
<script>
const API = {
  login: '${P('/api/admin/login')}',
  logout: '${P('/api/admin/logout')}',
  shares: '${P('/api/admin/shares')}',
  config: '${P('/api/admin/config')}',
  stats: '${P('/api/admin/stats')}',
  share: id => '${P('/api/share')}/' + id,
};
const HOME = '${P('/')}';
</script>
<script>${ADMIN_JS}</script>
</body></html>`;
}

const ADMIN_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:linear-gradient(135deg,#eef2ff 0%,#f5f7fa 50%,#f0f9ff 100%);color:#1e293b;line-height:1.6;min-height:100vh;transition:background .4s ease,color .3s ease}
.admin-container{max-width:1200px;margin:0 auto;padding:20px}
.admin-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.admin-top h1{font-size:22px}
.back{color:#007bff;text-decoration:none;font-size:14px}
.login-box{max-width:360px;margin:60px auto;background:#fff;padding:30px;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);text-align:center}
.login-box h2{margin-bottom:16px;font-size:18px}
.login-box input{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;margin-bottom:12px}
.login-box button{width:100%;padding:10px;background:#007bff;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:15px}
.err{color:#ef4444;font-size:13px;margin-top:8px;min-height:18px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:20px}
.stat-card{background:linear-gradient(135deg,#fff 0%,#f8fafc 100%);padding:20px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.06);border:1px solid #e2e8f0;transition:all .25s ease}
.stat-card:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.1)}
.stat-card .label{font-size:13px;color:#64748b;margin-bottom:8px;font-weight:500}
.stat-card .value{font-size:26px;font-weight:700;background:linear-gradient(135deg,#007bff,#4f46e5);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.stat-card .sub{font-size:12px;color:#94a3b8;margin-top:6px}
.card{background:#fff;padding:22px;border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.06);margin-bottom:18px;border:1px solid #e2e8f0;transition:all .3s ease}
.card h3{margin-bottom:16px;font-size:17px;font-weight:700;color:#1e293b}
.card-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:14px}
.card-head h3{margin:0}
.filters{display:flex;gap:6px;align-items:center}
.filter-btn{padding:6px 14px;border:1px solid #ddd;background:#fff;border-radius:6px;cursor:pointer;font-size:13px}
.filter-btn.active{background:#007bff;color:#fff;border-color:#007bff}
.switch-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #f0f0f0}
.switch{position:relative;display:inline-block;width:44px;height:24px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:#ccc;border-radius:24px;transition:.3s}
.slider:before{content:"";position:absolute;height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.3s}
.switch input:checked+.slider{background:#007bff}
.switch input:checked+.slider:before{transform:translateX(20px)}
.btn-primary{padding:8px 20px;background:#007bff;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px;margin-top:12px;margin-right:8px}
.btn-danger{padding:8px 20px;background:#ef4444;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px}
.btn-sm{padding:5px 12px;border:1px solid #ddd;background:#fff;border-radius:6px;cursor:pointer;font-size:12px}
.btn-sm.danger{color:#ef4444;border-color:#fecaca}
.table-wrap{overflow-x:auto;border-radius:10px;border:1px solid #e2e8f0}
.share-table{width:100%;border-collapse:collapse;font-size:13px}
.share-table th,.share-table td{padding:12px 10px;border-bottom:1px solid #f1f5f9;text-align:left;vertical-align:top}
.share-table th{background:linear-gradient(180deg,#f8fafc,#f1f5f9);font-weight:600;color:#475569;position:sticky;top:0;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.share-table tr:hover{background:#f8fafc}
.share-table .id-cell{max-width:200px;word-break:break-all}
.share-table .id-cell a{color:#007bff;text-decoration:none;font-weight:500}
.share-table .id-cell a:hover{text-decoration:underline}
.share-table .tag{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.tag.text{background:#dbeafe;color:#1e40af}
.tag.file{background:#fef3c7;color:#92400e}
.tag.locked{background:#fee2e2;color:#991b1b}
.tag.unlocked{background:#dcfce7;color:#166534}
.actions{display:flex;flex-wrap:wrap;gap:5px}
.btn-sm{padding:6px 12px;border:1.5px solid #e2e8f0;background:#fff;border-radius:8px;cursor:pointer;font-size:12px;font-weight:500;color:#475569;transition:all .2s ease}
.btn-sm:hover{background:#f8fafc;border-color:#cbd5e1;color:#1e293b}
.btn-sm.danger{color:#ef4444;border-color:#fecaca}
.btn-sm.danger:hover{background:#fef2f2;border-color:#fca5a5}
.empty{text-align:center;padding:30px;color:#94a3b8}
/* ===== 编辑模态框 ===== */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:1000;padding:20px}
.modal-box{background:#fff;border-radius:12px;width:100%;max-width:460px;box-shadow:0 8px 32px rgba(0,0,0,.2);overflow:hidden}
.modal-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid #eee}
.modal-header h3{font-size:16px;margin:0}
.modal-close-btn{font-size:24px;cursor:pointer;color:#999;line-height:1}
.modal-close-btn:hover{color:#333}
.modal-body{padding:20px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:13px;color:#555;margin-bottom:6px;font-weight:500}
.form-group input{width:100%;padding:9px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px;outline:none}
.form-group input:focus{border-color:#007bff;box-shadow:0 0 0 3px rgba(0,123,255,.1)}
.form-group small{display:block;margin-top:4px}
.modal-footer{display:flex;justify-content:flex-end;gap:8px;padding:14px 20px;border-top:1px solid #eee;background:#f9fafb}
/* ===== 暗黑模式 ===== */
[data-theme="dark"] body{background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%);color:#e2e8f0}
[data-theme="dark"] .card,[data-theme="dark"] .stat-card,[data-theme="dark"] .login-box{background:linear-gradient(135deg,#1e293b 0%,#1a1d27 100%);box-shadow:0 2px 12px rgba(0,0,0,.4);border-color:#334155}
[data-theme="dark"] .login-box input{background:#0f172a;color:#e2e8f0;border-color:#334155}
[data-theme="dark"] .stat-card .label{color:#94a3b8}
[data-theme="dark"] .stat-card .value{background:linear-gradient(135deg,#4d9fff,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
[data-theme="dark"] .stat-card .sub{color:#64748b}
[data-theme="dark"] .switch-row{border-color:#334155}
[data-theme="dark"] .filter-btn{background:#1e293b;color:#94a3b8;border-color:#334155}
[data-theme="dark"] .filter-btn.active{background:linear-gradient(135deg,#4d9fff,#6366f1);border-color:transparent;color:#fff}
[data-theme="dark"] .share-table th{background:linear-gradient(180deg,#1e293b,#0f172a);color:#94a3b8}
[data-theme="dark"] .share-table th,[data-theme="dark"] .share-table td{border-color:#334155;color:#e2e8f0}
[data-theme="dark"] .share-table tr:hover{background:#1e293b}
[data-theme="dark"] .btn-sm{background:#1e293b;color:#e2e8f0;border-color:#334155}
[data-theme="dark"] .btn-sm.danger{color:#f87171;border-color:#7f1d1d}
[data-theme="dark"] input[type="text"],[data-theme="dark"] input[type="password"],[data-theme="dark"] input[type="number"]{background:#0f172a;color:#e2e8f0;border-color:#334155}
[data-theme="dark"] .back{color:#4d9fff}
[data-theme="dark"] .err{color:#f87171}
[data-theme="dark"] .modal-box{background:linear-gradient(135deg,#1e293b,#0f172a);color:#e2e8f0;border:1px solid #334155}
[data-theme="dark"] .modal-header{border-color:#334155}
[data-theme="dark"] .modal-footer{border-color:#334155;background:#0f172a}
[data-theme="dark"] .form-group label{color:#94a3b8}
[data-theme="dark"] .table-wrap{border-color:#334155}
[data-theme="dark"] .tag.text{background:#1e3a5f;color:#60a5fa}
[data-theme="dark"] .tag.file{background:#422006;color:#fbbf24}
[data-theme="dark"] .tag.locked{background:#450a0a;color:#f87171}
[data-theme="dark"] .tag.unlocked{background:#052e16;color:#4ade80}
[data-theme="dark"] .admin-top h1{background:linear-gradient(135deg,#4d9fff,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
`;

const ADMIN_JS = `
let token = localStorage.getItem('admin_token') || '';
let currentFilter = 'all';
let allShares = [];

function authHeaders(extra={}){ return Object.assign({'Content-Type':'application/json','Authorization':'Bearer '+token}, extra); }

// 主题切换
(function(){
  const btn = document.getElementById('theme-toggle');
  if(!btn) return;
  function updateIcon(){ btn.textContent = document.documentElement.getAttribute('data-theme')==='dark' ? '☀️' : '🌙'; }
  updateIcon();
  btn.onclick = () => {
    const cur = document.documentElement.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateIcon();
  };
})();

// 登录
document.getElementById('login-btn').onclick = async () => {
  const pwd = document.getElementById('login-pwd').value;
  const err = document.getElementById('login-err');
  err.textContent = '';
  try {
    const r = await fetch(API.login, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pwd})});
    const d = await r.json();
    if(!r.ok) throw new Error(d.error||'登录失败');
    token = d.token;
    localStorage.setItem('admin_token', token);
    enterAdmin();
  } catch(e) { err.textContent = e.message; }
};
document.getElementById('login-pwd').addEventListener('keydown', e => { if(e.key==='Enter') document.getElementById('login-btn').click(); });

document.getElementById('btn-logout').onclick = async () => {
  await fetch(API.logout, {method:'POST', headers:authHeaders()});
  localStorage.removeItem('admin_token');
  token = '';
  location.reload();
};

async function enterAdmin(){
  document.getElementById('login-box').style.display='none';
  document.getElementById('admin-main').style.display='block';
  await loadConfig();
  await loadStats();
  await loadShares();
}

async function loadConfig(){
  const r = await fetch(API.config, {headers:{'Authorization':'Bearer '+token}});
  const d = await r.json();
  document.getElementById('cfg-text').checked = d.textUploadEnabled;
  document.getElementById('cfg-file').checked = d.fileUploadEnabled;
}

document.getElementById('btn-save-cfg').onclick = async () => {
  const r = await fetch(API.config, {method:'PUT', headers:authHeaders(), body:JSON.stringify({
    textUploadEnabled: document.getElementById('cfg-text').checked,
    fileUploadEnabled: document.getElementById('cfg-file').checked
  })});
  const d = await r.json();
  alert(d.ok?'配置已保存':(d.error||'失败'));
};

document.getElementById('btn-change-pwd').onclick = async () => {
  const pwd = document.getElementById('new-admin-pwd').value;
  if(!pwd){ alert('请输入新密码'); return; }
  const r = await fetch(API.config, {method:'PUT', headers:authHeaders(), body:JSON.stringify({newAdminPassword:pwd})});
  const d = await r.json();
  if(d.ok){ alert('管理员密码已修改,请重新登录'); localStorage.removeItem('admin_token'); location.reload(); }
  else alert(d.error||'失败');
};

async function loadStats(){
  const r = await fetch(API.stats, {headers:{'Authorization':'Bearer '+token}});
  const d = await r.json();
  document.getElementById('stats-grid').innerHTML =
    '<div class="stat-card"><div class="label">分享总数</div><div class="value">'+d.totalShares+'</div></div>'+
    '<div class="stat-card"><div class="label">文件总数</div><div class="value">'+d.totalFiles+'</div></div>'+
    '<div class="stat-card"><div class="label">已用存储</div><div class="value">'+d.totalBytesHuman+'</div><div class="sub">使用率 '+d.usagePercent+'%</div></div>'+
    '<div class="stat-card"><div class="label">存储配额(参考)</div><div class="value">10GB</div><div class="sub">R2 免费额度</div></div>';
}

async function loadShares(){
  const r = await fetch(API.shares, {headers:{'Authorization':'Bearer '+token}});
  const d = await r.json();
  allShares = d.shares || [];
  renderShares();
}

function fmtTime(ts){ if(!ts) return '永久'; return new Date(ts).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}); }
function fmtSize(b){ if(!b)return '-'; if(b<1024)return b+'B'; if(b<1048576)return (b/1024).toFixed(1)+'KB'; return (b/1048576).toFixed(2)+'MB'; }

function renderShares(){
  const tbody = document.getElementById('share-tbody');
  const list = allShares.filter(s => currentFilter==='all' || s.type===currentFilter);
  if(!list.length){ tbody.innerHTML='<tr><td colspan="8" class="empty">暂无分享</td></tr>'; return; }
  tbody.innerHTML = list.map(s => {
    const url = location.origin + HOME + s.id;
    const typeTag = s.type==='text' ? '<span class="tag text">文本</span>' : '<span class="tag file">文件</span>';
    const pwdTag = s.hasPassword ? '<span class="tag locked">🔒</span>' : '<span class="tag unlocked">无</span>';
    const size = s.type==='file' ? fmtSize(s.totalSize) : (s.content? (new Blob([s.content]).size>1024?(new Blob([s.content]).size/1024).toFixed(1)+'KB':new Blob([s.content]).size+'B') : '-');
    const views = (s.views||0)+(s.maxViews?'/'+s.maxViews:'');
    return '<tr>'+
      '<td class="id-cell"><a href="'+url+'" target="_blank">'+s.id+'</a>'+(s.title?'<br><small>'+s.title+'</small>':'')+'</td>'+
      '<td>'+typeTag+'</td>'+
      '<td>'+size+'</td>'+
      '<td>'+views+'</td>'+
      '<td>'+pwdTag+'</td>'+
      '<td>'+fmtTime(s.expireAt)+'</td>'+
      '<td>'+fmtTime(s.createdAt)+'</td>'+
      '<td class="actions">'+
        '<button class="btn-sm" onclick="copyLink(\\''+url+'\\')">复制</button>'+
        '<button class="btn-sm" onclick="openEditModal(\\''+s.id+'\\')">编辑</button>'+
        '<button class="btn-sm danger" onclick="delShare(\\''+s.id+'\\')">删除</button>'+
      '</td></tr>';
  }).join('');
}

window.copyLink = url => { navigator.clipboard.writeText(url).then(()=>alert('已复制链接')); };

window.delShare = async id => {
  if(!confirm('确认删除此分享?文件将一并删除,不可恢复!')) return;
  const r = await fetch(API.share(id)+'/delete', {method:'POST', headers:authHeaders()});
  const d = await r.json();
  if(d.ok){ await loadStats(); await loadShares(); }
  else alert(d.error||'失败');
};

// ===== 编辑分享模态框(密码+次数限制) =====
let editingId = null;
window.openEditModal = function(id){
  const s = allShares.find(x => x.id === id);
  if(!s){ alert('分享数据未找到'); return; }
  editingId = id;
  document.getElementById('edit-share-id').textContent = '#' + id;
  document.getElementById('edit-shareid').value = id;
  document.getElementById('edit-password').value = '';
  document.getElementById('edit-password').placeholder = s.hasPassword ? '已设置密码，留空=保持不变，输入新密码=修改' : '未设置密码，输入=设置，留空=无密码';
  document.getElementById('edit-max-views').value = s.maxViews || '';
  document.getElementById('edit-current-views').textContent = s.views || 0;
  // 下载次数仅文件分享显示
  const dlGroup = document.getElementById('edit-downloads-group');
  if(s.type === 'file'){
    dlGroup.style.display = '';
    document.getElementById('edit-max-downloads').value = s.maxDownloads || '';
    document.getElementById('edit-current-downloads').textContent = s.downloads || 0;
  } else {
    dlGroup.style.display = 'none';
  }
  document.getElementById('edit-modal').style.display = 'flex';
};
function closeEditModal(){ document.getElementById('edit-modal').style.display = 'none'; editingId = null; }
document.getElementById('edit-modal-close').onclick = closeEditModal;
document.getElementById('edit-cancel').onclick = closeEditModal;
document.getElementById('edit-modal').onclick = e => { if(e.target.id === 'edit-modal') closeEditModal(); };

document.getElementById('edit-save').onclick = async () => {
  if(!editingId) return;
  const btn = document.getElementById('edit-save');
  btn.disabled = true; btn.textContent = '保存中...';
  try {
    // 0. 修改分享号(如果改了,后续API用新ID)
    const newShareId = document.getElementById('edit-shareid').value.trim();
    if(newShareId && newShareId !== editingId){
      const r = await fetch(API.share(editingId)+'/rename', {method:'PUT', headers:authHeaders(), body:JSON.stringify({newId:newShareId})});
      const d = await r.json();
      if(!r.ok) throw new Error(d.error||'分享号修改失败');
      editingId = d.id;
    }
    // 1. 密码(有输入才改, 留空=保持不变; 但如果原来没密码,留空就是无密码)
    const pwd = document.getElementById('edit-password').value.trim();
    const s = allShares.find(x => x.id === editingId);
    // 只有当用户输入了密码, 或者(原来有密码且用户想清空)时才改密码
    // 规则: 输入框非空=设置新密码; 输入框为空且原来有密码=需要用户确认是否清空
    if(pwd){
      const r = await fetch(API.share(editingId)+'/password', {method:'PUT', headers:authHeaders(), body:JSON.stringify({password:pwd})});
      const d = await r.json();
      if(!r.ok) throw new Error(d.error||'密码修改失败');
    } else if(s && s.hasPassword){
      if(confirm('原分享有密码，留空将移除密码保护，确认？')){
        const r = await fetch(API.share(editingId)+'/password', {method:'PUT', headers:authHeaders(), body:JSON.stringify({password:''})});
        const d = await r.json();
        if(!r.ok) throw new Error(d.error||'密码移除失败');
      }
    }
    // 2. 次数限制
    const maxViews = document.getElementById('edit-max-views').value;
    const maxDownloads = document.getElementById('edit-max-downloads').value;
    const body = {};
    if(maxViews !== '') body.maxViews = Number(maxViews) || 0;
    if(maxDownloads !== '') body.maxDownloads = Number(maxDownloads) || 0;
    if(Object.keys(body).length){
      const r = await fetch(API.share(editingId)+'/limits', {method:'PUT', headers:authHeaders(), body:JSON.stringify(body)});
      const d = await r.json();
      if(!r.ok) throw new Error(d.error||'次数限制修改失败');
    }
    closeEditModal();
    await loadShares();
    alert('保存成功');
  } catch(e) {
    alert('错误: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = '保存';
  }
};

window.editPwd = async (id, hasPwd) => {
  const action = hasPwd ? '修改/清空密码' : '设置密码';
  const pwd = prompt(action+'\\n留空并确认=移除密码保护\\n请输入新密码:');
  if(pwd===null) return;
  const r = await fetch(API.share(id)+'/password', {method:'PUT', headers:authHeaders(), body:JSON.stringify({password:pwd})});
  const d = await r.json();
  if(d.ok){ alert(d.hasPassword?'密码已设置':'密码已移除'); loadShares(); }
  else alert(d.error||'失败');
};

document.querySelectorAll('.filter-btn').forEach(b => {
  b.onclick = () => {
    document.querySelectorAll('.filter-btn').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    currentFilter = b.dataset.filter;
    renderShares();
  };
});
document.getElementById('btn-refresh').onclick = () => { loadStats(); loadShares(); };

// 自动登录
if(token){
  // 验证 token 有效性
  fetch(API.config, {headers:{'Authorization':'Bearer '+token}}).then(r => {
    if(r.ok) enterAdmin(); else { localStorage.removeItem('admin_token'); token=''; }
  });
}
`;
