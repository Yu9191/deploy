/**
 * Pear 自动登录服务
 * 每4小时自动登录刷新Cookie和__pk
 * 
 * 使用: node server.js
 * 环境变量: PEAR_USER, PEAR_PASS
 */

const crypto = require('crypto');
const zlib = require('zlib');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const pako = require('pako');
const srpClient = require('secure-remote-password/client');
const SRPInteger = require('secure-remote-password/lib/srp-integer');
const params = require('secure-remote-password/lib/params');

// 配置
const CONFIG = {
    cbcKeyHex: 'b38313aed3d51f971769102760a4012182fbe26505853dd710f7dc656cf33a0a',
    loginenc: 'l2',
    baseUrl: 'https://dirt.pearhot.com',
    refreshInterval: 4 * 60 * 60 * 1000,  // 4小时
    outputFile: path.join(__dirname, 'cookie.json'),
    httpPort: process.env.PORT || 3000,
    testMovieId: '8cfc5220-c280-2be4-8b1b-3a1dfc3eeda4'  // 测试用视频ID
};

// 当前登录数据 (内存缓存)
let currentData = null;

// 从环境变量或config.json读取账号
function loadCredentials() {
    if (process.env.PEAR_USER && process.env.PEAR_PASS) {
        return { 
            username: process.env.PEAR_USER, 
            password: process.env.PEAR_PASS,
            githubToken: process.env.GITHUB_TOKEN || '',
            githubRepo: process.env.GITHUB_REPO || '',
            githubFile: process.env.GITHUB_FILE || ''
        };
    }
    const configPath = path.join(__dirname, 'config.json');
    if (fs.existsSync(configPath)) {
        return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
    return null;
}

// 工具函数
const hexToBuffer = (hex) => Buffer.from(hex.replace(/[^0-9a-fA-F]/g, ''), 'hex');
const bufferToHex = (buf) => buf.toString('hex');
const pakoDeflate = (data) => Buffer.from(pako.deflate(data));
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

function buildGuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// PBKDF2
function PBKDF2(input, salt, iterations, keylen) {
    return new Promise((resolve, reject) => {
        const deflated = pakoDeflate(Buffer.from(input, 'utf8'));
        const digest = sha256(deflated);
        crypto.pbkdf2(digest, hexToBuffer(salt), iterations, keylen, 'sha256', (err, key) => {
            if (err) reject(err);
            else resolve(bufferToHex(key));
        });
    });
}

// PAD to 512 hex chars
function PAD(srpInt) {
    return SRPInteger.fromHex(srpInt.toHex().padStart(512, '0'));
}

// Hash function for SRP
function H(...args) {
    const buffers = args.map(arg => {
        if (arg instanceof SRPInteger || (arg && typeof arg.toHex === 'function')) {
            return Buffer.from(arg.toHex(), 'hex');
        } else if (typeof arg === 'string') {
            return Buffer.from(arg, 'utf8');
        } else if (Buffer.isBuffer(arg)) {
            return arg;
        }
        throw new TypeError('Expected string or SRPInteger');
    });
    return SRPInteger.fromHex(crypto.createHash('sha256').update(Buffer.concat(buffers)).digest('hex'));
}

// Custom SRP session derivation with PAD
function customDeriveSession(clientSecretEphemeral, serverPublicEphemeral, salt, username, privateKey) {
    const { N, g } = params;
    const k = H(N, PAD(g));
    const aInt = SRPInteger.fromHex(clientSecretEphemeral);
    const B = SRPInteger.fromHex(serverPublicEphemeral);
    const s = SRPInteger.fromHex(salt);
    const x = SRPInteger.fromHex(privateKey);
    const A = g.modPow(aInt, N);
    
    if (B.mod(N).equals(SRPInteger.ZERO)) throw new Error('Invalid B');
    
    const u = H(PAD(A), PAD(B));
    const S = B.subtract(k.multiply(g.modPow(x, N))).modPow(aInt.add(u.multiply(x)), N);
    const K = H(S);
    const M = H(H(N).xor(H(g)), H(String(username)), s, A, B, K);
    
    return { key: K.toHex(), proof: M.toHex(), A: A.toHex() };
}

// AES-256-CBC 加密
function encryptCBC(data) {
    const kvBytes = hexToBuffer(CONFIG.cbcKeyHex);
    const cipher = crypto.createCipheriv('aes-256-cbc', kvBytes.subarray(0, 32), kvBytes.subarray(-16));
    return bufferToHex(Buffer.concat([cipher.update(Buffer.from(data, 'utf8')), cipher.final()]));
}

// 生成 msgKey
async function createMsgKey(passwordHash, salt) {
    const prefix = bufferToHex(sha256(Buffer.from('scee+srp', 'utf8')));
    return PBKDF2(prefix + '+' + passwordHash + '+' + salt, salt, 10000, 32);
}

// 解密 rule
function decryptRule(encryptedRule, msgKey) {
    try {
        const bytes = hexToBuffer(encryptedRule);
        const decipher = crypto.createDecipheriv('aes-256-gcm', hexToBuffer(msgKey), bytes.subarray(0, 12));
        decipher.setAuthTag(bytes.subarray(-16));
        return zlib.inflateSync(Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()])).toString('utf8');
    } catch (e) {
        return '';
    }
}

// HTTP 请求
function httpRequest(method, urlPath, data = null, headers = {}) {
    return new Promise((resolve, reject) => {
        const url = new URL(urlPath, CONFIG.baseUrl);
        const req = https.request({
            hostname: url.hostname,
            port: 443,
            path: url.pathname + url.search,
            method,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Origin': CONFIG.baseUrl,
                'Referer': CONFIG.baseUrl + '/changeAccount',
                ...headers
            }
        }, (res) => {
            const chunks = [];
            const setCookies = res.headers['set-cookie'] || [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => {
                let body = Buffer.concat(chunks);
                try {
                    if (res.headers['content-encoding'] === 'gzip') body = zlib.gunzipSync(body);
                    else if (res.headers['content-encoding'] === 'deflate') body = zlib.inflateSync(body);
                    else if (res.headers['content-encoding'] === 'br') body = zlib.brotliDecompressSync(body);
                } catch (e) {}
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(body.toString('utf8')), cookies: setCookies });
                } catch (e) {
                    resolve({ status: res.statusCode, data: body.toString('utf8'), cookies: setCookies });
                }
            });
        });
        req.on('error', reject);
        if (data) {
            const postData = typeof data === 'string' ? data : 
                Object.entries(data).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
            req.setHeader('Content-Length', Buffer.byteLength(postData));
            req.write(postData);
        }
        req.end();
    });
}

// 从 EncCheck 返回的混淆代码中提取 __pk 值
function extractPkFromEncCheck(base64Data) {
    try {
        const decoded = Buffer.from(base64Data.replace(/"/g, ''), 'base64').toString('utf8');
        const storage = {
            _data: {},
            getItem: function(key) { return this._data[key] || null; },
            setItem: function(key, value) { this._data[key] = value; }
        };
        const sandbox = {
            localStorage: storage,
            setTimeout: (fn) => { try { fn(); } catch(e) {} },
            setInterval: (fn) => { try { fn(); } catch(e) {} return 1; },
            clearInterval: () => {},
            console: { log: () => {}, error: () => {} }
        };
        vm.createContext(sandbox);
        try {
            const script = new vm.Script(decoded, { timeout: 3000 });
            script.runInContext(sandbox, { timeout: 3000 });
        } catch (e) {}
        return storage._data['__pk'] || null;
    } catch (e) {
        return null;
    }
}

// 调用 EncCheck 接口获取 __pk
async function fetchEncCheckPk(cookie) {
    const guid = buildGuid();
    const res = await httpRequest('POST', `/api/account/EncCheck?id=${guid}`, null, {
        'Cookie': cookie,
        'loginenc': CONFIG.loginenc,
        'loginenc7': CONFIG.loginenc
    });
    if (res.status === 200 && typeof res.data === 'string') {
        const pk = extractPkFromEncCheck(res.data);
        if (pk) return pk;
    }
    return CONFIG.loginenc;
}

// 登录主函数
async function login(username, password) {
    console.log(`[${new Date().toISOString()}] 开始登录: ${username}`);
    const commonHeaders = { 'loginenc': CONFIG.loginenc, 'loginenc7': CONFIG.loginenc };
    
    // Step 1: LoginA
    const clientEphemeral = srpClient.generateEphemeral();
    const res1 = await httpRequest('POST', '/api/account/LoginA', { A: clientEphemeral.public, ci: username }, commonHeaders);
    if (!res1.data.valid) throw new Error('LoginA失败: ' + JSON.stringify(res1.data));
    const { salt, b: B, c, iteration } = res1.data;
    console.log(`[LoginA] iteration=${iteration}`);
    
    // Step 2: SRP计算
    const passwordHash = await PBKDF2(username, salt, iteration, 64);
    const privateKey = srpClient.derivePrivateKey(salt, username, passwordHash);
    const session = customDeriveSession(clientEphemeral.secret, B, salt, username, privateKey);
    const m2 = crypto.createHash('sha256')
        .update(hexToBuffer(session.A))
        .update(hexToBuffer(session.proof))
        .update(hexToBuffer(session.key))
        .digest('hex');
    
    // Step 3: LoginB
    const step2Body = `srp%5Bci%5D=${encodeURIComponent(username)}&srp%5Bm1%5D=${session.proof}&srp%5Bm2%5D=${m2}&srp%5Bc%5D=${encodeURIComponent(c)}&userName=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&IsUserEvidenceLogin=false`;
    const res2 = await httpRequest('POST', '/api/account/LoginB', step2Body, commonHeaders);
    if (!res2.data.value) throw new Error('LoginB失败: ' + JSON.stringify(res2.data));
    console.log('[LoginB] 成功');
    
    // 解析Cookie
    let pearCookie = '', aspNetCookie = '';
    for (const cookieStr of res2.cookies) {
        const match = cookieStr.match(/^([^=]+)=([^;]+)/);
        if (match) {
            if (match[1] === '.Pear.Cookies') pearCookie = match[2];
            if (match[1] === '.AspNet.ApplicationCookie') aspNetCookie = match[2];
        }
    }
    
    // 生成密钥
    const msgKey = await createMsgKey(passwordHash, salt);
    const msgKEncrypted = encryptCBC(msgKey);
    let ruleKEncrypted = '';
    if (res2.data.rule) {
        const ruleDecrypted = decryptRule(res2.data.rule, msgKey);
        if (ruleDecrypted) ruleKEncrypted = encryptCBC(ruleDecrypted);
    }
    
    // 组装Cookie
    const cookieParts = [
        'NewPro.LabelCookie=0', 'NewPro.WebPCookie=1', 'tabHeaderSlider=0',
        `.Pear.Cookies=${pearCookie}`, `.AspNet.ApplicationCookie=${aspNetCookie}`,
        `__msg_k=${msgKEncrypted}`, `__rule_k=${ruleKEncrypted}`
    ];
    const fullCookie = cookieParts.join('; ');
    
    // 获取 __pk
    console.log('[EncCheck] 获取 __pk...');
    const pk = await fetchEncCheckPk(fullCookie);
    console.log('[EncCheck] __pk:', pk);
    
    return { cookie: fullCookie, pk, success: true, timestamp: new Date().toISOString() };
}

// 保存结果到文件
function saveResult(result) {
    currentData = result;  // 更新内存缓存
    fs.writeFileSync(CONFIG.outputFile, JSON.stringify(result, null, 2));
    console.log(`[${new Date().toISOString()}] 已保存到 ${CONFIG.outputFile}`);
    
    // 同步上传到 GitHub
    const creds = loadCredentials();
    if (creds && creds.githubToken && creds.githubRepo && creds.githubFile) {
        uploadToGitHub(result, creds);
    }
}

// 上传到 GitHub 仓库
async function uploadToGitHub(data, creds) {
    try {
        const content = Buffer.from(JSON.stringify(data, null, 2)).toString('base64');
        
        // 先获取文件的 sha (如果存在)
        const getReq = https.request({
            hostname: 'api.github.com',
            path: `/repos/${creds.githubRepo}/contents/${creds.githubFile}`,
            method: 'GET',
            headers: {
                'Authorization': `token ${creds.githubToken}`,
                'User-Agent': 'Pear-Login-Server',
                'Accept': 'application/vnd.github.v3+json'
            }
        }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                let sha = '';
                try {
                    const json = JSON.parse(body);
                    sha = json.sha || '';
                } catch (e) {}
                
                // 更新文件
                const payload = JSON.stringify({
                    message: `Update pear cookie ${new Date().toISOString()}`,
                    content: content,
                    sha: sha || undefined
                });
                
                const putReq = https.request({
                    hostname: 'api.github.com',
                    path: `/repos/${creds.githubRepo}/contents/${creds.githubFile}`,
                    method: 'PUT',
                    headers: {
                        'Authorization': `token ${creds.githubToken}`,
                        'User-Agent': 'Pear-Login-Server',
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(payload)
                    }
                }, (res2) => {
                    if (res2.statusCode === 200 || res2.statusCode === 201) {
                        console.log(`[${new Date().toISOString()}] 已同步到 GitHub`);
                    } else {
                        let errBody = '';
                        res2.on('data', chunk => errBody += chunk);
                        res2.on('end', () => console.error(`[GitHub] 上传失败: ${res2.statusCode} ${errBody}`));
                    }
                });
                
                putReq.on('error', (e) => console.error(`[GitHub] 错误: ${e.message}`));
                putReq.write(payload);
                putReq.end();
            });
        });
        
        getReq.on('error', (e) => console.error(`[GitHub] 获取sha错误: ${e.message}`));
        getReq.end();
    } catch (e) {
        console.error(`[GitHub] 上传异常: ${e.message}`);
    }
}

// ==================== 测试 API 相关 ====================

// 解密 CBC
function decryptCBC(hexCipher) {
    const kvBytes = hexToBuffer(CONFIG.cbcKeyHex);
    const key = kvBytes.subarray(0, 32);
    const iv = kvBytes.subarray(-16);
    const ct = hexToBuffer(hexCipher);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    decipher.setAutoPadding(false);
    let out = Buffer.concat([decipher.update(ct), decipher.final()]);
    // PKCS7 unpad
    const pad = out[out.length - 1];
    if (pad >= 1 && pad <= 32) out = out.subarray(0, out.length - pad);
    return out;
}

// 解密 GCM 响应
function decryptGcmResponse(hexData, msgkBuffer) {
    const bytes = hexToBuffer(hexData);
    const gcmKeyStr = msgkBuffer.toString('utf8').replace(/[\x00-\x1F\x7F-\xFF]/g, '');
    const key = Buffer.from(gcmKeyStr, 'hex');
    const iv = bytes.subarray(0, 12);
    const tag = bytes.subarray(-16);
    const ciphertext = bytes.subarray(12, -16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return zlib.inflateSync(decrypted).toString('utf8');
}

// 生成签名
function generateSign(rule, url, timeStr) {
    const parts = [rule.staticParam, timeStr, url, rule.key];
    const joinedStr = parts.join('\n');
    const compressed = zlib.deflateSync(Buffer.from(joinedStr, 'utf8'));
    const sha1Hash = crypto.createHash('sha1').update(compressed).digest();
    const hashHex = sha1Hash.toString('hex');
    const hashBytes = Buffer.from(hashHex, 'utf8');
    let checksum = rule.checksumConstant;
    for (const idx of rule.checksumIndexes) {
        if (idx < hashBytes.length) checksum += hashBytes[idx];
    }
    const checksumHex = Math.abs(checksum).toString(16).padStart(2, '0');
    let sign = rule.format.replace('{}', hashHex);
    return sign.replace('{:x}', checksumHex);
}

// 测试 Cookie 有效性
async function testCookieValidity() {
    if (!currentData) return { success: false, error: '无登录数据' };
    
    try {
        // 解析 cookie 中的 __msg_k 和 __rule_k
        const msgKMatch = currentData.cookie.match(/__msg_k=([0-9a-fA-F]+)/);
        const ruleKMatch = currentData.cookie.match(/__rule_k=([0-9a-fA-F]+)/);
        
        if (!msgKMatch || !ruleKMatch) {
            return { success: false, error: 'Cookie 缺少必要字段' };
        }
        
        const msgkBuffer = decryptCBC(msgKMatch[1]);
        const ruleRaw = decryptCBC(ruleKMatch[1]);
        let ruleStr = ruleRaw.toString('utf8');
        const jsonEnd = ruleStr.lastIndexOf('}');
        if (jsonEnd > 0) ruleStr = ruleStr.substring(0, jsonEnd + 1);
        const rule = JSON.parse(ruleStr);
        
        // 调用 WatchMovie API
        const signUrl = '/api/movie/watchmovie';
        const time = Date.now().toString();
        const sign = generateSign(rule, signUrl, time);
        
        const res = await httpRequest('POST', '/api/movie/WatchMovie', 
            `movieId=${CONFIG.testMovieId}&onlyCzn=0`, {
            'Cookie': currentData.cookie,
            'app-token': rule.appToken,
            'loginenc': currentData.pk,
            'loginenc7': currentData.pk,
            'time': time,
            'sign': sign
        });
        
        if (res.status === 200 && /^[0-9a-fA-F]+$/.test(res.data)) {
            // 解密响应
            const decrypted = decryptGcmResponse(res.data, msgkBuffer);
            const watchResult = JSON.parse(decrypted);
            
            if (watchResult.value === true && watchResult.checkId) {
                // 继续调用 movieCloud 获取播放地址
                const signUrl2 = '/api/movieplay/moviecloud';
                const time2 = Date.now().toString();
                const sign2 = generateSign(rule, signUrl2, time2);
                
                const res2 = await httpRequest('POST', '/api/moviePlay/movieCloud',
                    `movieId=${CONFIG.testMovieId}&checkId=${watchResult.checkId}`, {
                    'Cookie': currentData.cookie,
                    'app-token': rule.appToken,
                    'loginenc': currentData.pk,
                    'loginenc7': currentData.pk,
                    'time': time2,
                    'sign': sign2
                });
                
                if (res2.status === 200 && /^[0-9a-fA-F]+$/.test(res2.data)) {
                    const cloudResult = JSON.parse(decryptGcmResponse(res2.data, msgkBuffer));
                    
                    return { 
                        success: true, 
                        message: 'Cookie 有效',
                        data: {
                            name: cloudResult.name,
                            thumbnail: cloudResult.thumbnail,
                            playUrl: cloudResult.resolution?.[0]?.url || null,
                            resolution: cloudResult.resolution?.[0]?.name || null
                        }
                    };
                }
                
                return { 
                    success: true, 
                    message: 'Cookie 有效 (WatchMovie成功，但获取播放地址失败)',
                    data: { checkId: watchResult.checkId }
                };
            }
        }
        
        return { success: false, error: 'API 返回异常', raw: res.data };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// 定时任务
async function runTask() {
    const creds = loadCredentials();
    if (!creds) {
        console.error('错误: 未找到账号配置，请设置环境变量 PEAR_USER/PEAR_PASS 或创建 config.json');
        process.exit(1);
    }
    
    try {
        const result = await login(creds.username, creds.password);
        saveResult(result);
        console.log(`[${new Date().toISOString()}] 登录成功，下次刷新: ${new Date(Date.now() + CONFIG.refreshInterval).toISOString()}`);
        return true;
    } catch (e) {
        console.error(`[${new Date().toISOString()}] 登录失败:`, e.message);
        return false;
    }
}

// Web 页面 HTML
function getHtmlPage() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pear 登录服务</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 30px; color: #00d9ff; }
        .status { background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
        .status-row { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .status-label { color: #888; }
        .status-value { color: #00d9ff; font-family: monospace; }
        .status-value.ok { color: #00ff88; }
        .status-value.error { color: #ff4757; }
        .buttons { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 20px; }
        button { background: #0f3460; border: none; color: #fff; padding: 15px 20px; border-radius: 8px; cursor: pointer; font-size: 16px; transition: all 0.3s; }
        button:hover { background: #00d9ff; color: #1a1a2e; }
        button:active { transform: scale(0.98); }
        button.refresh { background: #e94560; }
        button.refresh:hover { background: #ff6b81; }
        .data-box { background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
        .data-box h3 { color: #00d9ff; margin-bottom: 15px; }
        .data-content { background: #0f0f23; border-radius: 5px; padding: 15px; font-family: monospace; font-size: 13px; word-break: break-all; max-height: 200px; overflow-y: auto; }
        .copy-btn { background: #00d9ff; color: #1a1a2e; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; margin-top: 10px; font-size: 14px; }
        .copy-btn:hover { background: #00b8d4; }
        .loading { opacity: 0.5; pointer-events: none; }
        #toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: #00d9ff; color: #1a1a2e; padding: 10px 20px; border-radius: 5px; display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍐 Pear 登录服务</h1>
        
        <div class="status">
            <div class="status-row">
                <span class="status-label">状态</span>
                <span class="status-value" id="status">检查中...</span>
            </div>
            <div class="status-row">
                <span class="status-label">最后更新</span>
                <span class="status-value" id="lastUpdate">-</span>
            </div>
            <div class="status-row">
                <span class="status-label">下次刷新</span>
                <span class="status-value" id="nextRefresh">-</span>
            </div>
        </div>
        
        <div class="buttons">
            <button onclick="getCookie()">获取 Cookie</button>
            <button onclick="getPk()">获取 PK</button>
            <button onclick="getAll()">获取全部数据</button>
            <button onclick="testApi()" style="background:#9b59b6;">测试 API</button>
            <button class="refresh" onclick="doRefresh()">立即刷新</button>
        </div>
        
        <div class="data-box" id="dataBox" style="display:none;">
            <h3 id="dataTitle">数据</h3>
            <div class="data-content" id="dataContent"></div>
            <button class="copy-btn" onclick="copyData()">复制</button>
        </div>
    </div>
    
    <div id="toast"></div>
    
    <script>
        let currentDataText = '';
        
        function showToast(msg) {
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.style.display = 'block';
            setTimeout(() => t.style.display = 'none', 2000);
        }
        
        function showData(title, data) {
            document.getElementById('dataTitle').textContent = title;
            currentDataText = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
            document.getElementById('dataContent').textContent = currentDataText;
            document.getElementById('dataBox').style.display = 'block';
        }
        
        function copyData() {
            navigator.clipboard.writeText(currentDataText).then(() => showToast('已复制'));
        }
        
        async function checkHealth() {
            try {
                const res = await fetch('/health');
                const data = await res.json();
                const statusEl = document.getElementById('status');
                if (data.hasData) {
                    statusEl.textContent = '正常运行';
                    statusEl.className = 'status-value ok';
                    if (data.lastUpdate) {
                        const d = new Date(data.lastUpdate);
                        document.getElementById('lastUpdate').textContent = d.toLocaleString('zh-CN');
                        const next = new Date(d.getTime() + 4 * 60 * 60 * 1000);
                        document.getElementById('nextRefresh').textContent = next.toLocaleString('zh-CN');
                    }
                } else {
                    statusEl.textContent = '等待首次登录';
                    statusEl.className = 'status-value';
                }
            } catch (e) {
                document.getElementById('status').textContent = '连接失败';
                document.getElementById('status').className = 'status-value error';
            }
        }
        
        async function getCookie() {
            const res = await fetch('/cookie');
            const data = await res.json();
            showData('Cookie', data.cookie || data.error);
        }
        
        async function getPk() {
            const res = await fetch('/pk');
            const data = await res.json();
            showData('PK (loginenc)', data.pk || data.error);
        }
        
        async function getAll() {
            const res = await fetch('/api');
            const data = await res.json();
            showData('完整数据', data);
        }
        
        async function doRefresh() {
            showToast('正在刷新...');
            await fetch('/refresh');
            setTimeout(checkHealth, 3000);
        }
        
        async function testApi() {
            showToast('正在测试...');
            try {
                const res = await fetch('/test');
                const data = await res.json();
                if (data.success) {
                    showData('测试结果 ✅', data);
                    showToast('Cookie 有效!');
                } else {
                    showData('测试结果 ❌', data);
                    showToast('测试失败: ' + (data.error || '未知错误'));
                }
            } catch (e) {
                showData('测试结果 ❌', { error: e.message });
            }
        }
        
        checkHealth();
        setInterval(checkHealth, 30000);
    </script>
</body>
</html>`;
}

// HTTP 服务
function startHttpServer() {
    const server = http.createServer(async (req, res) => {
        const url = new URL(req.url, `http://${req.headers.host}`);
        
        // CORS
        res.setHeader('Access-Control-Allow-Origin', '*');
        
        if (url.pathname === '/') {
            // 返回 Web 页面
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.end(getHtmlPage());
        } else if (url.pathname === '/api') {
            // 返回完整数据
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            if (currentData) {
                res.end(JSON.stringify(currentData, null, 2));
            } else {
                res.statusCode = 503;
                res.end(JSON.stringify({ error: '数据未就绪，请稍后重试' }));
            }
        } else if (url.pathname === '/cookie') {
            // 只返回 cookie
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            if (currentData) {
                res.end(JSON.stringify({ cookie: currentData.cookie }));
            } else {
                res.statusCode = 503;
                res.end(JSON.stringify({ error: '数据未就绪' }));
            }
        } else if (url.pathname === '/pk') {
            // 只返回 pk
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            if (currentData) {
                res.end(JSON.stringify({ pk: currentData.pk }));
            } else {
                res.statusCode = 503;
                res.end(JSON.stringify({ error: '数据未就绪' }));
            }
        } else if (url.pathname === '/refresh') {
            // 手动刷新
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.end(JSON.stringify({ message: '正在刷新...' }));
            runTask();
        } else if (url.pathname === '/test') {
            // 测试 Cookie 有效性
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            try {
                const result = await testCookieValidity();
                res.end(JSON.stringify(result, null, 2));
            } catch (e) {
                res.end(JSON.stringify({ success: false, error: e.message }));
            }
        } else if (url.pathname === '/health') {
            // 健康检查
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.end(JSON.stringify({ 
                status: 'ok', 
                hasData: !!currentData,
                lastUpdate: currentData?.timestamp || null
            }));
        } else {
            res.statusCode = 404;
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.end(JSON.stringify({ error: 'Not Found' }));
        }
    });
    
    server.listen(CONFIG.httpPort, () => {
        console.log(`HTTP 服务已启动: http://0.0.0.0:${CONFIG.httpPort}`);
        console.log('接口:');
        console.log(`  GET /       - Web 控制面板`);
        console.log(`  GET /api    - 获取完整数据 (JSON)`);
        console.log(`  GET /cookie - 只获取 cookie`);
        console.log(`  GET /pk     - 只获取 pk`);
        console.log(`  GET /test   - 测试 Cookie 有效性`);
        console.log(`  GET /refresh - 手动刷新`);
        console.log(`  GET /health - 健康检查`);
    });
}

// 启动服务
async function main() {
    console.log('='.repeat(50));
    console.log('Pear 自动登录服务');
    console.log(`刷新间隔: ${CONFIG.refreshInterval / 1000 / 60} 分钟`);
    console.log(`HTTP 端口: ${CONFIG.httpPort}`);
    console.log('='.repeat(50));
    
    // 启动 HTTP 服务
    startHttpServer();
    
    // 立即执行一次登录
    await runTask();
    
    // 设置定时任务
    setInterval(runTask, CONFIG.refreshInterval);
    
    console.log('服务已启动，按 Ctrl+C 退出');
}

main();
