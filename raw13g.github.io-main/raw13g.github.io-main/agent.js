/**
 * RogueByte Advanced Agent v3.0 (agent.js)
 * =========================================================================
 * وكيل متقدم يعمل داخل المتصفح مع jb.js في الوقت الفعلي.
 *
 * الميزات الرئيسية:
 *   1. اكتشاف إصدار الفيرموير تلقائياً من navigator.userAgent
 *   2. معالجة ذكية للإصدارات غير المدعومة:
 *      - إيجاد أقرب إصدار مدعوم
 *      - استعارة offsets منه مع درجة ثقة
 *      - تحذير واضح للمستخدم
 *   3. سُلّم إعادة المحاولة الذكي (5 مراحل متصاعدة)
 *   4. تتبع المراحل مع Timeout مخصص لكل مرحلة
 *   5. ذاكرة الجلسة — يتعلم من المحاولات السابقة
 *   6. Exponential Backoff لتقليل تضارب النواة
 *   7. واجهة HUD متقدمة مع شريط تقدم المراحل
 *   8. window.__agentAPI للتكامل مع core.js و jb.js
 * =========================================================================
 */

;(function () {
  'use strict';

  // ══════════════════════════════════════════════════════════════════════
  //  1. إعدادات الوكيل
  // ══════════════════════════════════════════════════════════════════════
  const AGENT_CFG = {
    version: '3.0',
    ollamaUrl: (new URLSearchParams(location.search)).get('ollama') || 'http://localhost:11434',
    ollamaModel: 'qwen2.5-coder:7b',
    maxRetries: 5,
    baseRetryDelayMs: 1800,
    showHud: true,
    KEY_RETRIES:  '__ag3_retries',
    KEY_STRATEGY: '__ag3_strategy',
    KEY_FW:       '__ag3_fw',
    KEY_SLOTS:    '__ag3_slots',
    KEY_DRAIN:    '__ag3_drain',
  };

  // ══════════════════════════════════════════════════════════════════════
  //  2. جدول الإصدارات المدعومة
  // ══════════════════════════════════════════════════════════════════════
  const KNOWN_FIRMWARES = [
    { key: '11.00', num: 1100, tier: 'proven',   alias: null },
    { key: '11.50', num: 1150, tier: 'proven',   alias: null },
    { key: '12.00', num: 1200, tier: 'untested', alias: null },
    { key: '12.02', num: 1202, tier: 'untested', alias: '12.00' },
    { key: '12.50', num: 1250, tier: 'untested', alias: null },
    { key: '12.52', num: 1252, tier: 'untested', alias: '12.50' },
    { key: '13.00', num: 1300, tier: 'proven',   alias: null },
    { key: '13.02', num: 1302, tier: 'proven',   alias: '13.00' },
    { key: '13.04', num: 1304, tier: 'proven',   alias: '13.00' },
    { key: '13.50', num: 1350, tier: 'proven',   alias: null },
    { key: '13.52', num: 1352, tier: 'proven',   alias: '13.50' },
  ];

  const CONFIDENCE = {
    EXACT:          { label: 'EXACT',        color: '#00ffa3', score: 100 },
    ALIAS:          { label: 'ALIAS',        color: '#00ffa3', score: 95  },
    NEIGHBOR_CLOSE: { label: 'NEAR',         color: '#ffb703', score: 72  },
    NEIGHBOR_FAR:   { label: 'FAR',          color: '#ff6b35', score: 40  },
    UNKNOWN:        { label: 'EXPERIMENTAL', color: '#ff3366', score: 15  },
  };

  // ══════════════════════════════════════════════════════════════════════
  //  3. الحالة الداخلية
  // ══════════════════════════════════════════════════════════════════════
  const _state = {
    rawFw: null, fwNum: 0, fwDetected: null,
    fwBorrowed: false, fwBorrowedFrom: null, fwConfidence: null, fwSupported: false,
    retryCount: 0, currentSlots: 12000000, currentDrain: 512,
    phase: 'IDLE', subPhase: null,
    fixAttempted: false, startTime: null, lastMarkTime: Date.now(),
    benchmarkMs: 0, stabilityScore: 'STABLE', recommendedGcPause: 80, strategy: 'DEFAULT',
    eventLog: [], failureLog: [],
    stallTimer: null, timerInterval: null,
  };

  // ══════════════════════════════════════════════════════════════════════
  //  4. مراحل الاكسبلويت مع Timeout مخصص
  // ══════════════════════════════════════════════════════════════════════
  const PHASE_MAP = {
    'FW':        { label: 'FW Detect',   timeoutMs: 5000  },
    'PRIMITIVE': { label: 'Primitive',   timeoutMs: 60000 },
    'PAIR':      { label: 'Pair Setup',  timeoutMs: 30000 },
    'BASES':     { label: 'Mod Bases',   timeoutMs: 10000 },
    'GADGET':    { label: 'Gadgets',     timeoutMs: 15000 },
    'PROBE':     { label: 'K-Probe',     timeoutMs: 45000 },
    'KERNEL':    { label: 'Kernel R/W',  timeoutMs: 60000 },
    'KPATCH':    { label: 'KPatch',      timeoutMs: 30000 },
    'PAYLOAD':   { label: 'Payload',     timeoutMs: 30000 },
    'PROOF':     { label: 'Verify',      timeoutMs: 20000 },
    'DEFAULT':   { label: 'Running',     timeoutMs: 45000 },
  };

  const PHASE_ORDER = ['FW','PRIMITIVE','PAIR','BASES','GADGET','PROBE','KERNEL','KPATCH','PAYLOAD','PROOF'];

  // ══════════════════════════════════════════════════════════════════════
  //  5. كاشفات النمط
  // ══════════════════════════════════════════════════════════════════════
  const BAD_RE  = /FAIL|ERROR|THREW|REBOOT|LOST|POISON|TIMEOUT|MISMATCH|ABORTED|PANIC|CORRUPT|CRASH/i;
  const WARN_RE = /WARN|SKIP|REFUSED|COMMITTED|DIRTY|UNSTABLE/i;
  const OK_RE   = /\bOK\b|PASS|ACHIEVED|RUNNING|ARMED|PROOF-OK|FOUND/i;
  const DONE_RE = /\bDONE\b|SUCCESS|JAILBROKEN|KERNEL.*OK|finishUI\(true\)/i;

  function _tagCls(tag) {
    const t = String(tag);
    if (BAD_RE.test(t))  return 'fail';
    if (WARN_RE.test(t)) return 'warn';
    if (OK_RE.test(t) || DONE_RE.test(t)) return 'ok';
    return '';
  }

  function _detectSubPhase(tag) {
    const t = String(tag).toUpperCase();
    for (const [key, cfg] of Object.entries(PHASE_MAP)) {
      if (key !== 'DEFAULT' && t.startsWith(key)) return { key, cfg };
    }
    return { key: 'DEFAULT', cfg: PHASE_MAP.DEFAULT };
  }

  // ══════════════════════════════════════════════════════════════════════
  //  6. اكتشاف ومعالجة الفيرموير
  // ══════════════════════════════════════════════════════════════════════
  function _parseFirmwareFromUA(ua) {
    const m = (ua || '').match(/PlayStation\s+4[\/\s](\d+)\.(\d+)/i);
    if (!m) return null;
    const major = parseInt(m[1], 10);
    const minor  = parseInt(m[2], 16);
    const key    = major + '.' + minor.toString(16).padStart(2, '0').replace(/^0(?=[1-9])/, '');
    const keyAlt = major + '.' + parseInt(m[2], 10);
    return { raw: key, rawAlt: keyAlt, num: major * 100 + minor };
  }

  function _resolveOffsets(fwInfo) {
    if (!fwInfo) return { resolvedKey: null, confidence: CONFIDENCE.UNKNOWN, borrowed: false,
      notes: 'UA not recognized as PS4' };
    const { raw, rawAlt, num } = fwInfo;

    const exact = KNOWN_FIRMWARES.find(f => f.key === raw || f.key === rawAlt);
    if (exact) {
      const isAlias = !!exact.alias;
      return { resolvedKey: exact.key,
        confidence: isAlias ? CONFIDENCE.ALIAS : CONFIDENCE.EXACT,
        borrowed: false,
        notes: isAlias
          ? `Known firmware ${raw} (alias of ${exact.alias})`
          : `Known firmware ${raw} — directly supported` };
    }

    // أقرب إصدار
    let best = null, bestDelta = Infinity;
    for (const fw of KNOWN_FIRMWARES) {
      const d = Math.abs(fw.num - num);
      if (d < bestDelta) { bestDelta = d; best = fw; }
    }
    if (!best) return { resolvedKey: null, confidence: CONFIDENCE.UNKNOWN, borrowed: false,
      notes: 'No known firmware found' };

    const confidence = bestDelta <= 2 ? CONFIDENCE.NEIGHBOR_CLOSE : CONFIDENCE.NEIGHBOR_FAR;
    return {
      resolvedKey: best.key,
      confidence,
      borrowed: true,
      borrowDelta: bestDelta,
      notes: `FW ${raw} not in offsets → borrowing from ${best.key} (Δ${bestDelta} vers, tier=${best.tier})`,
    };
  }

  function _injectBorrowedOffsets(resolvedKey, fwInfo) {
    if (!resolvedKey || !fwInfo) return;
    window.__agentFWOverride = {
      originalKey: fwInfo.raw,
      resolvedKey,
      borrowed: true,
      confidence: _state.fwConfidence,
      activatedAt: Date.now(),
    };
    _agLog('FW-INJECT', `Override set: ${fwInfo.raw} → ${resolvedKey}`, 'warn');
  }

  // ══════════════════════════════════════════════════════════════════════
  //  7. قياس الأداء والتوقيت التكيفي
  // ══════════════════════════════════════════════════════════════════════
  function _runBenchmark() {
    const t0 = performance.now ? performance.now() : Date.now();
    let acc = 0;
    for (let i = 0; i < 200000; i++) acc = (acc + ((i * 7) ^ 13)) | 0;
    try {
      const b = [];
      for (let j = 0; j < 64; j++) b.push(new Uint32Array(512));
      b.length = 0;
    } catch(e) {}
    const lat = Math.max(1, Math.round((performance.now ? performance.now() : Date.now()) - t0));
    _state.benchmarkMs = lat;

    if (lat < 15)       { _state.stabilityScore = 'FAST';     _state.recommendedGcPause = 45; }
    else if (lat < 50)  { _state.stabilityScore = 'STABLE';   _state.recommendedGcPause = 85; }
    else if (lat < 100) { _state.stabilityScore = 'MODERATE'; _state.recommendedGcPause = 140; }
    else                { _state.stabilityScore = 'DEGRADED'; _state.recommendedGcPause = 220; }

    if (_state.retryCount >= 1) {
      const bf = 1 + _state.retryCount * 0.5;
      _state.recommendedGcPause = Math.min(Math.round(_state.recommendedGcPause * bf), 600);
    }
    if (!_state.fwSupported) _state.recommendedGcPause = Math.min(_state.recommendedGcPause + 60, 600);

    const strats = ['DEFAULT','CONSERVATIVE','HEAP_RESHAPE','DRAIN_TUNE','FULL_RESET'];
    _state.strategy = strats[Math.min(_state.retryCount, strats.length - 1)];

    window.__agentTiming = {
      latencyMs: lat, stability: _state.stabilityScore,
      gcPauseMs: _state.recommendedGcPause, strategy: _state.strategy,
      retryCount: _state.retryCount, slots: _state.currentSlots, drain: _state.currentDrain,
    };
    _agLog('BENCH', `${lat}ms | ${_state.stabilityScore} | GC=${_state.recommendedGcPause}ms | ${_state.strategy}`, 'ok');
  }

  // ══════════════════════════════════════════════════════════════════════
  //  8. سُلّم إعادة المحاولة
  // ══════════════════════════════════════════════════════════════════════
  function _retryTimingAdjust(d) {
    _agLog('RETRY', 'Conservative GC timing adjustment', 'fix');
    _saveSession(); setTimeout(() => location.reload(), d);
  }
  function _retryCachePurge(d) {
    _agLog('RETRY', 'Session cache purge', 'fix');
    try {
      const keep = {};
      ['__ag3_retries','__ag3_strategy','__ag3_fw','__ag3_slots','__ag3_drain'].forEach(k => {
        const v = sessionStorage.getItem(k); if (v !== null) keep[k] = v;
      });
      sessionStorage.clear();
      Object.entries(keep).forEach(([k,v]) => sessionStorage.setItem(k, v));
    } catch(e) {}
    _saveSession(); setTimeout(() => location.reload(), d);
  }
  function _retryHeapReshape(d) {
    const opts = [8000000, 10000000, 14000000, 16000000, 18000000];
    _state.currentSlots = opts[Math.min(_state.retryCount - 1, opts.length - 1)];
    _agLog('RETRY', `Heap reshape: slots=${_state.currentSlots}`, 'fix');
    const url = new URL(location.href);
    url.searchParams.set('slots', String(_state.currentSlots));
    try { sessionStorage.setItem(AGENT_CFG.KEY_SLOTS, String(_state.currentSlots)); } catch(e) {}
    _saveSession(); setTimeout(() => location.replace(url.toString()), d);
  }
  function _retryDrainTune(d) {
    const opts = [256, 384, 640, 768, 1024];
    _state.currentDrain = opts[Math.min(_state.retryCount - 1, opts.length - 1)];
    _agLog('RETRY', `Drain tune: drain=${_state.currentDrain}`, 'fix');
    const url = new URL(location.href);
    url.searchParams.set('g', `drain:${_state.currentDrain}`);
    try {
      const s = sessionStorage.getItem(AGENT_CFG.KEY_SLOTS);
      if (s) url.searchParams.set('slots', s);
      sessionStorage.setItem(AGENT_CFG.KEY_DRAIN, String(_state.currentDrain));
    } catch(e) {}
    _saveSession(); setTimeout(() => location.replace(url.toString()), d);
  }
  function _retryFullReset(d) {
    _agLog('RETRY', 'FULL RESET — clearing all state', 'fix');
    try {
      const r = sessionStorage.getItem(AGENT_CFG.KEY_RETRIES);
      sessionStorage.clear();
      sessionStorage.setItem(AGENT_CFG.KEY_RETRIES, r || '0');
    } catch(e) {}
    const url = new URL(location.href);
    url.searchParams.delete('slots'); url.searchParams.delete('g');
    _saveSession(); setTimeout(() => location.replace(url.toString()), d);
  }

  const RETRY_LADDER = [
    { step:1, name:'TIMING_ADJUST',  desc:'Adjusting GC pause timing',          action: _retryTimingAdjust  },
    { step:2, name:'CACHE_PURGE',    desc:'Clearing session caches',             action: _retryCachePurge    },
    { step:3, name:'HEAP_RESHAPE',   desc:'Reshaping heap spray (slots)',        action: _retryHeapReshape   },
    { step:4, name:'DRAIN_TUNE',     desc:'Tuning drain cycle count',            action: _retryDrainTune     },
    { step:5, name:'FULL_RESET',     desc:'Full state reset + clean reload',     action: _retryFullReset     },
  ];

  // ══════════════════════════════════════════════════════════════════════
  //  9. ذاكرة الجلسة
  // ══════════════════════════════════════════════════════════════════════
  function _saveSession() {
    try {
      sessionStorage.setItem(AGENT_CFG.KEY_RETRIES, String(_state.retryCount));
      sessionStorage.setItem(AGENT_CFG.KEY_STRATEGY, _state.strategy);
      if (_state.rawFw) sessionStorage.setItem(AGENT_CFG.KEY_FW, _state.rawFw);
    } catch(e) {}
  }
  function _loadSession() {
    try {
      const s = parseInt(sessionStorage.getItem(AGENT_CFG.KEY_RETRIES) || '0', 10);
      _state.retryCount = isNaN(s) ? 0 : s;
      const strat = sessionStorage.getItem(AGENT_CFG.KEY_STRATEGY);
      if (strat) _state.strategy = strat;
      const slots = sessionStorage.getItem(AGENT_CFG.KEY_SLOTS);
      if (slots) _state.currentSlots = parseInt(slots, 10) || 12000000;
      const drain = sessionStorage.getItem(AGENT_CFG.KEY_DRAIN);
      if (drain) _state.currentDrain = parseInt(drain, 10) || 512;
      if (_state.retryCount > 0)
        _agLog('RESUME', `Attempt ${_state.retryCount}/${AGENT_CFG.maxRetries} | ${_state.strategy}`, 'fix');
    } catch(e) {}
  }
  function _clearSession() {
    try {
      ['__ag3_retries','__ag3_strategy','__ag3_fw','__ag3_slots','__ag3_drain']
        .forEach(k => sessionStorage.removeItem(k));
    } catch(e) {}
  }

  // ══════════════════════════════════════════════════════════════════════
  //  10. محرك الإصلاح (Self-Healing Engine)
  // ══════════════════════════════════════════════════════════════════════
  function _onFailureDetected(tag, detail) {
    if (_state.phase === 'SUCCESS' || _state.phase === 'RETRYING') return;
    _state.failureLog.push({ tag, detail, phase: _state.subPhase, ts: Date.now() });

    if (_state.retryCount >= AGENT_CFG.maxRetries) { _onExhausted(); return; }

    _state.phase = 'RETRYING';
    _hudSetPhase('RECOVERING', 'fix');

    const step = RETRY_LADDER[Math.min(_state.retryCount, RETRY_LADDER.length - 1)];
    _state.retryCount++;

    // Exponential backoff
    const delay = Math.round(Math.min(AGENT_CFG.baseRetryDelayMs * Math.pow(1.6, _state.retryCount - 1), 15000));
    _agLog('RETRY', `[${step.name}] ${_state.retryCount}/${AGENT_CFG.maxRetries} in ${delay}ms`, 'fix');
    _hudSetStatus(`↺ Retry ${_state.retryCount}/${AGENT_CFG.maxRetries}: ${step.desc}`);
    _hudSetRetry(`[${step.name}] ${delay}ms…`);
    step.action(delay);
  }

  function _onExhausted() {
    _state.phase = 'FAILED';
    _agLog('EXHAUSTED', `All ${AGENT_CFG.maxRetries} retries failed`, 'fail');
    _hudSetPhase('FAILED', 'fail');
    _hudSetStatus('All retries exhausted. Reboot console or check FW compatibility.');
    _clearSession();
    _sendToQwen('exhausted');
  }

  // ══════════════════════════════════════════════════════════════════════
  //  11. مراقبة الجمود
  // ══════════════════════════════════════════════════════════════════════
  function _resetStallTimer(subPhaseKey) {
    if (_state.stallTimer) clearTimeout(_state.stallTimer);
    if (_state.phase !== 'RUNNING') return;
    const cfg = PHASE_MAP[subPhaseKey] || PHASE_MAP.DEFAULT;
    _state.stallTimer = setTimeout(() => {
      if (_state.phase !== 'RUNNING') return;
      _agLog('STALL', `[${cfg.label}] stalled after ${cfg.timeoutMs / 1000}s`, 'warn');
      _hudSetPhase('STALLED', 'warn');
      _onFailureDetected('STALL', `Phase ${cfg.label} timeout`);
    }, cfg.timeoutMs);
  }

  // ══════════════════════════════════════════════════════════════════════
  //  12. AI / Heuristics
  // ══════════════════════════════════════════════════════════════════════
  function _sendToQwen(eventType) {
    const logSummary = _state.eventLog.slice(-20).map(e => `[${e.tag}] ${e.detail}`).join('\n');
    const lastFail = _state.failureLog.slice(-1)[0];
    _hudSetStatus(`Heuristic: ${lastFail ? lastFail.tag + ' @ ' + (lastFail.phase || '?') : 'generic instability'}`);
    if (!AGENT_CFG.ollamaUrl) return;
    const fwStr = _state.fwBorrowed
      ? `FW=${_state.rawFw} BORROWED from ${_state.fwBorrowedFrom} (${_state.fwConfidence ? _state.fwConfidence.label : '?'})`
      : `FW=${_state.rawFw}`;
    const prompt = `PS4 Exploit Agent — Event: ${eventType}\n${fwStr}\nRetry: ${_state.retryCount}/${AGENT_CFG.maxRetries}\nStrategy: ${_state.strategy}\nLogs:\n${logSummary}\n\nBrief root cause and fix (2 sentences).`.trim();
    fetch(AGENT_CFG.ollamaUrl + '/api/chat', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, mode: 'cors',
      body: JSON.stringify({ model: AGENT_CFG.ollamaModel,
        messages: [{ role: 'user', content: prompt }], stream: false,
        options: { temperature: 0.1, num_predict: 120 } }),
    }).then(r => r.json()).then(resp => {
      const msg = (resp.message && resp.message.content) || '';
      if (msg) { _agLog('AI', msg.slice(0, 130), 'fix'); _hudSetStatus('AI: ' + msg.slice(0, 110)); }
    }).catch(() => _agLog('AI', 'Ollama offline — heuristics only', 'warn'));
  }

  // ══════════════════════════════════════════════════════════════════════
  //  13. Preflight
  // ══════════════════════════════════════════════════════════════════════
  const PREFLIGHT = [
    { short:'PS4-UA',  warn:true,  test:() => /PlayStation\s+4/i.test(navigator.userAgent) },
    { short:'ES6',     warn:false, test:() => typeof Promise !== 'undefined' && typeof Symbol !== 'undefined' },
    { short:'Storage', warn:true,  test:() => { try{sessionStorage.setItem('t','1');sessionStorage.removeItem('t');return true;}catch(e){return false;} } },
    { short:'WASM',    warn:true,  test:() => typeof WebAssembly !== 'undefined' },
    { short:'SAB',     warn:true,  test:() => typeof SharedArrayBuffer !== 'undefined' },
    { short:'INT64',   warn:false, test:() => (0xffffffff | 0) === -1 },
  ];
  function _runPreflight() {
    const res = PREFLIGHT.map(t => {
      let ok = false; try { ok = !!t.test(); } catch(e) {}
      const cls = ok ? 'ok' : (t.warn ? 'warn' : 'fail');
      _agLog('PREFLIGHT', `${t.short}: ${ok?'OK':(t.warn?'WARN':'FAIL')}`, cls);
      return { short: t.short, cls };
    });
    _hudShowPreflight(res);
    return res.every(r => r.cls !== 'fail');
  }

  // ══════════════════════════════════════════════════════════════════════
  //  14. التسجيل
  // ══════════════════════════════════════════════════════════════════════
  function _agLog(tag, detail, cls) {
    const e = { tag, detail: String(detail || ''), cls, ts: Date.now() };
    _state.eventLog.push(e);
    if (_state.eventLog.length > 200) _state.eventLog.shift();
    _hudAddRow(tag, detail, cls || _tagCls(tag));
  }

  // ══════════════════════════════════════════════════════════════════════
  //  15. HUD
  // ══════════════════════════════════════════════════════════════════════
  let _hud=null,_hudPhase=null,_hudStatus=null,_hudRetry=null,_hudTimer=null,_hudRows=null;
  let _hudPbarFill=null,_hudCollapsed=false;

  function _createHud() {
    if (!AGENT_CFG.showHud || _hud || !document.body) return;
    const s = document.createElement('style');
    s.id = '__ag3-style';
    s.textContent = `
      #__ag3{position:fixed;bottom:14px;right:14px;z-index:2147483647;width:340px;
        font-family:Consolas,"Fira Code","Courier New",monospace;font-size:11px;
        background:rgba(5,9,20,.96);border:1px solid rgba(0,220,255,.3);border-radius:14px;
        backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);
        box-shadow:0 14px 44px rgba(0,0,0,.9),0 0 28px rgba(0,220,255,.12);
        overflow:hidden;transition:height .3s cubic-bezier(.4,0,.2,1);
        user-select:none;-webkit-user-select:none;color:#dde4f0;}
      #__ag3.collapsed{height:42px;}
      #__ag3-head{display:flex;align-items:center;justify-content:space-between;padding:9px 13px;
        background:linear-gradient(90deg,rgba(0,220,255,.12),rgba(140,60,220,.12));
        border-bottom:1px solid rgba(0,220,255,.18);cursor:pointer;}
      #__ag3-title{display:flex;align-items:center;gap:8px;font-weight:800;font-size:11px;
        letter-spacing:.13em;color:#00dcff;text-transform:uppercase;}
      #__ag3-dot{width:8px;height:8px;border-radius:50%;background:#00ffa3;
        box-shadow:0 0 9px #00ffa3;animation:ag3p 1.5s infinite ease-in-out;}
      @keyframes ag3p{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.8)}}
      #__ag3-head-r{display:flex;align-items:center;gap:8px;color:#778;font-size:10px;}
      #__ag3-tog{background:none;border:none;color:#778;font-size:13px;cursor:pointer;padding:2px 4px;}
      #__ag3-body{padding:10px 12px;}
      #__ag3-fw{display:flex;align-items:center;gap:6px;padding:5px 9px;border-radius:8px;
        margin-bottom:7px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);font-size:10px;}
      #__ag3-fw .fwk{font-weight:800;font-size:11px;}
      #__ag3-fw .fwc{font-size:9px;font-weight:700;padding:2px 6px;border-radius:5px;}
      #__ag3-fwwarn{font-size:9px;padding:5px 8px;border-radius:7px;margin-bottom:7px;
        background:rgba(255,140,0,.1);border:1px solid rgba(255,140,0,.3);
        color:#ffb703;display:none;line-height:1.5;}
      #__ag3-met{display:flex;justify-content:space-between;padding:4px 8px;
        background:rgba(255,255,255,.03);border-radius:6px;margin-bottom:7px;font-size:10px;color:#778;}
      #__ag3-met strong{color:#d1d8e8;}
      #__ag3-pf{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:7px;}
      .ag3-pf{font-size:9px;padding:2px 6px;border-radius:5px;font-weight:700;}
      .ag3-pf.ok{background:rgba(0,255,163,.12);color:#00ffa3;border:1px solid rgba(0,255,163,.25);}
      .ag3-pf.fail{background:rgba(255,51,102,.12);color:#ff3366;border:1px solid rgba(255,51,102,.25);}
      .ag3-pf.warn{background:rgba(255,183,3,.12);color:#ffb703;border:1px solid rgba(255,183,3,.25);}
      #__ag3-pr{display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;}
      #__ag3-phase{font-size:12px;font-weight:900;letter-spacing:.1em;text-transform:uppercase;color:#00dcff;}
      #__ag3-phase.ok{color:#00ffa3;text-shadow:0 0 10px #00ffa3;}
      #__ag3-phase.fail{color:#ff3366;text-shadow:0 0 10px #ff3366;}
      #__ag3-phase.warn{color:#ffb703;text-shadow:0 0 10px #ffb703;}
      #__ag3-phase.fix{color:#b48ef8;text-shadow:0 0 10px #b48ef8;}
      #__ag3-pbar{height:3px;background:rgba(255,255,255,.07);border-radius:2px;margin-bottom:7px;overflow:hidden;}
      #__ag3-pbf{height:100%;background:linear-gradient(90deg,#00dcff,#7c3aed);border-radius:2px;
        transition:width .5s ease;width:0%;}
      #__ag3-status{font-size:10px;color:#b0b8cc;line-height:1.45;min-height:28px;
        margin-bottom:5px;word-break:break-word;}
      #__ag3-retry{font-size:10px;color:#ffb703;font-weight:700;margin-bottom:5px;display:none;}
      #__ag3-acts{display:flex;gap:5px;margin-bottom:7px;}
      .ag3-btn{flex:1;background:rgba(0,220,255,.07);border:1px solid rgba(0,220,255,.22);
        border-radius:6px;color:#00dcff;font-size:9px;font-weight:700;
        padding:4px 5px;cursor:pointer;transition:all .2s;text-align:center;}
      .ag3-btn:hover{background:rgba(0,220,255,.2);box-shadow:0 0 8px rgba(0,220,255,.3);}
      .ag3-btn.p{background:rgba(140,60,220,.1);border-color:rgba(140,60,220,.35);color:#c4b5fd;}
      .ag3-btn.p:hover{background:rgba(140,60,220,.25);}
      .ag3-btn.r{background:rgba(255,51,102,.1);border-color:rgba(255,51,102,.35);color:#ff8099;}
      .ag3-btn.r:hover{background:rgba(255,51,102,.25);}
      #__ag3-log{max-height:90px;overflow-y:auto;border-top:1px solid rgba(255,255,255,.06);padding-top:6px;}
      #__ag3-log::-webkit-scrollbar{width:3px;}
      #__ag3-log::-webkit-scrollbar-thumb{background:rgba(0,220,255,.2);border-radius:2px;}
      .ag3-row{display:flex;gap:5px;padding:2px 0;font-size:10px;color:#556;line-height:1.3;}
      .ag3-row.ok{color:#00ffa3;}.ag3-row.fail{color:#ff3366;}.ag3-row.warn{color:#ffb703;}.ag3-row.fix{color:#c4b5fd;}
      .ag3-tag{opacity:.85;font-weight:700;min-width:50px;}
    `;
    document.head.appendChild(s);

    _hud = document.createElement('div');
    _hud.id = '__ag3';
    _hud.innerHTML = `
      <div id="__ag3-head">
        <div id="__ag3-title"><span id="__ag3-dot"></span><span>Rogue Agent v3</span></div>
        <div id="__ag3-head-r"><span id="__ag3-timer">00:00</span><button id="__ag3-tog">▲</button></div>
      </div>
      <div id="__ag3-body">
        <div id="__ag3-fw">
          <span>FW:</span>
          <span class="fwk" id="__ag3-fwkey">Detecting…</span>
          <span class="fwc" id="__ag3-fwconf" style="display:none"></span>
          <span id="__ag3-mem" style="margin-left:auto;color:#556;font-size:9px">--</span>
        </div>
        <div id="__ag3-fwwarn"></div>
        <div id="__ag3-met">
          <span>Bench:<strong id="__ag3-bench"> --</strong></span>
          <span>GC:<strong id="__ag3-gc"> --</strong>ms</span>
          <span>Retry:<strong id="__ag3-rc"> 0</strong>/${AGENT_CFG.maxRetries}</span>
        </div>
        <div id="__ag3-pf"></div>
        <div id="__ag3-pr"><span id="__ag3-phase">INIT</span></div>
        <div id="__ag3-pbar"><div id="__ag3-pbf"></div></div>
        <div id="__ag3-status">Starting…</div>
        <div id="__ag3-retry"></div>
        <div id="__ag3-acts">
          <button class="ag3-btn" id="__ag3-b-retry">↺ Retry</button>
          <button class="ag3-btn p" id="__ag3-b-ai">🤖 AI</button>
          <button class="ag3-btn" id="__ag3-b-copy">📋 Log</button>
          <button class="ag3-btn r" id="__ag3-b-reset">⊗ Reset</button>
        </div>
        <div id="__ag3-log"></div>
      </div>
    `;
    document.body.appendChild(_hud);

    _hudPhase   = document.getElementById('__ag3-phase');
    _hudStatus  = document.getElementById('__ag3-status');
    _hudRetry   = document.getElementById('__ag3-retry');
    _hudTimer   = document.getElementById('__ag3-timer');
    _hudRows    = document.getElementById('__ag3-log');
    _hudPbarFill = document.getElementById('__ag3-pbf');

    document.getElementById('__ag3-head').addEventListener('click', e => {
      if (e.target.tagName === 'BUTTON') return;
      _hudCollapsed = !_hudCollapsed;
      _hud.classList.toggle('collapsed', _hudCollapsed);
      document.getElementById('__ag3-tog').textContent = _hudCollapsed ? '▼' : '▲';
    });
    document.getElementById('__ag3-b-retry').addEventListener('click', () =>
      _onFailureDetected('MANUAL_RETRY', 'User triggered'));
    document.getElementById('__ag3-b-ai').addEventListener('click', () => {
      _hudSetPhase('AI DIAGNOSING','fix'); _sendToQwen('manual');
    });
    document.getElementById('__ag3-b-copy').addEventListener('click', () => {
      const d = JSON.stringify(window.__agentDump(), null, 2);
      try { navigator.clipboard.writeText(d); } catch(e) { console.log('[DUMP]',d); }
      _hudSetStatus('Copied to clipboard!');
    });
    document.getElementById('__ag3-b-reset').addEventListener('click', () => {
      _clearSession(); setTimeout(() => location.reload(), 200);
    });

    _state.timerInterval = setInterval(() => {
      if (_hudTimer && _state.startTime) {
        const s = Math.floor((Date.now() - _state.startTime) / 1000);
        _hudTimer.textContent = `${String(Math.floor(s/60)).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`;
      }
      _updateMetrics();
    }, 1000);
  }

  function _updateMetrics() {
    const mem = document.getElementById('__ag3-mem');
    if (mem && window.performance && window.performance.memory)
      mem.textContent = Math.round(window.performance.memory.usedJSHeapSize/(1024*1024))+'MB';
    const bench = document.getElementById('__ag3-bench');
    if (bench) bench.textContent = ' '+_state.benchmarkMs+'ms ('+_state.stabilityScore+')';
    const gc = document.getElementById('__ag3-gc');
    if (gc) gc.textContent = ' '+_state.recommendedGcPause;
    const rc = document.getElementById('__ag3-rc');
    if (rc) rc.textContent = ' '+_state.retryCount;
  }
  function _hudSetFirmware(key, conf, borrowed, notes) {
    const kEl = document.getElementById('__ag3-fwkey');
    const cEl = document.getElementById('__ag3-fwconf');
    const wEl = document.getElementById('__ag3-fwwarn');
    if (kEl) kEl.textContent = key || 'Unknown';
    if (cEl && conf) {
      cEl.style.display = 'inline'; cEl.textContent = conf.label;
      cEl.style.background = conf.color + '22'; cEl.style.color = conf.color;
      cEl.style.border = '1px solid ' + conf.color + '55';
    }
    if (wEl && borrowed && notes) { wEl.style.display = 'block'; wEl.innerHTML = '⚠ ' + notes; }
  }
  function _hudSetPhase(l, c) { if (_hudPhase) { _hudPhase.textContent = l; _hudPhase.className = c||''; } }
  function _hudSetStatus(t) { if (_hudStatus) _hudStatus.textContent = t; }
  function _hudSetRetry(t) {
    if (!_hudRetry) return;
    _hudRetry.style.display = t ? 'block' : 'none';
    if (t) _hudRetry.textContent = t;
  }
  function _hudSetProgress(pct) {
    if (_hudPbarFill) _hudPbarFill.style.width = Math.min(100, Math.max(0, pct)) + '%';
  }
  function _hudAddRow(tag, detail, cls) {
    if (!_hudRows) return;
    const r = document.createElement('div');
    r.className = 'ag3-row ' + (cls || '');
    const e = t => String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;');
    r.innerHTML = `<span class="ag3-tag">${e(tag)}</span><span>${e(String(detail||'').slice(0,110))}</span>`;
    _hudRows.appendChild(r);
    while (_hudRows.children.length > 60) _hudRows.removeChild(_hudRows.firstChild);
    _hudRows.scrollTop = _hudRows.scrollHeight;
  }
  function _hudShowPreflight(res) {
    const el = document.getElementById('__ag3-pf');
    if (!el) return;
    el.innerHTML = res.map(r => `<span class="ag3-pf ${r.cls}">${r.short}</span>`).join('');
  }

  // ══════════════════════════════════════════════════════════════════════
  //  16. مراقبة body.className
  // ══════════════════════════════════════════════════════════════════════
  function _watchBody() {
    if (!document.body) return;
    new MutationObserver(() => {
      const cls = document.body.className;
      if (cls === 'done') {
        if (_state.stallTimer) clearTimeout(_state.stallTimer);
        _state.phase = 'SUCCESS';
        _agLog('SUCCESS', 'Exploit complete!', 'ok');
        _hudSetPhase('SUCCESS ✓', 'ok');
        _hudSetStatus('Jailbreak complete! Kernel access granted.');
        _hudSetRetry(''); _hudSetProgress(100); _clearSession();
        const dot = document.getElementById('__ag3-dot');
        if (dot) { dot.style.background='#00ffa3'; dot.style.boxShadow='0 0 16px #00ffa3'; dot.style.animation='none'; }
      } else if (cls === 'fail') {
        if (_state.phase === 'SUCCESS') return;
        _agLog('FAIL', 'finishUI(false)', 'fail');
        _onFailureDetected('finishUI:FAIL', 'Exploit signaled failure');
      }
    }).observe(document.body, { attributes: true, attributeFilter: ['class'] });
  }

  // ══════════════════════════════════════════════════════════════════════
  //  17. واجهات window العامة
  // ══════════════════════════════════════════════════════════════════════
  window.__agentMark = function (tag, detail) {
    _state.lastMarkTime = Date.now();
    if (_state.phase === 'IDLE' || _state.phase === 'READY' || _state.phase === 'RETRYING') {
      _state.phase = 'RUNNING';
      _state.startTime = _state.startTime || Date.now();
      _hudSetPhase('RUNNING', '');
    }
    const { key: sk, cfg: scfg } = _detectSubPhase(tag);
    if (sk !== _state.subPhase) {
      _state.subPhase = sk; _resetStallTimer(sk);
      const idx = PHASE_ORDER.indexOf(sk);
      if (idx >= 0) _hudSetProgress(idx / (PHASE_ORDER.length - 1) * 100);
      _hudSetStatus(`[${scfg.label}] ${String(detail||'').slice(0,80)}`);
    }
    const cls = _tagCls(tag);
    _agLog(tag, detail, cls);
    if (BAD_RE.test(tag) || BAD_RE.test(String(detail))) _onFailureDetected(tag, String(detail||''));
    else if (DONE_RE.test(tag) || DONE_RE.test(String(detail))) {
      _state.phase = 'SUCCESS'; _hudSetPhase('SUCCESS ✓','ok'); _hudSetProgress(100); _clearSession();
    }
  };

  // ── Kernel Fuzzer State ───────────────────────────────────────────────
  const _fuzzState = {
    running: false,
    complete: false,
    found: 0,
    missed: 0,
    discovered: {},
    abortCtrl: null,
  };

  window.__agentAPI = {
    getGcPause:       () => _state.recommendedGcPause,
    getStrategy:      () => _state.strategy,
    getSlots:         () => _state.currentSlots,
    getDrain:         () => _state.currentDrain,
    getFirmware:      () => ({
      raw: _state.rawFw, resolved: _state.fwDetected,
      borrowed: _state.fwBorrowed, borrowedFrom: _state.fwBorrowedFrom,
      confidence: _state.fwConfidence, supported: _state.fwSupported,
    }),
    getOffsetOverride: () => window.__agentFWOverride || null,
    reportPhase:      (name, data) => {
      _agLog('PHASE:'+name, data||'', 'ok');
      _state.subPhase = name.toUpperCase().split('-')[0];
      _resetStallTimer(_state.subPhase);
    },
    log: (tag, detail, cls) => _agLog(tag, detail, cls),

    // ── Kernel Fuzzer API ───────────────────────────────────────────────
    /**
     * يُشغَّل من jb.js بعد تأسيس kernel ARW عند إصدار غير مدعوم.
     *
     * @param {Function} rd8fn    - rd8(lo, hi) → [lo32, hi32]
     * @param {number}   kbaseLo  - kernel base address low 32bit
     * @param {number}   kbaseHi  - kernel base address high 32bit
     * @param {Object}   borrowed - offsets مستعارة من ps4_offsets.js
     * @returns {Promise<Object>} mergedOffsets مع الـ discovered offsets
     */
    startKernelFuzz: async (rd8fn, kbaseLo, kbaseHi, borrowed) => {
      // لا تشغّل إذا الإصدار مدعوم أصلاً
      if (_state.fwSupported && !_state.fwBorrowed) {
        _agLog('FUZZER', 'FW is natively supported — skipping kernel fuzz', 'ok');
        return borrowed;
      }
      if (_fuzzState.running) {
        _agLog('FUZZER', 'Already running — ignoring duplicate call', 'warn');
        return borrowed;
      }

      _fuzzState.running  = true;
      _fuzzState.complete = false;
      _fuzzState.abortCtrl = new AbortController();

      _hudSetPhase('FUZZING KERNEL', 'fix');
      _hudSetStatus('🔍 Scanning kernel memory for real offsets...');
      _agLog('FUZZER', `Kernel fuzz starting — base=0x${kbaseHi.toString(16)}${kbaseLo.toString(16).padStart(8,'0')}`, 'fix');

      try {
        // تحميل الـ fuzzer ديناميكياً (لا يحمّل إذا غير مدعوم)
        const mod = await import('./kernel_fuzzer.js').catch(() => null);
        if (!mod || !mod.runKernelFuzz) {
          _agLog('FUZZER', 'kernel_fuzzer.js not loaded — static fallback only', 'warn');
          _fuzzState.running = false;
          return borrowed;
        }

        const result = await mod.runKernelFuzz({
          rd8fn,
          kbaseLo, kbaseHi,
          borrowedOffsets: borrowed,
          signal: _fuzzState.abortCtrl.signal,
          stepSize: 8,
          onProgress: (p) => {
            _hudSetStatus(`🔍 [FUZZ:${p.key}] ${p.pct}% (${p.steps}/${p.maxSteps} steps)`);
          },
        });

        _fuzzState.found      = result.found;
        _fuzzState.missed     = result.missed;
        _fuzzState.discovered = result.discovered;
        _fuzzState.complete   = true;
        _fuzzState.running    = false;

        const summary = `✓ Fuzzer: ${result.found} found, ${result.missed} missed in ${result.elapsedSec}s`;
        _agLog('FUZZER', summary, result.found > 0 ? 'ok' : 'warn');
        _hudSetStatus(summary);

        if (result.found > 0) {
          _hudSetPhase('FUZZ OK', 'ok');
        } else {
          _hudSetPhase('FUZZ PARTIAL', 'warn');
        }

        return result.mergedOffsets;

      } catch (err) {
        _fuzzState.running  = false;
        _fuzzState.complete = true;
        _agLog('FUZZER', 'Error: ' + (err.message || err), 'fail');
        _hudSetPhase('FUZZ ERR', 'fail');
        return borrowed;
      }
    },

    /** إلغاء الـ fuzzing إذا كان يعمل */
    abortKernelFuzz: () => {
      if (_fuzzState.abortCtrl) _fuzzState.abortCtrl.abort();
      _fuzzState.running = false;
      _agLog('FUZZER', 'Aborted by user/agent', 'warn');
    },

    /** حالة الـ fuzzer */
    getFuzzerState:    () => ({ ..._fuzzState }),
    isFuzzingComplete: () => _fuzzState.complete,
    getFuzzedOffsets:  () => ({ ..._fuzzState.discovered }),
  };

  window.__agentDump = function () {
    return {
      agentVersion: AGENT_CFG.version,
      firmware: { raw:_state.rawFw, resolved:_state.fwDetected,
        borrowed:_state.fwBorrowed, borrowedFrom:_state.fwBorrowedFrom,
        confidence:_state.fwConfidence ? _state.fwConfidence.label : null,
        supported:_state.fwSupported },
      phase: _state.phase, subPhase: _state.subPhase,
      retries: _state.retryCount, strategy: _state.strategy,
      timing: window.__agentTiming || {},
      slots: _state.currentSlots, drain: _state.currentDrain,
      benchmark: { ms:_state.benchmarkMs, stability:_state.stabilityScore },
      failures: _state.failureLog,
      elapsedSec: _state.startTime ? Math.round((Date.now()-_state.startTime)/1000) : 0,
      recentEvents: _state.eventLog.slice(-30),
    };
  };

  // ══════════════════════════════════════════════════════════════════════
  //  18. Bootstrap
  // ══════════════════════════════════════════════════════════════════════
  function _bootstrap() {
    _loadSession();
    window.addEventListener('beforeunload', _saveSession);
    window.addEventListener('error', e => {
      const msg = `${e.message} @ ${e.filename||'?'}:${e.lineno||0}`;
      _agLog('JS-ERR', msg, 'fail'); _onFailureDetected('JS_ERROR', msg);
    });
    window.addEventListener('unhandledrejection', e => {
      const msg = String(e.reason ? (e.reason.message || e.reason) : 'Unhandled Promise');
      _agLog('PROMISE', msg, 'fail'); _onFailureDetected('PROMISE_ERROR', msg);
    });

    const init = () => {
      _createHud();
      _watchBody();

      // ── اكتشاف الفيرموير ──────────────────────────────────────────────
      const fwParsed = _parseFirmwareFromUA(navigator.userAgent);

      if (!fwParsed) {
        _agLog('FW', 'Non-PS4 UA — debug/dev mode', 'warn');
        _hudSetFirmware('DEV/PC', { label:'DEBUG', color:'#778' }, false, null);
        _hudSetPhase('DEBUG MODE', 'warn');
        _hudSetStatus('Non-PS4 browser — monitoring mode only.');
      } else {
        _state.rawFw = fwParsed.raw;
        _state.fwNum = fwParsed.num;
        _agLog('FW', `Detected: ${fwParsed.raw} (num=${fwParsed.num})`, 'ok');

        const res = _resolveOffsets(fwParsed);
        _state.fwDetected     = res.resolvedKey;
        _state.fwBorrowed     = res.borrowed;
        _state.fwBorrowedFrom = res.borrowed ? res.resolvedKey : null;
        _state.fwConfidence   = res.confidence;
        _state.fwSupported    = !res.borrowed || res.confidence.score >= 70;

        _hudSetFirmware(
          fwParsed.raw + (res.borrowed ? ` → ${res.resolvedKey}` : ''),
          res.confidence, res.borrowed, res.borrowed ? res.notes : null
        );

        if (res.borrowed) {
          _agLog('FW-BORROW', res.notes, 'warn');
          _agLog('FW-BORROW', `Confidence: ${res.confidence.label} (${res.confidence.score}%) — proceeding`, 'warn');
          _injectBorrowedOffsets(res.resolvedKey, fwParsed);
          if (res.confidence.score < 70) {
            _state.recommendedGcPause += 60;
            _agLog('FW-SAFETY', 'Low confidence → +60ms GC safety margin', 'warn');
          }
        } else {
          _agLog('FW', res.notes, 'ok');
        }
      }

      _runPreflight();
      _runBenchmark();
      _updateMetrics();

      _hudSetPhase('READY', '');
      _hudSetStatus(
        _state.fwBorrowed
          ? `⚠ Borrowed offsets from ${_state.fwBorrowedFrom} — success rate may vary`
          : 'Ready. Awaiting exploit bootstrap...'
      );
      _agLog('AGENT', `v${AGENT_CFG.version} ready | FW=${_state.rawFw||'N/A'} | Retry=${_state.retryCount}/${AGENT_CFG.maxRetries}`, 'ok');
    };

    if (document.body) init();
    else document.addEventListener('DOMContentLoaded', init);
  }

  _bootstrap();

})();
