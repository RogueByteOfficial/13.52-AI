/**
 * kernel_fuzzer.js — PS4 Kernel Offset Discovery Engine
 * ==========================================================================
 * يعمل بعد تأسيس الـ ARW primitive (arbitrary kernel read/write).
 * عند إصدار غير مدعوم، يفحص الـ kernel memory بحثاً عن signatures
 * معروفة لإيجاد الـ offsets الحقيقية.
 *
 * كيف يعمل:
 *   1. يأخذ الـ offsets المستعارة كنقطة بداية
 *   2. لكل offset مهم، يفحص نافذة ± delta حوله
 *   3. يتحقق من وجود signature بايت معروف في الذاكرة
 *   4. عند التأكيد — يحدث window.__agentFWOverride
 *   5. يُبلّغ الـ Agent بالنتائج
 *
 * الاستخدام (من jb.js بعد KERNEL phase):
 *   import { KernelFuzzer } from './kernel_fuzzer.js';
 *   const fz = new KernelFuzzer(kread8, kbase, borrowedOffsets);
 *   const discovered = await fz.run();
 * ==========================================================================
 */

'use strict';

// ══════════════════════════════════════════════════════════════════════════
//  A. تعريفات الـ Signatures الثابتة للـ PS4 Kernel
//
//  كل signature تحتوي على:
//    - key: اسم الـ offset (مثل 'k_sysent')
//    - scanWindow: نطاق البحث ± حول القيمة المستعارة
//    - align: محاذاة العنوان (bytes)
//    - verify: دالة تستقبل rd8(addr) وترجع true إذا وجدت signature صحيحة
//    - critical: إذا true → الفشل يوقف الـ fuzzing
// ══════════════════════════════════════════════════════════════════════════

const KERNEL_SIGNATURES = [

  // ────────────────────────────────────────────────────────────────────
  //  k_sysent — جدول syscalls
  //  البنية: struct sysent { u_int sy_narg; ... sy_call: ptr, ... }
  //  تعرف: الـ entry الأول (syscall 0 = nosys) له sy_call يشير
  //  لدالة kern_nosys في الـ kernel text segment
  //  الميزة: sy_narg للأول = 0، والـ pointer يجب أن يكون kernel VA
  // ────────────────────────────────────────────────────────────────────
  {
    key: 'k_sysent',
    desc: 'Syscall table (sysent[0] = nosys, sy_narg=0)',
    scanWindow: 0x80000,    // ± 512KB حول القيمة المستعارة
    align: 0x10,
    critical: true,
    verify: (lo, hi, rd8fn) => {
      // sysent[0].sy_narg يجب أن يكون 0 (nosys لا يأخذ args)
      const [n0, n1] = rd8fn(lo, hi);
      if (n0 !== 0 && n0 !== 1) return false;  // sy_narg

      // sysent[0].sy_call = pointer لـ nosys — يجب أن يكون kernel VA
      // على PS4: kernel text في 0xFFFFFFFF80000000+
      const [p0, p1] = rd8fn(lo + 8, hi);
      if (p1 < 0xffff8000 >>> 0) return false;  // ليس kernel space

      // sysent[1].sy_narg = 1 (exit) — تحقق إضافي
      // حجم كل sysent entry = 0x30 bytes على FreeBSD PS4
      const [n2] = rd8fn(lo + 0x30, hi);
      return (n2 === 1 || n2 === 0);
    },
    confidence: 'HIGH',
  },

  // ────────────────────────────────────────────────────────────────────
  //  k_sysent_661 — نسخة 6.61 من الجدول (alternate entry point)
  //  على بعض الإصدارات يوجد sysent آخر للـ compatibility layer
  // ────────────────────────────────────────────────────────────────────
  {
    key: 'k_sysent_661',
    desc: 'Alternate sysent table (6.61 compat)',
    scanWindow: 0x80000,
    align: 0x10,
    critical: false,
    verify: (lo, hi, rd8fn) => {
      // نفس منطق k_sysent لكن أقل صرامة
      const [p0, p1] = rd8fn(lo + 8, hi);
      return p1 >= (0xffff8000 >>> 0);
    },
    confidence: 'MEDIUM',
  },

  // ────────────────────────────────────────────────────────────────────
  //  k_idt_rsvd — IDT entry محجوز (descriptor)
  //  البنية: IDT entry = 16 bytes على x86-64
  //  الميزة: الـ entry المحجوز له type = 0xEE (386 Interrupt Gate)
  //  والـ DPL = 3 (userspace accessible)
  //  كلمة الوصف: [present=1][DPL=11][type=01110] = 0xEE في byte العلوي
  // ────────────────────────────────────────────────────────────────────
  {
    key: 'k_idt_rsvd',
    desc: 'IDT reserved entry (type=0xEE, DPL=3)',
    scanWindow: 0x100000,   // ± 1MB
    align: 0x10,            // IDT entries محاذاة 16
    critical: false,
    verify: (lo, hi, rd8fn) => {
      const [w0, w1] = rd8fn(lo, hi);
      // high word يحتوي على type/DPL/P في bit 8-15
      const typeField = (w1 >> 8) & 0xFF;
      return typeField === 0xEE || typeField === 0x8E;
    },
    confidence: 'MEDIUM',
  },

  // ────────────────────────────────────────────────────────────────────
  //  k_prison0 — بنية prison رئيسية
  //  البنية: struct prison { pr_ref=1, pr_uref=1, pr_flags=..., pr_id=0 }
  //  prison0 هو الـ root prison — pr_id يجب أن يكون 0
  //  وpr_ref يجب أن يكون >= 1
  // ────────────────────────────────────────────────────────────────────
  {
    key: 'k_prison0',
    desc: 'prison0 struct (pr_id=0, pr_ref>=1)',
    scanWindow: 0x200000,   // ± 2MB (يوجد في kernel data segment)
    align: 8,
    critical: false,
    verify: (lo, hi, rd8fn) => {
      // pr_ref (offset 0) — refcount >= 1
      const [ref] = rd8fn(lo, hi);
      if (ref < 1 || ref > 0xFFFF) return false;

      // pr_uref (offset 4) — user refcount
      // pr_flags (offset 8)
      // pr_id (offset 0x10 تقريباً) يجب أن يكون 0
      const [id] = rd8fn(lo + 0x10, hi);
      return id === 0;
    },
    confidence: 'LOW',    // بنية شائعة، قد تعطي false positives
  },

  // ────────────────────────────────────────────────────────────────────
  //  k_jmp_rsi — gadget: jmp rsi (opcodes: FF E6)
  //  نبحث عن FF E6 C3 أو FF E6 في الـ kernel text
  // ────────────────────────────────────────────────────────────────────
  {
    key: 'k_jmp_rsi',
    desc: 'Gadget: JMP RSI (0xFF 0xE6)',
    scanWindow: 0x40000,    // ± 256KB (gadgets قريبة من بعضها)
    align: 1,               // لا محاذاة — gadgets في أي مكان
    critical: false,
    verify: (lo, hi, rd8fn) => {
      const [bytes] = rd8fn(lo, hi);
      // FF E6 = JMP RSI
      return (bytes & 0xFFFF) === 0xE6FF;
    },
    confidence: 'HIGH',
  },

  // ────────────────────────────────────────────────────────────────────
  //  k_evf_cv — condition variable في kernel
  //  بنية kcondvar_t: cv_waiters (int) + cv_description (pointer)
  //  الـ description هو string في kernel text → يشير للـ text segment
  // ────────────────────────────────────────────────────────────────────
  {
    key: 'k_evf_cv',
    desc: 'evf condition variable (cv_description ptr)',
    scanWindow: 0x100000,
    align: 8,
    critical: false,
    verify: (lo, hi, rd8fn) => {
      // cv_description يشير لـ kernel text (string)
      const [p0, p1] = rd8fn(lo + 4, hi);
      return p1 >= (0xffff8000 >>> 0) && p0 !== 0;
    },
    confidence: 'LOW',
  },

];

// ══════════════════════════════════════════════════════════════════════════
//  B. الـ KernelFuzzer Class
// ══════════════════════════════════════════════════════════════════════════

export class KernelFuzzer {
  /**
   * @param {Function} rd8fn   - دالة تقرأ 8 bytes: rd8fn(lo, hi) → [lo32, hi32]
   * @param {number}   kbaseLo - الـ low 32bit من kernel base address
   * @param {number}   kbaseHi - الـ high 32bit من kernel base address
   * @param {Object}   borrowedOffsets - الـ offsets المستعارة من ps4_offsets.js
   * @param {Object}   [options]
   */
  constructor(rd8fn, kbaseLo, kbaseHi, borrowedOffsets, options = {}) {
    this._rd8   = rd8fn;
    this._kbLo  = kbaseLo  >>> 0;
    this._kbHi  = kbaseHi  >>> 0;
    this._borrowed = borrowedOffsets || {};
    this._opts  = {
      stepSize: options.stepSize || 8,       // خطوة الـ scan بالـ bytes
      maxStepsPerOffset: options.maxStepsPerOffset || 16000, // حد الـ scan
      yieldEvery: options.yieldEvery || 200, // كل كم خطوة نتيح للـ event loop
      onProgress: options.onProgress || null,// callback للتقدم
      signal: options.signal || null,        // AbortSignal للإلغاء
    };
    this._discovered = {};  // { key: offset_from_kbase }
    this._log = [];
  }

  // ────────────────────────────────────────────────────────────────────
  //  rd8 wrapper مع حماية من crashes
  // ────────────────────────────────────────────────────────────────────
  _safeRd8(lo, hi) {
    try {
      return this._rd8(lo >>> 0, hi >>> 0);
    } catch (e) {
      return [0, 0];  // قراءة فاشلة → صفر
    }
  }

  // ────────────────────────────────────────────────────────────────────
  //  تحويل offset من kbase إلى عنوان مطلق [lo, hi]
  // ────────────────────────────────────────────────────────────────────
  _addrOf(offset) {
    const lo = (this._kbLo + (offset & 0xFFFFFFFF)) >>> 0;
    const carry = (this._kbLo + (offset & 0xFFFFFFFF)) > 0xFFFFFFFF ? 1 : 0;
    const hi = (this._kbHi + ((offset >>> 0) >>> 32 | 0) + carry) >>> 0;
    return [lo, hi];
  }

  // ────────────────────────────────────────────────────────────────────
  //  تحويل عنوان مطلق إلى offset من kbase
  // ────────────────────────────────────────────────────────────────────
  _offsetFrom(lo, hi) {
    let offLo = (lo - this._kbLo) >>> 0;
    // تقريب — نفترض أن الـ hi32 متماثل أو يختلف بـ 1
    return offLo;
  }

  // ────────────────────────────────────────────────────────────────────
  //  فحص signature واحدة في عنوان محدد
  // ────────────────────────────────────────────────────────────────────
  _checkSignature(sig, lo, hi) {
    return sig.verify(lo, hi, (addrLo, addrHi) => this._safeRd8(addrLo, addrHi));
  }

  // ────────────────────────────────────────────────────────────────────
  //  scan نافذة لإيجاد offset واحد
  // ────────────────────────────────────────────────────────────────────
  async _scanForOffset(sig) {
    const borrowedOff = this._borrowed[sig.key];
    if (!borrowedOff && borrowedOff !== 0) {
      this._emit(sig.key, 'SKIP', `No borrowed offset for ${sig.key}`);
      return null;
    }

    const step   = Math.max(1, sig.align || this._opts.stepSize);
    const window = sig.scanWindow;
    const maxSteps = Math.min(
      Math.ceil((window * 2) / step),
      this._opts.maxStepsPerOffset
    );

    this._emit(sig.key, 'SCAN-START',
      `Scanning ±0x${window.toString(16)} around 0x${borrowedOff.toString(16)} (${maxSteps} steps)`);

    // نبدأ من المركز ونتوسع للخارج (Spiral scan — أفضل شانس نجاح مبكر)
    let found = null;
    let stepsChecked = 0;

    for (let delta = 0; delta <= window; delta += step) {
      // تحقق من إلغاء
      if (this._opts.signal && this._opts.signal.aborted) {
        this._emit(sig.key, 'ABORTED', 'Scan cancelled');
        return null;
      }

      // فحص +delta
      for (const direction of [1, -1]) {
        const candidateOff = borrowedOff + (delta * direction);
        if (candidateOff < 0) continue;

        const [cLo, cHi] = this._addrOf(candidateOff);

        if (this._checkSignature(sig, cLo, cHi)) {
          found = candidateOff;
          this._emit(sig.key, 'FOUND',
            `0x${candidateOff.toString(16)} (Δ=${delta >= 0 ? '+' : ''}${(delta * direction).toString(16)}) confidence=${sig.confidence}`);
          break;
        }
        stepsChecked++;
      }

      if (found !== null) break;

      // yield للـ event loop كل N خطوات (لا نجمد الصفحة)
      if (stepsChecked % this._opts.yieldEvery === 0) {
        await new Promise(r => setTimeout(r, 0));
        if (this._opts.onProgress) {
          this._opts.onProgress({
            key: sig.key,
            steps: stepsChecked,
            maxSteps,
            pct: Math.round((stepsChecked / maxSteps) * 100),
          });
        }
      }

      if (stepsChecked >= maxSteps) {
        this._emit(sig.key, 'EXHAUSTED', `Scanned ${stepsChecked} steps — not found`);
        break;
      }
    }

    return found;
  }

  // ────────────────────────────────────────────────────────────────────
  //  الدالة الرئيسية: تشغيل الـ fuzzing الكامل
  // ────────────────────────────────────────────────────────────────────
  async run() {
    this._emit('FUZZER', 'START',
      `Kernel fuzzing — kbase=0x${this._kbHi.toString(16)}:${this._kbLo.toString(16)}`);

    const startTime = Date.now();
    let found = 0, missed = 0, skipped = 0;

    for (const sig of KERNEL_SIGNATURES) {
      this._emit(sig.key, 'TRY', sig.desc);

      const offset = await this._scanForOffset(sig);

      if (offset !== null) {
        this._discovered[sig.key] = offset;
        found++;

        // حدث الـ Agent فوراً
        this._updateAgentOverride();
      } else {
        if (sig.critical) {
          this._emit(sig.key, 'CRITICAL-MISS', `Critical offset missing — exploit may fail`);
        }
        missed++;
      }
    }

    const elapsed = Math.round((Date.now() - startTime) / 1000);
    this._emit('FUZZER', 'DONE',
      `Complete: ${found} found, ${missed} missed, ${skipped} skipped in ${elapsed}s`);

    // نتائج نهائية
    return {
      discovered: { ...this._discovered },
      found,
      missed,
      skipped,
      elapsedSec: elapsed,
      log: this._log,
    };
  }

  // ────────────────────────────────────────────────────────────────────
  //  تحديث window.__agentFWOverride بالـ offsets المكتشفة (live update)
  // ────────────────────────────────────────────────────────────────────
  _updateAgentOverride() {
    if (typeof window === 'undefined') return;

    // دمج مع الـ override الموجود
    const existing = window.__agentFWOverride || {};
    window.__agentFWOverride = {
      ...existing,
      fuzzedOffsets: { ...(existing.fuzzedOffsets || {}), ...this._discovered },
      fuzzedAt: Date.now(),
      fuzzedCount: Object.keys(this._discovered).length,
    };

    // إبلاغ الـ Agent API
    if (window.__agentAPI && window.__agentAPI.log) {
      const keys = Object.keys(this._discovered);
      window.__agentAPI.log('FUZZER',
        `Live: discovered ${keys.length} offsets [${keys.slice(-3).join(', ')}]`, 'ok');
    }
  }

  // ────────────────────────────────────────────────────────────────────
  //  تسجيل الأحداث
  // ────────────────────────────────────────────────────────────────────
  _emit(key, event, detail) {
    const entry = { key, event, detail, ts: Date.now() };
    this._log.push(entry);

    // إبلاغ الـ Agent
    if (typeof window !== 'undefined' && window.__agentMark) {
      try {
        window.__agentMark(`FUZZ-${key}`, `[${event}] ${detail}`);
      } catch(e) {}
    }

    if (typeof window !== 'undefined' && window.__agentAPI && window.__agentAPI.log) {
      const cls = event.includes('FOUND') ? 'ok'
        : event.includes('MISS') || event.includes('EXHAUSTED') ? 'fail'
        : event.includes('ABORTED') ? 'warn'
        : 'fix';
      try { window.__agentAPI.log(`FUZZ:${key}`, `[${event}] ${detail}`, cls); } catch(e) {}
    }
  }

  // ────────────────────────────────────────────────────────────────────
  //  دمج الـ offsets المكتشفة مع الـ offsets الأصلية
  //  المكتشفة لها أولوية أعلى
  // ────────────────────────────────────────────────────────────────────
  getMergedOffsets(baseOffsets) {
    return {
      ...baseOffsets,
      ...this._discovered,
      __fuzzer_merged: true,
      __fuzzer_discovered_keys: Object.keys(this._discovered),
    };
  }
}

// ══════════════════════════════════════════════════════════════════════════
//  C. دالة مساعدة: تكامل سهل من jb.js
// ══════════════════════════════════════════════════════════════════════════

/**
 * runKernelFuzz — الطريقة الموصى بها للاستخدام من jb.js
 *
 * تُستدعى بعد تأسيس kernel ARW ومعرفة kbase.
 *
 * @param {Object} params
 *   - rd8fn:          دالة rd8 من rpc_worker (عبر callWorker)
 *   - kbaseLo/Hi:     kernel base address
 *   - borrowedOffsets: الـ offsets المستعارة من ps4_offsets.js
 *   - onProgress:     callback اختياري للتقدم
 *   - signal:         AbortSignal اختياري للإلغاء
 *
 * @returns {Object} { mergedOffsets, discovered, found, missed, elapsed }
 */
export async function runKernelFuzz({
  rd8fn,
  kbaseLo,
  kbaseHi,
  borrowedOffsets,
  onProgress = null,
  signal = null,
  stepSize = 8,
}) {
  // تحقق أن ARW جاهز
  if (typeof rd8fn !== 'function') {
    throw new Error('kernel_fuzzer: rd8fn is required (kernel ARW not established)');
  }

  // تحقق أن الإصدار فعلاً غير مدعوم (لا نشغل fuzzer بلا سبب)
  const isUnsupported = (
    typeof window !== 'undefined' &&
    window.__agentFWOverride &&
    window.__agentFWOverride.borrowed === true
  );

  if (!isUnsupported) {
    if (window.__agentAPI) {
      window.__agentAPI.log('FUZZER', 'Firmware is supported — skipping fuzzing', 'ok');
    }
    return { mergedOffsets: borrowedOffsets, discovered: {}, found: 0, missed: 0, skipped: 'supported_fw' };
  }

  // شغّل الـ fuzzer
  if (window.__agentAPI) {
    window.__agentAPI.log('FUZZER', 'Starting kernel offset discovery for unsupported FW...', 'fix');
  }

  const fuzzer = new KernelFuzzer(rd8fn, kbaseLo, kbaseHi, borrowedOffsets, {
    stepSize,
    onProgress,
    signal,
  });

  const result = await fuzzer.run();

  const mergedOffsets = fuzzer.getMergedOffsets(borrowedOffsets);

  // تحديث نهائي لـ Agent
  if (typeof window !== 'undefined' && window.__agentFWOverride) {
    window.__agentFWOverride.fuzzingComplete = true;
    window.__agentFWOverride.fuzzingResult = {
      found: result.found,
      missed: result.missed,
      elapsedSec: result.elapsedSec,
    };
  }

  return {
    mergedOffsets,
    discovered: result.discovered,
    found: result.found,
    missed: result.missed,
    elapsedSec: result.elapsedSec,
    log: result.log,
  };
}

// ══════════════════════════════════════════════════════════════════════════
//  D. إضافة fuzzer state لـ window.__agentAPI
// ══════════════════════════════════════════════════════════════════════════
if (typeof window !== 'undefined' && window.__agentAPI) {
  window.__agentAPI.getFuzzerState = () => window.__agentFWOverride?.fuzzedOffsets || null;
  window.__agentAPI.isFuzzingComplete = () => !!window.__agentFWOverride?.fuzzingComplete;
}
