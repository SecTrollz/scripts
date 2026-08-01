// ==UserScript==
// @name         Blackjack Advisor (DOM-read + OCR, mobile) — with error log
// @namespace    evan.local.blackjack-advisor
// @version      6.0.0
// @description  Glassmorphism overlay. Reads the table from what's visually rendered — DOM elements when present, OCR-on-canvas fallback when the table is drawn in a game engine. Never reads internal game state. Tracks Hi-Lo count, shows recommended move + bet. Advisory only — never clicks buttons or sets bet fields.
// @match        https://example.com/*
// @run-at       document-idle
// @grant        none
// ==/UserScript==
(function () {
  'use strict';

  // --- error logging (UI accessible) --------------------------------------
  const MAX_LOG_ENTRIES = 60;
  const logEntries = [];

  function logError(msg, err = null) {
    const ts = new Date().toLocaleTimeString();
    const entry = `[${ts}] ${msg}` + (err ? `\n${err.stack || err}` : '');
    console.error('[blackjack-advisor]', entry);
    logEntries.push(entry);
    if (logEntries.length > MAX_LOG_ENTRIES) logEntries.shift();
    if (logTextArea) {
      logTextArea.value = logEntries.join('\n\n');
      logTextArea.scrollTop = logTextArea.scrollHeight;
    }
    if (logToggleBtn) {
      logToggleBtn.style.borderColor = '#f87171';
      setTimeout(() => { if (logToggleBtn) logToggleBtn.style.borderColor = 'rgba(255,255,255,0.18)'; }, 2000);
    }
  }

  let logPanel, logTextArea, logToggleBtn;

  try {
    run();
  } catch (err) {
    console.error('[blackjack-advisor] Fatal startup error:', err);
    try {
      const fallback = document.createElement('div');
      fallback.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:2147483647;background:red;color:white;padding:10px;border-radius:8px;font-size:12px;';
      fallback.textContent = 'Blackjack Advisor crashed. Check console.';
      document.documentElement.appendChild(fallback);
    } catch (e) { /* nothing else we can do */ }
  }

  function run() {

    // ---- CONFIGURATION ---------------------------------------------------------
    const SURRENDER_ALLOWED = false;
    const POLL_MS = 700;

    // ---- PERSISTENT STORAGE (storage-safe) --------------------------------
    const memoryStore = {};
    const safeStorage = {
      get(key) {
        try { return localStorage.getItem(key); } catch (e) { return memoryStore[key] ?? null; }
      },
      set(key, val) {
        try { localStorage.setItem(key, val); } catch (e) { memoryStore[key] = val; }
      },
      remove(key) {
        try { localStorage.removeItem(key); } catch (e) { delete memoryStore[key]; }
      },
    };

    const CONFIRM_KEY = 'blackjackAdvisor_confirm_' + window.location.hostname;
    const storedConfirm = safeStorage.get(CONFIRM_KEY); // 'true' | 'false' | null

    // ---- GUARD: prevent multiple panels -----------------------------------
    if (document.getElementById('bj-advisor-panel')) return;

    // ---- BASIC STRATEGY TABLES --------------------------------------------------
    const HARD = {
      5: 'HHHHHHHHHH', 6: 'HHHHHHHHHH', 7: 'HHHHHHHHHH', 8: 'HHHHHHHHHH',
      9: 'HDDDDHHHHH', 10: 'DDDDDDDDHH', 11: 'DDDDDDDDDH',
      12: 'HHSSSHHHHH', 13: 'SSSSSHHHHH', 14: 'SSSSSHHHHH',
      15: 'SSSSSHHHHH', 16: 'SSSSSHHHHH', 17: 'SSSSSSSSSS',
    };
    const SOFT = {
      13: 'HHHDDHHHHH', 14: 'HHHDDHHHHH', 15: 'HHDDDHHHHH', 16: 'HHDDDHHHHH',
      17: 'HDDDDHHHHH', 18: 'SDDDDSSHHH', 19: 'SSSSSSSSSS', 20: 'SSSSSSSSSS',
    };
    const PAIRS = {
      2: 'PPPPPPHHHH', 3: 'PPPPPPHHHH', 4: 'HHHPPHHHHH', 5: 'DDDDDDDDHH',
      6: 'PPPPPHHHHH', 7: 'PPPPPPHHHH', 8: 'PPPPPPPPPP', 9: 'PPPPPSPPSS',
      10: 'SSSSSSSSSS', 11: 'PPPPPPPPPP',
    };
    const COLS = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'A'];
    function upIdx(up) {
      const v = up === 'A' ? 'A' : (['10', 'J', 'Q', 'K'].includes(up) ? '10' : up);
      return COLS.indexOf(v);
    }
    function rankValue(r) {
      if (r === 'A') return 11;
      if (['10', 'J', 'Q', 'K'].includes(r)) return 10;
      return Number(r);
    }
    function decode(code) {
      switch (code) {
        case 'H': return { move: 'HIT', why: 'basic strategy' };
        case 'S': return { move: 'STAND', why: 'basic strategy' };
        case 'D': return { move: 'DOUBLE', why: 'basic strategy' };
        case 'P': return { move: 'SPLIT', why: 'basic strategy' };
        default: return { move: 'HIT', why: 'basic strategy' };
      }
    }

    const DEVIATIONS = [
      { type: 'insurance', tc: 3, cmp: 'gte', action: 'INSURANCE' },
      { type: 'hard', total: 16, vs: '10', tc: 0, cmp: 'gte', action: 'STAND' },
      { type: 'hard', total: 15, vs: '10', tc: 4, cmp: 'gte', action: 'STAND' },
      { type: 'pair', rank: 10, vs: '5', tc: 5, cmp: 'gte', action: 'SPLIT' },
      { type: 'pair', rank: 10, vs: '6', tc: 4, cmp: 'gte', action: 'SPLIT' },
      { type: 'hard', total: 9, vs: '2', tc: 1, cmp: 'gte', action: 'DOUBLE' },
      { type: 'hard', total: 16, vs: '9', tc: 5, cmp: 'gte', action: 'STAND' },
      { type: 'hard', total: 10, vs: '10', tc: 4, cmp: 'gte', action: 'DOUBLE' },
      { type: 'hard', total: 13, vs: '2', tc: -1, cmp: 'lte', action: 'HIT' },
      { type: 'hard', total: 12, vs: '2', tc: 3, cmp: 'gte', action: 'STAND' },
      { type: 'hard', total: 12, vs: '3', tc: 2, cmp: 'gte', action: 'STAND' },
      { type: 'hard', total: 11, vs: 'A', tc: 1, cmp: 'gte', action: 'DOUBLE' },
      { type: 'hard', total: 9, vs: '7', tc: 3, cmp: 'gte', action: 'DOUBLE' },
      { type: 'hard', total: 13, vs: '3', tc: -2, cmp: 'lte', action: 'HIT' },
      { type: 'hard', total: 12, vs: '4', tc: 0, cmp: 'lte', action: 'HIT' },
      { type: 'hard', total: 12, vs: '5', tc: -2, cmp: 'lte', action: 'HIT' },
      { type: 'hard', total: 12, vs: '6', tc: -1, cmp: 'lte', action: 'HIT' },
      { type: 'hard', total: 14, vs: '10', tc: 3, cmp: 'gte', action: 'SURRENDER', requiresSurrender: true },
      { type: 'hard', total: 15, vs: '9', tc: 2, cmp: 'gte', action: 'SURRENDER', requiresSurrender: true },
      { type: 'hard', total: 15, vs: 'A', tc: 1, cmp: 'gte', action: 'SURRENDER', requiresSurrender: true },
    ];

    function applyDeviation(base, kind, ref, up, tc) {
      for (const d of DEVIATIONS) {
        if (d.requiresSurrender && !SURRENDER_ALLOWED) continue;
        if (d.type !== kind) continue;
        if (kind === 'hard' && (d.total !== ref || d.vs !== up)) continue;
        if (kind === 'pair' && (d.rank !== ref || d.vs !== up)) continue;
        const hit = d.cmp === 'gte' ? tc >= d.tc : tc <= d.tc;
        if (hit) return { move: d.action, why: `deviation: count ${d.cmp === 'gte' ? 'at or above' : 'at or below'} ${d.tc}` };
      }
      return base;
    }

    function strategy(hand, up, tc) {
      const ci = upIdx(up);
      if (ci === -1) return { move: null, why: 'bad dealer card' };
      let insurance = null;
      if (up === 'A') {
        const dev = applyDeviation({ move: null }, 'insurance', null, null, tc);
        if (dev.move === 'INSURANCE') insurance = 'take insurance';
      }
      if (hand.length === 2 && rankValue(hand[0]) === rankValue(hand[1])) {
        const pr = rankValue(hand[0]) === 11 ? 11 : rankValue(hand[0]);
        const row = PAIRS[pr];
        if (row) {
          const code = row[ci];
          const res = code === 'P' ? { move: 'SPLIT', why: `pair of ${hand[0]}s` } : null;
          const dev = applyDeviation(res || { move: null }, 'pair', pr, up, tc);
          if (dev.move) return { ...dev, insurance };
          if (res) return { ...res, insurance };
        }
      }
      let sum = hand.reduce((a, r) => a + (r === 'A' ? 11 : rankValue(r)), 0);
      let numAces = hand.filter((r) => r === 'A').length;
      let usableAce = false;
      while (sum > 21 && numAces > 0) { sum -= 10; numAces--; }
      if (numAces > 0 && sum <= 21) usableAce = true;
      if (usableAce && sum <= 20) {
        const row = SOFT[Math.max(13, sum)];
        return { ...decode(row ? row[ci] : 'S'), insurance };
      }
      if (sum >= 17) return { ...applyDeviation({ move: 'STAND', why: 'basic strategy' }, 'hard', sum, up, tc), insurance };
      if (sum > 21) return { move: null, why: 'bust', insurance };
      const row = HARD[Math.max(5, Math.min(17, sum))];
      const base = decode(row ? row[ci] : (sum < 5 ? 'H' : 'S'));
      return { ...applyDeviation(base, 'hard', sum, up, tc), insurance };
    }

    // ---- COUNTS ------------------------------------------------------------
    const HILO = { '2': 1, '3': 1, '4': 1, '5': 1, '6': 1, '7': 0, '8': 0, '9': 0, '10': -1, 'J': -1, 'Q': -1, 'K': -1, 'A': -1 };
    let rcHiLo = 0, cardsSeen = 0, decksInShoe = 6;
    function logCard(r) {
      if (r in HILO) { rcHiLo += HILO[r]; cardsSeen++; }
    }
    function decksLeft() { return Math.max(0.5, decksInShoe - cardsSeen / 52); }
    function tcHiLo() { return rcHiLo / decksLeft(); }

    // ---- BET SIZING --------------------------------------------------------
    const VARIANCE = 1.3;
    const KELLY_MULT = 0.5;
    const EDGE_TC_BREAKEVEN = 2;
    let bankroll = 1000, unit = 10, minBet = 10, maxBet = 200, penetrationWarnPct = 75;

    function edgeAt(tc) { return 0.005 * (tc - EDGE_TC_BREAKEVEN); }
    function suggestedBet(tc) {
      const edge = edgeAt(tc);
      const f = Math.max(0, (edge / VARIANCE) * KELLY_MULT);
      const raw = f * bankroll;
      const rounded = Math.round(raw / unit) * unit;
      return Math.min(maxBet, Math.max(minBet, rounded || minBet));
    }
    function validateBetConfig() {
      const problems = [];
      if (unit <= 0) problems.push('unit must be > 0');
      if (minBet <= 0) problems.push('min bet must be > 0');
      if (maxBet < minBet) problems.push('max bet must be ≥ min bet');
      if (bankroll < minBet) problems.push('bankroll is smaller than min bet');
      if (decksInShoe <= 0) problems.push('decks must be > 0');
      if (penetrationWarnPct <= 0 || penetrationWarnPct > 100) problems.push('penetration warning must be 1–100');
      return problems;
    }

    // ---- UI HELPERS ------------------------------------------------------------
    function h(tag, attrs, children) {
      const n = document.createElement(tag);
      for (const k in attrs || {}) {
        if (k === 'style') n.style.cssText = attrs[k];
        else if (k === 'text') n.textContent = attrs[k];
        else n.setAttribute(k, attrs[k]);
      }
      (children || []).forEach((c) => n.appendChild(c));
      return n;
    }

    // ---- GLASSMORPHIC THEME ----------------------------------------------------
    const GLASS_PANEL = 'background:rgba(24,26,32,0.55);backdrop-filter:blur(18px) saturate(160%);-webkit-backdrop-filter:blur(18px) saturate(160%);border:1px solid rgba(255,255,255,0.16);box-shadow:0 8px 32px rgba(0,0,0,0.35),0 0 0 1px rgba(255,255,255,0.06) inset;border-radius:20px;';
    const GLASS_INPUT = 'width:100%;background:rgba(255,255,255,0.08);color:#fff;border:1px solid rgba(255,255,255,0.18);border-radius:30px;padding:8px 12px;font-size:14px;min-height:36px;backdrop-filter:blur(4px);box-sizing:border-box;';
    const GLASS_BTN = 'padding:8px 14px;min-height:36px;font-size:12px;font-weight:600;border-radius:30px;border:1px solid rgba(255,255,255,0.18);background:rgba(255,255,255,0.06);color:#fff;cursor:pointer;backdrop-filter:blur(4px);flex:1;text-align:center;transition:background 0.2s;';

    // ---- TOAST (glassy notification) -------------------------------------------
    let toastTimeout = null;
    function showToast(msg, color = '#4ade80') {
      const existing = document.getElementById('bj-toast');
      if (existing) existing.remove();
      const toast = h('div', {
        id: 'bj-toast',
        style: `${GLASS_PANEL}position:fixed;bottom:calc(env(safe-area-inset-bottom, 0px) + 80px);left:50%;transform:translateX(-50%);z-index:2147483647;padding:10px 20px;color:#fff;font-size:14px;font-weight:600;border-left:4px solid ${color};max-width:90vw;text-align:center;pointer-events:none;transition:opacity 0.3s;`,
        text: msg,
      });
      document.body.appendChild(toast);
      clearTimeout(toastTimeout);
      toastTimeout = setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 400); }, 2500);
    }

    function buildLogUI() {
      logToggleBtn = h('button', { style: GLASS_BTN, text: '📋 Log', title: 'Show error log' });
      logToggleBtn.addEventListener('click', () => {
        if (!logPanel) return;
        const visible = logPanel.style.display === 'block';
        logPanel.style.display = visible ? 'none' : 'block';
        logToggleBtn.style.background = visible ? 'rgba(255,255,255,0.06)' : 'rgba(75,139,180,0.5)';
        if (!visible) {
          logTextArea.value = logEntries.join('\n\n');
          logTextArea.scrollTop = logTextArea.scrollHeight;
        }
      });

      logTextArea = h('textarea', {
        style: 'width:100%;height:120px;background:rgba(0,0,0,0.4);color:#fff;border:1px solid rgba(255,255,255,0.15);border-radius:12px;padding:8px;font-size:11px;resize:none;font-family:monospace;backdrop-filter:blur(4px);box-sizing:border-box;',
        readonly: true,
        text: '',
      });

      const copyBtn = h('button', { style: 'margin-top:4px;' + GLASS_BTN + ';flex:none;width:100%;', text: '📋 Copy logs' });
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(logEntries.join('\n\n')).then(() => {
          showToast('Logs copied', '#4ade80');
        }).catch(() => {
          showToast('Copy failed, see console', '#f87171');
        });
      });

      logPanel = h('div', { style: 'display:none;margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.1);' }, [logTextArea, copyBtn]);

      return [logToggleBtn, logPanel];
    }

    // ---- CORE UI STATE ---------------------------------------------------------
    let panel, badgeDot, badgeText, countEl, moveEl, whyEl, insuranceEl, betEl, statusEl;
    let manualBox, manualHand, manualUp, manualGo;
    let configContainer, configToggle;
    let inBankroll, inUnit, inMin, inMax, inDecks, inPenetration;
    let debugOut, btnDebug, ocrOut, btnOcr;
    let everSeenHand = false;
    let shuffleUnconfirmed = false;
    let countedNodes = new Map();
    let configOpen = false;
    let emptyCardTicks = 0;

    const MOVE_COLORS = { STAND: '#4ade80', HIT: '#eab308', DOUBLE: '#f97316', SPLIT: '#f97316', SURRENDER: '#ef4444' };
    const BADGE_MODES = { WATCHING: '#8a8f98', READING: '#4ade80', UNCONFIRMED: '#f59e0b' };

    function setBadge(mode) {
      try {
        const color = BADGE_MODES[mode] || BADGE_MODES.WATCHING;
        badgeDot.style.background = color;
        badgeDot.style.boxShadow = `0 0 8px ${color}`;
        badgeText.textContent = mode === 'READING' ? 'READING TABLE' : mode === 'UNCONFIRMED' ? 'CONFIRM SHUFFLE' : 'WATCHING';
      } catch (e) { logError('setBadge failed', e); }
    }
    function setMove(move) {
      try {
        moveEl.textContent = move || '—';
        moveEl.style.color = MOVE_COLORS[move] || '#a6ffcb';
      } catch (e) { logError('setMove failed', e); }
    }
    function status(m) {
      try { statusEl.textContent = m; } catch (e) { logError('status update failed', e); }
    }

    // ---- CARD READING (DOM-only — reads what's visually rendered, never
    // internal game/engine objects, and never anything not yet revealed) -------
    function deepQueryAll(selector, root) {
      root = root || document;
      let results = [...root.querySelectorAll(selector)];
      const all = root.querySelectorAll('*');
      for (const el of all) {
        if (el.shadowRoot) results = results.concat(deepQueryAll(selector, el.shadowRoot));
      }
      return results;
    }

    const RANK_RE = /\b(10|[2-9]|[AJQK])\b/i;
    const WORD_RANK = { ACE: 'A', KING: 'K', QUEEN: 'Q', JACK: 'J' };
    function rankFromString(s) {
      if (!s) return null;
      const upper = s.toUpperCase();
      for (const w in WORD_RANK) {
        if (new RegExp(`\\b${w}\\b`).test(upper)) return WORD_RANK[w];
      }
      let m = upper.match(/(?:^|[_\-\/])((?:10|[2-9]|[AJQK]))(?:[SHDC](?=[_.\-]|$)|_?(?:SPADES|HEARTS|DIAMONDS|CLUBS))/);
      if (m) return m[1];
      m = s.match(RANK_RE);
      return m ? m[1].toUpperCase() : null;
    }
    function classStr(n) {
      const c = n.className;
      if (!c) return '';
      return c.baseVal !== undefined ? c.baseVal : c.toString();
    }
    function textRank(n) {
      const attrs = n.getAttribute('data-rank') || n.getAttribute('data-card') || n.getAttribute('data-value') || n.getAttribute('aria-label');
      if (attrs) { const r = rankFromString(attrs); if (r) return r; }
      const text = (n.innerText || '').trim();
      if (text) { const r = rankFromString(text); if (r) return r; }
      const src = n.getAttribute('src') || n.getAttribute('xlink:href') || n.getAttribute('href');
      if (src) { const r = rankFromString(src); if (r) return r; }
      const alt = n.getAttribute('alt');
      if (alt) { const r = rankFromString(alt); if (r) return r; }
      return rankFromString(classStr(n));
    }

    const CARD_SELECTOR = '[class*="card" i], [data-rank], [data-card], img[src*="card" i], img[alt*="card" i], svg use, [class*="playing-card" i], [style*="background-image" i]';

    function readTable() {
      const cardEls = deepQueryAll(CARD_SELECTOR).filter((n) => n.getBoundingClientRect().width > 0);
      let dealerEls = cardEls.filter((n) => /dealer/i.test(classStr(n) + classStr(n.closest('[class*="dealer"]') || document.createElement('div'))));
      let playerEls = cardEls.filter((n) => !dealerEls.includes(n));

      // Fallback: if no element's class/ancestor mentions "dealer" at all,
      // class-based detection found nothing to distinguish — everything
      // would otherwise get misclassified as the player's hand. Use table
      // convention instead: dealer cards render above player cards. This
      // is a guess, not a guarantee — flagged in debugScan when it kicks in.
      let usedPositionFallback = false;
      if (dealerEls.length === 0 && cardEls.length >= 2) {
        const tops = cardEls.map((n) => n.getBoundingClientRect().top);
        const minTop = Math.min(...tops);
        const maxTop = Math.max(...tops);
        if (maxTop - minTop > 40) { // only if cards are meaningfully split vertically
          const midpoint = (minTop + maxTop) / 2;
          dealerEls = cardEls.filter((n) => n.getBoundingClientRect().top < midpoint);
          playerEls = cardEls.filter((n) => n.getBoundingClientRect().top >= midpoint);
          usedPositionFallback = true;
        }
      }

      const handContainers = deepQueryAll('[class*="hand"], [data-hand]')
        .filter((n) => n.getBoundingClientRect().width > 0 && !/dealer/i.test(classStr(n)));
      let hands = null, activeHandIdx = 0;
      if (handContainers.length > 1) {
        hands = handContainers.map((c) => playerEls.filter((el) => c.contains(el)).map(textRank).filter(Boolean))
          .filter((ranks) => ranks.length > 0);
        if (hands.length > 1) {
          const activeIdx = handContainers.findIndex((n) => /active|current|selected|focused?/i.test(classStr(n)));
          activeHandIdx = activeIdx !== -1 ? activeIdx : hands.length - 1;
        } else {
          hands = null;
        }
      }

      return {
        dealer: dealerEls.map(textRank).filter(Boolean),
        player: hands ? hands[activeHandIdx] : playerEls.map(textRank).filter(Boolean),
        dealerEls, playerEls,
        split: !!hands,
        handCount: hands ? hands.length : 1,
        activeHandIdx,
        usedPositionFallback,
      };
    }

    function nodeIdentity(n, rank) {
      // Framework-rendered sites often recreate card nodes on every
      // re-render rather than mutating them in place — keying by node
      // reference would then re-log the same physical card repeatedly.
      // Key by rank + a coarse rounded position instead, which is stable
      // across re-renders as long as the card doesn't move on screen.
      const r = n.getBoundingClientRect();
      return `${rank}@${Math.round(r.left / 8)},${Math.round(r.top / 8)}`;
    }

    function countNewCards(els) {
      for (const n of els) {
        const r = textRank(n);
        if (!r) continue;
        const id = nodeIdentity(n, r);
        if (countedNodes.has(id)) continue;
        logCard(r);
        countedNodes.set(id, true);
      }
    }

    function hasLargeCanvas() {
      return deepQueryAll('canvas').some((c) => {
        const r = c.getBoundingClientRect();
        return r.width > 200 && r.height > 150;
      });
    }

    function largestCanvas() {
      const canvases = deepQueryAll('canvas').filter((c) => {
        const r = c.getBoundingClientRect();
        return r.width > 200 && r.height > 150;
      });
      if (!canvases.length) return null;
      return canvases.reduce((a, b) =>
        (a.getBoundingClientRect().width * a.getBoundingClientRect().height) >
        (b.getBoundingClientRect().width * b.getBoundingClientRect().height) ? a : b
      );
    }

    // ---- OCR fallback for canvas/WebGL-rendered tables --------------------
    // Manual-trigger only: captures the canvas as an image and runs text
    // recognition on it, the same way a human eye would read the screen.
    // Never reads canvas internals, engine state, or anything not visibly
    // rendered. If the canvas is cross-origin-tainted, getImageData/toDataURL
    // throws a SecurityError — that's the browser's own protection and is
    // surfaced honestly rather than worked around.
    let tesseractLoadPromise = null;
    function loadTesseract() {
      if (window.Tesseract) return Promise.resolve(window.Tesseract);
      if (tesseractLoadPromise) return tesseractLoadPromise;
      tesseractLoadPromise = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js';
        script.onload = () => resolve(window.Tesseract);
        script.onerror = () => reject(new Error('Failed to load Tesseract.js from CDN'));
        document.head.appendChild(script);
      });
      return tesseractLoadPromise;
    }

    async function ocrScan() {
      const canvas = largestCanvas();
      if (!canvas) {
        ocrOut.style.display = 'block';
        ocrOut.textContent = 'No large canvas found on this page — nothing to OCR.';
        return;
      }

      let dataUrl;
      try {
        dataUrl = canvas.toDataURL('image/png');
      } catch (err) {
        ocrOut.style.display = 'block';
        ocrOut.textContent = 'Canvas capture blocked by the browser (SecurityError — the canvas is ' +
          'cross-origin-tainted). This is the browser\'s own cross-origin protection; it can\'t be ' +
          'worked around from a userscript. This table can\'t be read programmatically — manual entry ' +
          'below is the only option for it.';
        logError('OCR canvas capture failed (likely tainted canvas)', err);
        return;
      }

      ocrOut.style.display = 'block';
      ocrOut.textContent = 'Loading OCR engine...';
      status('OCR: loading Tesseract.js from CDN...');

      let Tesseract;
      try {
        Tesseract = await loadTesseract();
      } catch (err) {
        ocrOut.textContent = 'Could not load Tesseract.js — check network access to cdn.jsdelivr.net.';
        logError('Tesseract load failed', err);
        return;
      }

      ocrOut.textContent = 'Scanning canvas...';
      status('OCR: recognizing text on canvas...');
      try {
        const result = await Tesseract.recognize(dataUrl, 'eng');
        const rawText = result.data.text || '';
        const tokens = rawText.match(/\b(10|[2-9]|[AJQK])\b/gi) || [];
        ocrOut.textContent = `Raw OCR text:\n${rawText.trim() || '(nothing recognized)'}\n\n` +
          `Rank-like tokens found: ${tokens.length ? tokens.join(' ') : '(none)'}\n\n` +
          'This is unverified — OCR on a small/rotated/stylized card graphic can misread ranks ' +
          '(e.g. mistaking an 8 for a B, or a 10 for a 1 and 0 separately). Confirm against what you ' +
          'see on screen before using it, then enter the hand manually below.';
        status('OCR scan complete — review output above');
      } catch (err) {
        ocrOut.textContent = 'OCR recognition failed — see log.';
        logError('Tesseract.recognize failed', err);
      }
    }

    // ---- DEBUG SCAN — shows what CARD_SELECTOR actually matched on this
    // page, since guessing at a site's markup doesn't work; this gives
    // real data to correct the selector against. -----------------------
    function debugScan() {
      const all = deepQueryAll(CARD_SELECTOR).filter((n) => n.getBoundingClientRect().width > 0);
      const rows = all.map((n, i) => {
        const r = textRank(n);
        return {
          idx: i,
          tag: n.tagName,
          cls: classStr(n).slice(0, 60),
          attrs: {
            'data-rank': n.getAttribute('data-rank'),
            'data-card': n.getAttribute('data-card'),
            'aria-label': n.getAttribute('aria-label'),
            src: (n.getAttribute('src') || '').slice(0, 80),
            alt: n.getAttribute('alt'),
          },
          text: (n.innerText || '').slice(0, 20),
          extractedRank: r,
        };
      });
      console.log(`[blackjack-advisor] debugScan: ${all.length} candidate element(s) matched CARD_SELECTOR`);
      console.table(rows);
      return rows;
    }
    window.__blackjackAdvisorDebugScan = debugScan;

    // ---- shuffle handling ---------------------------------------------------
    const SHUFFLE_RE = /\bshuffl\w*\b|\bnew shoe\b/i;
    let lastShuffleCheck = 0;
    function checkReshuffle() {
      const now = Date.now();
      if (now - lastShuffleCheck < 3000) return;
      lastShuffleCheck = now;
      if (SHUFFLE_RE.test(document.body.innerText.slice(0, 5000))) {
        rcHiLo = 0; cardsSeen = 0; countedNodes = new Map();
        shuffleUnconfirmed = true;
        setBadge('UNCONFIRMED');
        status('shuffle text detected — tap Reset to confirm and resume');
      }
    }

    // ---- domain confirmation dialog ---------------------------------------
    function showConfirmationDialog() {
      const overlay = h('div', {
        style: 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(10,12,16,0.6);backdrop-filter:blur(6px);z-index:2147483647;display:flex;align-items:center;justify-content:center;font:14px/1.4 -apple-system,system-ui,sans-serif;',
      });
      const yesBtn = h('button', {
        style: 'padding:12px 24px;min-height:44px;border:1px solid rgba(255,255,255,0.2);border-radius:30px;background:rgba(74,222,128,0.85);color:#052e13;font-weight:700;cursor:pointer;font-size:15px;',
        text: 'Yes, start',
      });
      const noBtn = h('button', {
        style: 'padding:12px 24px;min-height:44px;border:1px solid rgba(255,255,255,0.2);border-radius:30px;background:rgba(239,68,68,0.85);color:#2e0505;font-weight:700;cursor:pointer;font-size:15px;',
        text: 'No, disable',
      });
      yesBtn.addEventListener('click', () => {
        safeStorage.set(CONFIRM_KEY, 'true');
        document.body.removeChild(overlay);
        startAdvisor();
      });
      noBtn.addEventListener('click', () => {
        safeStorage.set(CONFIRM_KEY, 'false');
        document.body.removeChild(overlay);
        showDisabledNotice();
      });
      const box = h('div', {
        style: `${GLASS_PANEL}padding:24px;max-width:420px;width:90%;max-height:80vh;overflow-y:auto;color:#fff;text-align:center;`,
      }, [
        h('div', { style: 'font-size:18px;font-weight:700;margin-bottom:8px;' }, [document.createTextNode('Blackjack Advisor')]),
        h('div', { style: 'font-size:14px;color:rgba(255,255,255,0.8);margin-bottom:20px;' }, [document.createTextNode('Is this the active blackjack table?')]),
        h('div', { style: 'display:flex;gap:12px;justify-content:center;' }, [yesBtn, noBtn]),
        h('div', { style: 'margin-top:14px;font-size:11px;color:rgba(255,255,255,0.4);' }, [document.createTextNode('This choice is remembered for this domain.')]),
      ]);
      overlay.appendChild(box);
      document.body.appendChild(overlay);
    }

    function showDisabledNotice() {
      const notice = h('div', {
        style: `${GLASS_PANEL}position:fixed;bottom:calc(env(safe-area-inset-bottom, 0px) + 16px);right:12px;z-index:2147483647;padding:12px 16px;min-height:36px;color:rgba(255,255,255,0.75);font-size:13px;cursor:pointer;max-width:calc(100vw - 24px);`,
        text: 'Blackjack Advisor disabled for this site. Tap to re-enable.',
      });
      notice.addEventListener('click', () => {
        safeStorage.remove(CONFIRM_KEY);
        location.reload();
      });
      document.body.appendChild(notice);
    }

    // ---- BUILD PANEL ---------------------------------------------------------
    function buildPanel() {
      const [logBtn, logSection] = buildLogUI();

      const headerRow = h('div', { style: 'display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px;' });
      const badgeWrap = h('div', { style: 'display:flex;align-items:center;gap:4px;font-size:11px;font-weight:600;color:rgba(255,255,255,0.7);' });
      badgeDot = h('span', { style: 'width:8px;height:8px;border-radius:50%;background:#888;display:inline-block;' });
      badgeText = h('span', { text: 'WATCHING' });
      badgeWrap.append(badgeDot, badgeText);

      countEl = h('span', { style: 'font-size:12px;font-weight:500;color:rgba(255,255,255,0.8);' }, [document.createTextNode('TC 0.0 | 0')]);
      headerRow.append(badgeWrap, countEl);

      readoutEl = h('div', { style: 'font-size:13px;font-weight:600;color:#fff;min-height:18px;margin-top:2px;' }, [document.createTextNode('watching...')]);
      moveEl = h('div', { style: 'font-size:34px;font-weight:800;text-shadow:0 2px 8px rgba(0,0,0,.8);letter-spacing:.04em;min-height:40px;margin-top:2px;' }, [document.createTextNode('—')]);
      whyEl = h('div', { style: 'font-size:11px;color:rgba(255,255,255,0.7);' });
      insuranceEl = h('div', { style: 'font-size:12px;font-weight:700;color:#f59e0b;margin-top:2px;' });
      betEl = h('div', { style: 'font-size:16px;font-weight:600;color:#ffe08a;margin:4px 0 8px 0;' }, [document.createTextNode('Bet: $—')]);

      const actionRow = h('div', { style: 'display:flex;gap:6px;margin:6px 0 8px 0;' });
      const resetBtn = h('button', { style: GLASS_BTN, text: '🔄 Reset' });
      resetBtn.addEventListener('click', () => {
        rcHiLo = 0; cardsSeen = 0; countedNodes = new Map();
        shuffleUnconfirmed = false;
        setBadge(everSeenHand ? 'READING' : 'WATCHING');
        status('shoe reset — count zeroed');
        showToast('Shoe reset', '#f59e0b');
      });
      configToggle = h('button', { style: GLASS_BTN, text: '⚙️' });
      configToggle.addEventListener('click', () => {
        configOpen = !configOpen;
        configContainer.style.display = configOpen ? 'block' : 'none';
        configToggle.style.background = configOpen ? 'rgba(75,139,180,0.5)' : 'rgba(255,255,255,0.06)';
      });
      actionRow.append(resetBtn, configToggle, logBtn);

      // manual entry
      manualHand = h('input', { placeholder: 'your hand e.g. A 8', style: GLASS_INPUT });
      manualUp = h('input', { placeholder: 'dealer upcard', style: GLASS_INPUT + 'margin-top:6px' });
      manualGo = h('button', { style: GLASS_BTN + 'width:100%;', text: 'Get recommendation' });
      manualGo.addEventListener('click', () => {
        const hand = manualHand.value.trim().split(/\s+/).filter(Boolean).map((r) => rankFromString(r) || r.toUpperCase());
        const up = rankFromString(manualUp.value.trim()) || manualUp.value.trim().toUpperCase();
        if (hand.length < 2 || !up) { status('enter at least 2 cards and a dealer upcard'); return; }
        const tc = tcHiLo();
        const res = strategy(hand, up, tc);
        readoutEl.textContent = `you: ${hand.join(' ')}  dealer: ${up} (manual)`;
        setMove(res.move);
        whyEl.textContent = res.why || '';
        insuranceEl.textContent = res.insurance || '';
      });
      manualBox = h('details', { style: 'margin-top:6px;padding-top:6px;border-top:1px solid rgba(255,255,255,0.12)' }, [
        h('summary', { style: 'cursor:pointer;font-size:11px;color:rgba(255,255,255,0.75)', text: 'Type it in instead' }),
        h('div', { style: 'margin-top:6px' }, [manualHand, manualUp, manualGo]),
      ]);

      // config
      const smallInput = (val, placeholder) => h('input', { type: 'number', value: String(val), placeholder: placeholder, style: 'width:100%;background:rgba(255,255,255,0.08);color:#fff;border:1px solid rgba(255,255,255,0.18);border-radius:30px;padding:6px 12px;font-size:12px;box-sizing:border-box;margin-bottom:4px;' });
      inBankroll = smallInput(bankroll, 'bankroll');
      inUnit = smallInput(unit, 'unit');
      inMin = smallInput(minBet, 'min bet');
      inMax = smallInput(maxBet, 'max bet');
      inDecks = smallInput(decksInShoe, 'decks');
      inPenetration = smallInput(penetrationWarnPct, 'pen warn %');
      const configLabel = (text) => h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.6);margin:2px 0 0 4px;' }, [document.createTextNode(text)]);
      const configGrid = h('div', { style: 'display:grid;grid-template-columns:1fr 1fr;gap:4px 10px;margin-top:4px;' });
      configGrid.append(
        h('div', {}, [configLabel('Bankroll'), inBankroll]),
        h('div', {}, [configLabel('Unit'), inUnit]),
        h('div', {}, [configLabel('Min bet'), inMin]),
        h('div', {}, [configLabel('Max bet'), inMax]),
        h('div', {}, [configLabel('Decks'), inDecks]),
        h('div', {}, [configLabel('Pen warn %'), inPenetration]),
      );
      const configWarn = h('div', { style: 'font-size:10px;color:#f87171;margin:4px 0;' });
      function revalidate() {
        const problems = validateBetConfig();
        configWarn.textContent = problems.length ? '⚠ ' + problems.join('; ') : '';
        betEl.style.opacity = problems.length ? '0.4' : '1';
      }
      [[inBankroll, (v) => bankroll = v], [inUnit, (v) => unit = v], [inMin, (v) => minBet = v], [inMax, (v) => maxBet = v], [inDecks, (v) => decksInShoe = v || 6], [inPenetration, (v) => penetrationWarnPct = v || 75]]
        .forEach(([node, set]) => node.addEventListener('change', (e) => { set(Number(e.target.value) || 0); revalidate(); }));
      revalidate();

      const forgetBtn = h('button', { style: GLASS_BTN + 'width:100%;', text: 'Forget this site confirmation' });
      forgetBtn.addEventListener('click', () => {
        safeStorage.remove(CONFIRM_KEY);
        location.reload();
      });

      configContainer = h('div', { style: 'display:none;margin-top:6px;padding-top:6px;border-top:1px solid rgba(255,255,255,0.1);' }, [configGrid, configWarn, forgetBtn]);

      // debug scan
      debugOut = h('pre', { style: 'margin-top:6px;font-size:9px;line-height:1.35;color:rgba(255,255,255,0.75);max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,0.25);border-radius:10px;padding:8px;display:none' });
      btnDebug = h('button', { style: GLASS_BTN + 'width:100%;margin-top:6px;', text: '🔍 Scan page (debug)' });
      btnDebug.addEventListener('click', () => {
        const rows = debugScan();
        debugOut.style.display = 'block';
        if (!rows.length) {
          debugOut.textContent = 'CARD_SELECTOR matched 0 elements on this page.\n\nSelector is wrong for this site — inspect a card element and send its outerHTML over.';
          return;
        }
        const misses = rows.filter((r) => !r.extractedRank);
        const lines = rows.slice(0, 30).map((r) =>
          `#${r.idx} <${r.tag.toLowerCase()}> class="${r.cls}"\n  rank=${JSON.stringify(r.extractedRank)} text="${r.text}" src="${r.attrs.src}" alt="${r.attrs.alt || ''}"`
        );
        debugOut.textContent = `${rows.length} matched (${misses.length} unrecognized). Full data in console via __blackjackAdvisorDebugScan().\n\n` + lines.join('\n\n');
      });

      // OCR fallback for canvas/WebGL tables
      ocrOut = h('pre', { style: 'margin-top:6px;font-size:9px;line-height:1.35;color:rgba(255,255,255,0.75);max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,0.25);border-radius:10px;padding:8px;display:none' });
      btnOcr = h('button', { style: GLASS_BTN + 'width:100%;margin-top:6px;', text: '👁 OCR scan canvas' });
      btnOcr.addEventListener('click', () => { ocrScan(); });

      statusEl = h('div', { style: 'font-size:10px;color:rgba(255,200,150,0.7);margin-top:6px;min-height:16px;' });

      panel = h('div', {
        id: 'bj-advisor-panel',
        style: `${GLASS_PANEL}display:none;position:fixed;bottom:calc(env(safe-area-inset-bottom, 0px) + 16px);right:12px;z-index:2147483647;width:min(260px, calc(100vw - 24px));max-height:78vh;overflow-y:auto;padding:12px 14px;font:14px/1.4 -apple-system,system-ui,sans-serif;color:#fff;`,
      }, [headerRow, readoutEl, moveEl, whyEl, insuranceEl, betEl, actionRow, manualBox, configContainer, btnDebug, debugOut, btnOcr, ocrOut, logSection, statusEl]);

      document.documentElement.appendChild(panel);
      setBadge('WATCHING');
      status('waiting for table...');
    }

    let readoutEl;

    // ---- MAIN LOOP (DOM-read, with error catching) -----------------------
    function tick() {
      try {
        checkReshuffle();
        const { dealer, player, dealerEls, playerEls, usedPositionFallback } = readTable();
        countNewCards(dealerEls);
        countNewCards(playerEls);
        const tc = tcHiLo();
        const bet = suggestedBet(tc);
        const problems = validateBetConfig();
        betEl.textContent = problems.length ? 'Bet: fix config' : `Bet: $${bet}`;
        if (usedPositionFallback) status('dealer/player split guessed by position — verify it\'s correct');

        const penetration = cardsSeen / (decksInShoe * 52);
        if (penetration * 100 > penetrationWarnPct && !shuffleUnconfirmed) {
          status(`⚠️ deep in shoe (${Math.round(penetration * 100)}% dealt) — verify no reshuffle happened`);
        }

        if (!dealer.length || player.length < 2) {
          emptyCardTicks++;
          if (emptyCardTicks > 6 && hasLargeCanvas() && !manualBox.hasAttribute('open')) {
            manualBox.setAttribute('open', 'open');
            if (!everSeenHand) { everSeenHand = true; panel.style.display = 'block'; }
            status('no readable DOM cards + canvas table found — manual entry opened below');
          }
          if (everSeenHand) {
            readoutEl.textContent = 'watching...';
            setMove(null);
            whyEl.textContent = '';
            insuranceEl.textContent = '';
            if (!shuffleUnconfirmed) setBadge('WATCHING');
          }
          countEl.textContent = `TC ${tc.toFixed(1)} | ${cardsSeen} — dealer:${dealer.length} player:${player.length}`;
          return;
        }
        emptyCardTicks = 0;
        if (!everSeenHand) { everSeenHand = true; panel.style.display = 'block'; }
        if (!shuffleUnconfirmed) setBadge('READING');

        readoutEl.textContent = `you: ${player.join(' ')}  dealer: ${dealer[0]}`;
        const res = strategy(player, dealer[0], tc);
        setMove(res.move);
        whyEl.textContent = res.why || '';
        const currentInsurance = res.insurance || '';
        insuranceEl.textContent = currentInsurance;
        countEl.textContent = `TC ${tc.toFixed(1)} | ${cardsSeen} seen`;
      } catch (err) {
        logError('tick error', err);
        try { status('Error — see log'); } catch (e) {}
      }
    }

    // ---- START ----------------------------------------------------------------
    function startAdvisor() {
      try {
        buildPanel();
      } catch (e) {
        logError('buildPanel failed', e);
        const fallback = h('div', {
          style: 'position:fixed;bottom:20px;right:20px;z-index:2147483647;background:red;color:white;padding:10px;border-radius:8px;font-size:12px;',
          text: 'Advisor UI failed — check console / log.',
        });
        document.documentElement.appendChild(fallback);
        return;
      }

      setInterval(tick, POLL_MS);
      let mutTimer = null;
      const obs = new MutationObserver(() => {
        clearTimeout(mutTimer);
        mutTimer = setTimeout(() => {
          try { tick(); } catch (e) { logError('observer tick error', e); }
        }, 150);
      });
      obs.observe(document.body, { childList: true, subtree: true });
      setTimeout(() => {
        try { tick(); } catch (e) { logError('initial tick error', e); }
      }, 300);
      setTimeout(() => showToast('Blackjack Advisor ready', '#4ade80'), 500);
    }

    if (storedConfirm === 'true') {
      startAdvisor();
    } else if (storedConfirm === 'false') {
      showDisabledNotice();
    } else {
      showConfirmationDialog();
    }

  } // end run()
})();
