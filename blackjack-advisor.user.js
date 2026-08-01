// ==UserScript==
// @name         Blackjack Advisor (human-in-the-loop, mobile)
// @namespace    evan.local.blackjack-advisor
// @version      1.7.0
// @description  Glassmorphism overlay that reads the table, tracks Hi-Lo count, and shows the recommended move + bet. Advisory only — never clicks buttons or sets bet fields. Broad DOM-based card detection with a diagnostics view, pasted-in plugins for site-specific table reading, calibrated canvas pixel/shape matching, accessibility output, and a provably-fair audit panel that talks to a local companion server (blackjack-audit-server.js) to check casino RNG seed commitments and shuffles. Tuned for Firefox for Android (Tampermonkey/Violentmonkey): safe against blocked storage, small viewports, and touch input.
// @match        https://*.*/*
// @run-at       document-idle
// @grant        none
// @noframes
// ==/UserScript==
(function () {
  'use strict';

  try {
    run();
  } catch (err) {
    console.error('[blackjack-advisor] failed to start:', err);
  }

  function run() {

  // ---- CONFIGURATION ---------------------------------------------------------
  const SURRENDER_ALLOWED = false;
  const POLL_MS = 700;

  // ---- DOMAIN CONFIRMATION (persistent, storage-safe) -------------------
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

  // Basic strategy only allows DOUBLE on the initial two cards; once the
  // player has hit, a DOUBLE recommendation is no longer actionable.
  function strategy(hand, up, tc) {
    const res = computeStrategy(hand, up, tc);
    if (res.move === 'DOUBLE' && hand.length !== 2) {
      return { ...res, move: 'HIT', why: (res.why || '') + ' (double unavailable after hit — hit instead)' };
    }
    return res;
  }

  function computeStrategy(hand, up, tc) {
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
    if (sum > 21) return { move: null, why: 'bust', insurance };
    if (numAces > 0 && sum <= 21) usableAce = true;
    if (usableAce && sum <= 20) {
      const row = SOFT[Math.max(13, sum)];
      return { ...decode(row ? row[ci] : 'S'), insurance };
    }
    if (sum >= 17) return { ...applyDeviation({ move: 'STAND', why: 'basic strategy' }, 'hard', sum, up, tc), insurance };
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

  // ---- BET SIZING (sane caps, half Kelly by default) ------------------------
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

  // ---- glassmorphism theme (visual only — behavior below is unchanged) ------
  const GLASS_PANEL = 'background:rgba(24,26,32,0.55);backdrop-filter:blur(18px) saturate(160%);-webkit-backdrop-filter:blur(18px) saturate(160%);border:1px solid rgba(255,255,255,0.16);box-shadow:0 8px 32px rgba(0,0,0,0.35),0 0 0 1px rgba(255,255,255,0.06) inset;border-radius:20px;';
  const GLASS_INPUT = 'width:100%;background:rgba(255,255,255,0.08);color:#fff;border:1px solid rgba(255,255,255,0.18);border-radius:30px;padding:10px 14px;font-size:16px;min-height:40px;backdrop-filter:blur(4px);';
  const GLASS_BTN = 'width:100%;margin-top:6px;padding:10px;min-height:44px;font-size:14px;font-weight:600;border-radius:30px;border:1px solid rgba(255,255,255,0.18);background:rgba(75,139,180,0.28);color:#fff;cursor:pointer;backdrop-filter:blur(4px);';
  const GLASS_BTN_GHOST = 'width:100%;margin-top:8px;padding:10px;min-height:40px;font-size:12px;border-radius:30px;border:1px solid rgba(255,255,255,0.18);background:rgba(255,255,255,0.06);color:#fff;cursor:pointer;';

  // ---- top-level UI state (no window.* globals) -------------------------
  let panel, badgeDot, badgeText, readoutEl, moveEl, whyEl, insuranceEl, betEl,
    countEl, manualBox, manualHand, manualUp, manualGo, betConfig, configWarnEl,
    inBankroll, inUnit, inMin, inMax, inDecks, inPenetration, btnReset, statusEl;
  let everSeenHand = false;
  let shuffleUnconfirmed = false;
  let countedNodes = new Map();
  let countedRegions = new Map(); // canvas-adapter path: region.id -> last-counted rank
  let dealHistory = []; // [{ code:'AS'|'A?', rank, suit, t }] — order cards were first seen this shoe

  const MOVE_COLORS = { STAND: '#4ade80', HIT: '#eab308', DOUBLE: '#f97316', SPLIT: '#f97316', SURRENDER: '#ef4444' };
  const BADGE_MODES = { WATCHING: ['#8a8f98', 'WATCHING'], READING: ['#4ade80', 'READING TABLE'], UNCONFIRMED: ['#f59e0b', 'CONFIRM SHUFFLE'] };

  let currentBadgeMode = 'WATCHING';
  let currentStatus = '';
  function setBadge(mode) {
    currentBadgeMode = mode;
    const [color, label] = BADGE_MODES[mode] || BADGE_MODES.WATCHING;
    badgeDot.style.background = color;
    badgeDot.style.boxShadow = `0 0 8px ${color}`;
    badgeText.textContent = label;
  }
  function setMove(move) {
    moveEl.textContent = move || '—';
    moveEl.style.color = MOVE_COLORS[move] || '#a6ffcb';
  }
  function status(m) { currentStatus = m; statusEl.textContent = m; }

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

  // ---- panel construction --------------------------------------------------
  function buildPanel() {
    const badgeEl = h('div', { style: 'display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:700;letter-spacing:.04em;color:rgba(255,255,255,0.85);text-transform:uppercase' });
    badgeDot = h('span', { style: 'width:8px;height:8px;border-radius:50%;background:#888;display:inline-block;box-shadow:0 0 6px rgba(0,0,0,.5)' });
    badgeText = h('span', { text: 'WATCHING' });
    badgeEl.append(badgeDot, badgeText);

    readoutEl = h('div', { style: 'font-size:14px;font-weight:600;color:#fff;min-height:20px;margin-top:8px' }, [document.createTextNode('watching...')]);
    moveEl = h('div', { style: 'font-size:28px;font-weight:800;text-shadow:0 1px 4px rgba(0,0,0,.7);margin-top:6px;letter-spacing:.02em' }, [document.createTextNode('—')]);
    whyEl = h('div', { style: 'font-size:11px;color:rgba(255,255,255,0.7);margin-top:2px' });
    insuranceEl = h('div', { style: 'font-size:12px;font-weight:700;color:#f59e0b;margin-top:4px' });
    betEl = h('div', { style: 'font-size:14px;font-weight:600;color:#ffe08a;margin-top:8px' });
    countEl = h('div', { style: 'margin-top:6px;font-size:11px;color:rgba(255,255,255,0.75)' });

    manualHand = h('input', { placeholder: 'your hand e.g. A 8', style: GLASS_INPUT });
    manualUp = h('input', { placeholder: 'dealer upcard', style: GLASS_INPUT + 'margin-top:6px' });
    manualGo = h('button', { style: GLASS_BTN, text: 'Get recommendation' });
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
      notifyA11yPlugins({
        move: res.move, why: res.why || '', insurance: res.insurance || '', bet: null, betProblems: [], tc, cardsSeen,
        playerHand: hand, dealerUp: up, split: false, handCount: 1,
        badge: currentBadgeMode, status: currentStatus,
      });
    });
    manualBox = h('details', { style: 'margin-top:10px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.15)' }, [
      h('summary', { style: 'cursor:pointer;font-size:11px;color:rgba(255,255,255,0.75)', text: 'Type it in instead' }),
      h('div', { style: 'margin-top:6px' }, [manualHand, manualUp, manualGo]),
    ]);

    const smallInput = (val) => h('input', { type: 'number', value: String(val), style: 'width:100%;background:rgba(255,255,255,0.08);color:#fff;border:1px solid rgba(255,255,255,0.18);border-radius:10px;padding:3px;font-size:11px' });
    inBankroll = smallInput(bankroll);
    inUnit = smallInput(unit);
    inMin = smallInput(minBet);
    inMax = smallInput(maxBet);
    inDecks = smallInput(decksInShoe);
    inPenetration = smallInput(penetrationWarnPct);
    configWarnEl = h('div', { style: 'font-size:10px;color:#f87171;margin-top:4px' });

    const forgetBtn = h('button', { style: GLASS_BTN_GHOST, text: 'Forget this site confirmation' });
    forgetBtn.addEventListener('click', () => {
      safeStorage.remove(CONFIRM_KEY);
      location.reload();
    });

    betConfig = h('details', { style: 'margin-top:8px;font-size:10px;color:rgba(255,255,255,0.8)' }, [
      h('summary', { style: 'cursor:pointer', text: 'bet sizing config' }),
      h('label', { text: 'bankroll' }), inBankroll,
      h('label', { text: 'unit' }), inUnit,
      h('label', { text: 'min bet' }), inMin,
      h('label', { text: 'max bet' }), inMax,
      h('label', { text: 'decks in shoe' }), inDecks,
      h('label', { text: 'penetration warning %' }), inPenetration,
      configWarnEl,
      h('div', { style: 'margin-top:6px;border-top:1px solid rgba(255,255,255,0.1);padding-top:6px;' }, [forgetBtn]),
    ]);

    function revalidate() {
      const problems = validateBetConfig();
      configWarnEl.textContent = problems.length ? '⚠ ' + problems.join('; ') : '';
      betEl.style.opacity = problems.length ? '0.4' : '1';
    }
    [[inBankroll, (v) => bankroll = v], [inUnit, (v) => unit = v], [inMin, (v) => minBet = v], [inMax, (v) => maxBet = v], [inDecks, (v) => decksInShoe = v || 6], [inPenetration, (v) => penetrationWarnPct = v || 75]]
      .forEach(([node, set]) => node.addEventListener('change', (e) => { set(Number(e.target.value) || 0); revalidate(); }));
    revalidate();

    btnReset = h('button', { style: GLASS_BTN_GHOST, text: 'Reset shoe' });
    btnReset.addEventListener('click', () => {
      rcHiLo = 0; cardsSeen = 0; countedNodes = new Map(); countedRegions = new Map(); dealHistory = [];
      shuffleUnconfirmed = false;
      setBadge(everSeenHand ? 'READING' : 'WATCHING');
      status('shoe reset — count zeroed');
    });

    statusEl = h('div', { style: 'margin-top:8px;font-size:10px;color:rgba(255,200,150,0.85)' });

    // ---- plugins panel (site adapters + accessibility output) -----------
    const pluginListEl = h('div', { style: 'margin-top:6px;' });
    function renderPluginList() {
      while (pluginListEl.firstChild) pluginListEl.removeChild(pluginListEl.firstChild);
      if (!pluginRecords.length) {
        pluginListEl.appendChild(h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.5);', text: 'no plugins loaded' }));
        return;
      }
      pluginRecords.forEach((r) => {
        const removeBtn = h('button', { style: 'padding:2px 8px;font-size:10px;border-radius:20px;border:1px solid rgba(255,255,255,0.18);background:rgba(239,68,68,0.25);color:#fff;cursor:pointer;', text: 'remove' });
        removeBtn.addEventListener('click', () => { removePlugin(r.id); renderPluginList(); status(`plugin "${r.name}" removed`); });
        pluginListEl.appendChild(h('div', { style: 'display:flex;align-items:center;justify-content:space-between;gap:6px;font-size:11px;margin-top:4px;' }, [
          h('span', { text: `${r.name} (${r.type})${r.version ? ' v' + r.version : ''}` }),
          removeBtn,
        ]));
      });
    }

    const pluginSourceInput = h('textarea', { rows: '4', placeholder: 'Paste a plugin object literal here…', style: GLASS_INPUT + 'resize:vertical;font-family:monospace;font-size:11px;' });
    const pluginErrorEl = h('div', { style: 'font-size:10px;color:#f87171;margin-top:4px;white-space:pre-wrap;' });
    const pluginLoadBtn = h('button', { style: GLASS_BTN, text: 'Load plugin' });
    pluginLoadBtn.addEventListener('click', () => {
      const source = pluginSourceInput.value.trim();
      if (!source) { pluginErrorEl.textContent = 'paste a plugin object literal first'; return; }
      const result = addPlugin(source);
      if (result.ok) {
        pluginErrorEl.textContent = '';
        pluginSourceInput.value = '';
        renderPluginList();
        status(`plugin "${result.plugin.name || result.plugin.id}" loaded`);
      } else {
        pluginErrorEl.textContent = result.error;
      }
    });

    const pluginsSection = h('details', { style: 'margin-top:8px;font-size:10px;color:rgba(255,255,255,0.8);border-top:1px solid rgba(255,255,255,0.15);padding-top:8px;' }, [
      h('summary', { style: 'cursor:pointer', text: 'Plugins ♿ (site adapters & accessibility)' }),
      h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.6);margin-top:4px;' }, [document.createTextNode('Plugins run with full page access, same as anything pasted into devtools — only load code you wrote or trust. The advisor only ever reads the documented fields back from a plugin; it never calls anything else a plugin exposes, and plugins are never wired up to click buttons or set bet fields.')]),
      pluginListEl,
      pluginSourceInput,
      pluginLoadBtn,
      pluginErrorEl,
      h('details', { style: 'margin-top:6px;' }, [
        h('summary', { style: 'cursor:pointer;font-size:10px;color:rgba(255,255,255,0.6);', text: 'Example: site adapter' }),
        h('pre', { style: 'white-space:pre-wrap;font-size:10px;background:rgba(0,0,0,0.25);padding:6px;border-radius:8px;overflow-x:auto;margin-top:4px;' }, [document.createTextNode(EXAMPLE_SITE_ADAPTER)]),
      ]),
      h('details', { style: 'margin-top:6px;' }, [
        h('summary', { style: 'cursor:pointer;font-size:10px;color:rgba(255,255,255,0.6);', text: 'Example: accessibility output' }),
        h('pre', { style: 'white-space:pre-wrap;font-size:10px;background:rgba(0,0,0,0.25);padding:6px;border-radius:8px;overflow-x:auto;margin-top:4px;' }, [document.createTextNode(EXAMPLE_A11Y_OUTPUT)]),
      ]),
    ]);
    renderPluginList();

    // ---- canvas calibration (pixel/shape matching for canvas-rendered tables) ----
    const calibStatusEl = h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.6);margin-top:4px;' });
    const calibRegionsEl = h('div', { style: 'margin-top:6px;' });
    let highlightEls = [];

    function clearHighlights() {
      highlightEls.forEach((el) => el.remove());
      highlightEls = [];
    }
    function activeCanvasAdapter() {
      return pluginRegistry.canvasAdapters.find((p) => {
        try { return typeof p.matches !== 'function' || p.matches(window.location.hostname); }
        catch (e) { return false; }
      }) || null;
    }
    function renderRegions() {
      while (calibRegionsEl.firstChild) calibRegionsEl.removeChild(calibRegionsEl.firstChild);
      clearHighlights();
      const adapter = activeCanvasAdapter();
      if (!adapter) {
        calibStatusEl.textContent = 'load a canvas-adapter plugin first (see example below)';
        return;
      }
      let regions = [];
      try { regions = adapter.findCardRegions(pluginCtx()) || []; }
      catch (e) { calibStatusEl.textContent = `findCardRegions threw: ${e.message}`; return; }
      const templates = loadCanvasTemplates(adapter.id);
      calibStatusEl.textContent = `${regions.length} region(s) found — ${Object.keys(templates).length} label(s) calibrated`;
      regions.forEach((region, i) => {
        const box = h('div', { style: `position:fixed;left:${region.x}px;top:${region.y}px;width:${region.w}px;height:${region.h}px;border:2px solid #4ade80;z-index:2147483646;pointer-events:none;box-sizing:border-box;` });
        document.documentElement.appendChild(box);
        highlightEls.push(box);

        const rankSelect = h('select', { style: 'font-size:11px;border-radius:8px;' });
        ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'].forEach((r) => rankSelect.appendChild(h('option', { value: r, text: r })));
        const captureBtn = h('button', { style: 'padding:2px 8px;font-size:10px;border-radius:20px;border:1px solid rgba(255,255,255,0.18);background:rgba(75,139,180,0.4);color:#fff;cursor:pointer;', text: 'capture' });
        captureBtn.addEventListener('click', () => {
          const sample = sampleCanvasRegion(region.x, region.y, region.w, region.h);
          if (!sample) { calibStatusEl.textContent = `region ${region.id || i}: canvas unreadable (tainted or WebGL)`; return; }
          const t = loadCanvasTemplates(adapter.id);
          t[rankSelect.value] = { grid: sample.grid, colorHint: sample.colorHint };
          saveCanvasTemplates(adapter.id, t);
          calibStatusEl.textContent = `captured "${rankSelect.value}" from region ${region.id || i}`;
          renderRegions();
        });
        calibRegionsEl.appendChild(h('div', { style: 'display:flex;align-items:center;gap:6px;font-size:11px;margin-top:4px;' }, [
          h('span', { text: `${region.id || ('#' + i)} (${region.role || '?'})` }),
          rankSelect,
          captureBtn,
        ]));
      });
    }
    const rescanBtn = h('button', { style: GLASS_BTN_GHOST, text: 'Detect regions' });
    rescanBtn.addEventListener('click', renderRegions);
    const clearTemplatesBtn = h('button', { style: GLASS_BTN_GHOST, text: 'Clear calibration for this site' });
    clearTemplatesBtn.addEventListener('click', () => {
      const adapter = activeCanvasAdapter();
      if (!adapter) return;
      saveCanvasTemplates(adapter.id, {});
      renderRegions();
    });

    const canvasSection = h('details', { style: 'margin-top:8px;font-size:10px;color:rgba(255,255,255,0.8);border-top:1px solid rgba(255,255,255,0.15);padding-top:8px;' }, [
      h('summary', { style: 'cursor:pointer', text: 'Canvas calibration (pixel/shape matching)' }),
      h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.6);margin-top:4px;' }, [document.createTextNode('For canvas/WebGL tables with no readable DOM. Load a canvas-adapter plugin that reports pixel regions for each card slot, then capture one reference snapshot per rank label while that card is visibly showing at that slot — capture 10, J, Q, and K separately since they look different even though they play the same. A region is only read once its best match clears a confidence threshold; low-confidence regions are left blank rather than guessed.')]),
      calibStatusEl,
      calibRegionsEl,
      rescanBtn,
      clearTemplatesBtn,
      h('details', { style: 'margin-top:6px;' }, [
        h('summary', { style: 'cursor:pointer;font-size:10px;color:rgba(255,255,255,0.6);', text: 'Example: canvas adapter' }),
        h('pre', { style: 'white-space:pre-wrap;font-size:10px;background:rgba(0,0,0,0.25);padding:6px;border-radius:8px;overflow-x:auto;margin-top:4px;' }, [document.createTextNode(EXAMPLE_CANVAS_ADAPTER)]),
      ]),
    ]);

    // ---- debug: card detection diagnostics -------------------------------
    const debugResultsEl = h('div', { style: 'margin-top:6px;max-height:160px;overflow-y:auto;' });
    function renderDebugResults() {
      while (debugResultsEl.firstChild) debugResultsEl.removeChild(debugResultsEl.firstChild);
      const diag = diagnoseTable();
      debugResultsEl.appendChild(h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.7);', text:
        `${diag.rows.length} candidate element(s)${diag.usedFallback ? ' (via whole-page text fallback)' : ''}; ${diag.canvases.length} canvas element(s) on page`
      }));
      diag.rows.slice(0, 40).forEach((row) => {
        const highlightBtn = h('button', { style: 'padding:1px 6px;font-size:9px;border-radius:12px;border:1px solid rgba(255,255,255,0.18);background:rgba(255,255,255,0.08);color:#fff;cursor:pointer;', text: 'show' });
        highlightBtn.addEventListener('click', () => flashHighlight(row.el));
        debugResultsEl.appendChild(h('div', { style: 'display:flex;align-items:center;gap:6px;font-size:10px;margin-top:3px;' }, [
          h('span', { text: `${row.rank || '?'}${row.faceDown ? ' (face-down)' : ''} via ${row.matchedVia || '—'}${row.dealer ? ' [dealer]' : ''}` }),
          highlightBtn,
        ]));
      });
    }
    const debugScanBtn = h('button', { style: GLASS_BTN_GHOST, text: 'Scan now' });
    debugScanBtn.addEventListener('click', renderDebugResults);
    const debugSection = h('details', { style: 'margin-top:8px;font-size:10px;color:rgba(255,255,255,0.8);border-top:1px solid rgba(255,255,255,0.15);padding-top:8px;' }, [
      h('summary', { style: 'cursor:pointer', text: 'Debug: card detection' }),
      h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.6);margin-top:4px;' }, [document.createTextNode('Lists every element the DOM reader currently sees as a candidate card, what matched it, and whether it landed in dealer or player. Use this to figure out why a site isn’t reading, then write a site-adapter or canvas-adapter plugin for it.')]),
      debugScanBtn,
      debugResultsEl,
    ]);

    // ---- provably-fair audit (talks to a local companion server) --------
    const auditServerInput = h('input', { value: 'http://127.0.0.1:9999', style: GLASS_INPUT + 'font-size:11px;' });
    const auditServerSeed = h('input', { placeholder: 'server seed (revealed, after round)', style: GLASS_INPUT + 'margin-top:6px;font-size:11px;' });
    const auditCommitHash = h('input', { placeholder: 'server seed hash (published before round)', style: GLASS_INPUT + 'margin-top:6px;font-size:11px;' });
    const auditClientSeed = h('input', { placeholder: 'client seed', style: GLASS_INPUT + 'margin-top:6px;font-size:11px;' });
    const auditNonce = h('input', { placeholder: 'nonce', type: 'number', style: GLASS_INPUT + 'margin-top:6px;font-size:11px;' });
    const auditResultEl = h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.75);margin-top:6px;white-space:pre-wrap;' });

    async function auditFetch(path, payload) {
      const base = auditServerInput.value.trim().replace(/\/$/, '');
      try {
        const res = await fetch(base + path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const json = await res.json();
        if (!res.ok) return { ok: false, error: json.error || `HTTP ${res.status}` };
        return { ok: true, data: json };
      } catch (e) {
        return { ok: false, error: `unreachable (${e.message}) — start it on this device: node blackjack-audit-server.js` };
      }
    }

    const checkServerBtn = h('button', { style: GLASS_BTN_GHOST, text: 'Check server' });
    checkServerBtn.addEventListener('click', async () => {
      auditResultEl.textContent = 'checking…';
      const base = auditServerInput.value.trim().replace(/\/$/, '');
      try {
        const res = await fetch(base + '/health');
        const json = await res.json();
        auditResultEl.textContent = res.ok ? `reachable: ${json.name || 'audit server'} v${json.version || '?'}` : `error: HTTP ${res.status}`;
      } catch (e) {
        auditResultEl.textContent = `unreachable (${e.message}) — start it on this device: node blackjack-audit-server.js`;
      }
    });

    const verifyCommitBtn = h('button', { style: GLASS_BTN, text: 'Verify seed commitment' });
    verifyCommitBtn.addEventListener('click', async () => {
      auditResultEl.textContent = 'verifying…';
      const result = await auditFetch('/verify/commit', { serverSeed: auditServerSeed.value.trim(), commitHash: auditCommitHash.value.trim() });
      auditResultEl.textContent = result.ok
        ? (result.data.match ? `✓ commitment holds — sha256(server seed) matches the published hash` : `✗ MISMATCH — computed ${result.data.computedHash}, published ${auditCommitHash.value.trim()}`)
        : `error: ${result.error}`;
    });

    const reconstructBtn = h('button', { style: GLASS_BTN, text: 'Reconstruct shuffle' });
    reconstructBtn.addEventListener('click', async () => {
      auditResultEl.textContent = 'reconstructing…';
      const result = await auditFetch('/verify/shuffle', {
        serverSeed: auditServerSeed.value.trim(),
        clientSeed: auditClientSeed.value.trim(),
        nonce: Number(auditNonce.value) || 0,
        deckCount: decksInShoe,
      });
      auditResultEl.textContent = result.ok
        ? `reconstructed deal order (first 20 of ${result.data.deckSize}):\n${result.data.order.slice(0, 20).join(' ')}\n\nCompare this against "Hand history" below — if the ranks/suits actually dealt don't follow this order, either the casino isn't using the standard HMAC-SHA256/Fisher-Yates convention, or something's off.`
        : `error: ${result.error}`;
    });

    const historyEl = h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.75);margin-top:6px;max-height:100px;overflow-y:auto;white-space:pre-wrap;' });
    const refreshHistoryBtn = h('button', { style: GLASS_BTN_GHOST, text: 'Show hand history' });
    refreshHistoryBtn.addEventListener('click', () => {
      historyEl.textContent = dealHistory.length ? dealHistory.map((c) => c.code).join(' ') : '(no cards recorded yet this shoe)';
    });
    const copyHistoryBtn = h('button', { style: GLASS_BTN_GHOST, text: 'Copy hand history' });
    copyHistoryBtn.addEventListener('click', async () => {
      const text = dealHistory.map((c) => c.code).join(' ');
      try { await navigator.clipboard.writeText(text); status('hand history copied'); }
      catch (e) { status('copy failed — clipboard not available'); }
    });

    const auditSection = h('details', { style: 'margin-top:8px;font-size:10px;color:rgba(255,255,255,0.8);border-top:1px solid rgba(255,255,255,0.15);padding-top:8px;' }, [
      h('summary', { style: 'cursor:pointer', text: 'Provably-fair audit (localhost:9999)' }),
      h('div', { style: 'font-size:10px;color:rgba(255,255,255,0.6);margin-top:4px;' }, [document.createTextNode('Verifies a casino’s "provably fair" claim independently of its own verify page: checks that the revealed server seed actually hashes to what was published before the round, and reconstructs the RNG shuffle from the seeds so you can compare it against what was actually dealt. Needs the companion blackjack-audit-server.js running on THIS device (not a remote session) — run: node blackjack-audit-server.js. Implements the common HMAC-SHA256 + Fisher-Yates convention; some casinos vary the exact algorithm.')]),
      h('label', { text: 'audit server URL' }), auditServerInput,
      checkServerBtn,
      h('div', { style: 'margin-top:8px;border-top:1px solid rgba(255,255,255,0.1);padding-top:6px;' }, [
        auditServerSeed, auditCommitHash, verifyCommitBtn,
      ]),
      h('div', { style: 'margin-top:8px;border-top:1px solid rgba(255,255,255,0.1);padding-top:6px;' }, [
        auditClientSeed, auditNonce, reconstructBtn,
      ]),
      auditResultEl,
      h('div', { style: 'margin-top:8px;border-top:1px solid rgba(255,255,255,0.1);padding-top:6px;display:flex;gap:6px;' }, [refreshHistoryBtn, copyHistoryBtn]),
      historyEl,
    ]);

    panel = h('div', {
      style: `${GLASS_PANEL}display:none;position:fixed;bottom:calc(env(safe-area-inset-bottom, 0px) + 84px);right:12px;z-index:2147483647;width:min(240px, calc(100vw - 24px));max-height:70vh;overflow-y:auto;padding:14px;font:14px/1.4 -apple-system,system-ui,sans-serif;color:#fff`,
    }, [badgeEl, readoutEl, moveEl, whyEl, insuranceEl, betEl, countEl, manualBox, betConfig, pluginsSection, canvasSection, debugSection, auditSection, btnReset, statusEl]);
    document.documentElement.appendChild(panel);
  }

  // ---- card reading -----------------------------------------------------
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
  // Best-effort suit detection, used only for the provably-fair hand-history
  // log (strategy/counting only ever need rank). Not exhaustive — many sites
  // never expose suit as text at all, so a card with an unknown suit is
  // logged with '?' rather than guessed.
  const WORD_SUIT = { SPADE: 'S', SPADES: 'S', HEART: 'H', HEARTS: 'H', DIAMOND: 'D', DIAMONDS: 'D', CLUB: 'C', CLUBS: 'C' };
  function suitFromString(s) {
    if (!s) return null;
    const upper = s.toUpperCase();
    for (const w in WORD_SUIT) {
      if (new RegExp(`\\b${w}\\b`).test(upper)) return WORD_SUIT[w];
    }
    const m = upper.match(/(?:^|[_\-\/])(?:10|[2-9]|[AJQK])([SHDC])(?:[_.\-]|$)/);
    return m ? m[1] : null;
  }
  function textSuit(n) {
    for (const attr of ['data-suit', 'data-rank', 'data-card', 'data-code']) {
      const v = n.getAttribute(attr);
      if (v) { const s = suitFromString(v); if (s) return s; }
    }
    const sources = [n.getAttribute('aria-label'), n.getAttribute('title'), (n.innerText || '').trim(), n.getAttribute('src'), n.getAttribute('alt'), classStr(n)];
    for (const src of sources) { const s = suitFromString(src); if (s) return s; }
    return null;
  }
  function classStr(n) {
    const c = n.className;
    if (!c) return '';
    return c.baseVal !== undefined ? c.baseVal : c.toString();
  }
  // Tries each signal in turn and reports which one matched, so the debug
  // panel can show *why* an element was read as a given rank (or wasn't).
  function textRankDetailed(n) {
    for (const attr of ['data-rank', 'data-card', 'data-value', 'data-code', 'data-testid']) {
      const v = n.getAttribute(attr);
      if (v) { const r = rankFromString(v); if (r) return { rank: r, source: attr }; }
    }
    const aria = n.getAttribute('aria-label') || n.getAttribute('title');
    if (aria) { const r = rankFromString(aria); if (r) return { rank: r, source: 'aria-label/title' }; }
    const text = (n.innerText || '').trim();
    if (text) { const r = rankFromString(text); if (r) return { rank: r, source: 'text' }; }
    const src = n.getAttribute('src') || n.getAttribute('xlink:href') || n.getAttribute('href');
    if (src) { const r = rankFromString(src); if (r) return { rank: r, source: 'src/href' }; }
    const alt = n.getAttribute('alt');
    if (alt) { const r = rankFromString(alt); if (r) return { rank: r, source: 'alt' }; }
    let bg = '';
    try { bg = getComputedStyle(n).backgroundImage || ''; } catch (e) { /* unreachable in most engines */ }
    if (bg && bg !== 'none') { const r = rankFromString(bg); if (r) return { rank: r, source: 'background-image' }; }
    const cls = classStr(n);
    if (cls) { const r = rankFromString(cls); if (r) return { rank: r, source: 'class' }; }
    return { rank: null, source: null };
  }
  function textRank(n) { return textRankDetailed(n).rank; }

  const FACE_DOWN_RE = /\b(back|facedown|face-down|hidden|flipped|folded)\b/i;
  function isFaceDown(n) {
    if (FACE_DOWN_RE.test(classStr(n))) return true;
    const probe = [n.getAttribute('data-rank'), n.getAttribute('data-card'), n.getAttribute('alt'), n.getAttribute('src')].filter(Boolean).join(' ');
    return FACE_DOWN_RE.test(probe);
  }

  const CARD_SELECTOR = '[class*="card" i], [data-rank], [data-card], [data-code], [data-suit], [data-value], [data-testid*="card" i], img[src*="card" i], img[alt*="card" i], svg use, use[href*="card" i], object[data*="card" i], [class*="playing-card" i], [id*="card" i]';

  // Last-resort scan when the selector-based pass finds nothing: any small
  // leaf element whose own text is exactly a card rank (± suit letter).
  function fallbackTextScan() {
    return deepQueryAll('*').filter((n) => {
      if (n.children.length > 0) return false;
      const r = n.getBoundingClientRect();
      if (r.width <= 0 || r.width > 80 || r.height > 100) return false;
      const t = (n.innerText || '').trim();
      return /^(10|[2-9]|[AJQK])[SHDC]?$/i.test(t);
    });
  }

  function readTable() {
    const hostname = window.location.hostname;
    const adapter = pluginRegistry.siteAdapters.find((p) => {
      try { return typeof p.matches !== 'function' || p.matches(hostname); }
      catch (e) { return false; }
    });
    if (adapter) {
      try {
        const res = adapter.readTable(pluginCtx());
        if (res && Array.isArray(res.dealer) && Array.isArray(res.player)) {
          return {
            dealer: res.dealer,
            player: res.player,
            dealerEls: Array.isArray(res.dealerEls) ? res.dealerEls : [],
            playerEls: Array.isArray(res.playerEls) ? res.playerEls : [],
            split: !!res.split,
            handCount: res.handCount || 1,
            activeHandIdx: res.activeHandIdx || 0,
          };
        }
        console.error(`[blackjack-advisor] site-adapter "${adapter.id}" returned an invalid shape, falling back`);
      } catch (e) {
        console.error(`[blackjack-advisor] site-adapter "${adapter.id}" threw, falling back:`, e);
      }
    }

    const canvasAdapter = pluginRegistry.canvasAdapters.find((p) => {
      try { return typeof p.matches !== 'function' || p.matches(hostname); }
      catch (e) { return false; }
    });
    if (canvasAdapter) {
      try {
        const regions = canvasAdapter.findCardRegions(pluginCtx());
        if (Array.isArray(regions) && regions.length) {
          const classify = (regs) => regs.map((r) => ({ region: r, ...classifyRegion(canvasAdapter.id, r) }));
          const dealerClassified = classify(regions.filter((r) => r.role === 'dealer'));
          const playerClassified = classify(regions.filter((r) => r.role !== 'dealer'));
          return {
            dealer: dealerClassified.filter((c) => c.rank).map((c) => c.rank),
            player: playerClassified.filter((c) => c.rank).map((c) => c.rank),
            dealerEls: [], playerEls: [],
            split: false, handCount: 1, activeHandIdx: 0,
            canvasClassified: { dealer: dealerClassified, player: playerClassified },
          };
        }
      } catch (e) {
        console.error(`[blackjack-advisor] canvas-adapter "${canvasAdapter.id}" threw, falling back:`, e);
      }
    }

    return genericReadTable();
  }

  function genericReadTable() {
    let cardEls = deepQueryAll(CARD_SELECTOR)
      .filter((n) => n.getBoundingClientRect().width > 0 && !isFaceDown(n));
    let usedFallback = false;
    if (!cardEls.length) { cardEls = fallbackTextScan(); usedFallback = true; }
    const dealerEls = cardEls.filter((n) => /dealer/i.test(classStr(n) + classStr(n.closest('[class*="dealer"]') || document.createElement('div'))));
    const playerEls = cardEls.filter((n) => !dealerEls.includes(n));

    const handContainers = deepQueryAll('[class*="hand"], [data-hand]')
      .filter((n) => n.getBoundingClientRect().width > 0 && !/dealer/i.test(classStr(n)));
    let hands = null, activeHandIdx = 0;
    if (handContainers.length > 1) {
      // Keep each container paired with its ranks while filtering out empty
      // hands, so the "active" index (found by re-scanning class names) is
      // resolved against the same filtered list it will be used to index —
      // filtering handContainers and hands separately would drift the index
      // whenever an earlier hand slot happened to be empty.
      const paired = handContainers
        .map((c) => ({ container: c, ranks: playerEls.filter((el) => c.contains(el)).map(textRank).filter(Boolean) }))
        .filter((p) => p.ranks.length > 0);
      if (paired.length > 1) {
        const activeIdx = paired.findIndex((p) => /active|current|selected|focused?/i.test(classStr(p.container)));
        activeHandIdx = activeIdx !== -1 ? activeIdx : paired.length - 1;
        hands = paired.map((p) => p.ranks);
      }
    }

    return {
      dealer: dealerEls.map(textRank).filter(Boolean),
      player: hands ? hands[activeHandIdx] : playerEls.map(textRank).filter(Boolean),
      dealerEls, playerEls,
      split: !!hands,
      handCount: hands ? hands.length : 1,
      activeHandIdx,
      ambiguousFallback: usedFallback && cardEls.length > 0 && dealerEls.length === 0,
    };
  }

  function countNewCards(els) {
    for (const n of els) {
      const r = textRank(n);
      if (!r) continue;
      if (countedNodes.get(n) === r) continue;
      logCard(r);
      countedNodes.set(n, r);
      const suit = textSuit(n);
      dealHistory.push({ code: r + (suit || '?'), rank: r, suit: suit || null, t: Date.now() });
    }
  }

  function countNewRegions(classified) {
    for (const c of classified) {
      if (!c.rank) continue;
      const key = c.region.id || `${c.region.x},${c.region.y}`;
      if (countedRegions.get(key) === c.rank) continue;
      logCard(c.rank);
      countedRegions.set(key, c.rank);
      // Canvas classification only ever identifies rank (see classifyRegion) —
      // suit isn't part of the calibrated template — so these entries always
      // carry an unknown suit. Still logged, so the provably-fair hand
      // history isn't silently empty for canvas-only tables.
      dealHistory.push({ code: c.rank + '?', rank: c.rank, suit: null, t: Date.now() });
    }
  }

  // ---- detection diagnostics ---------------------------------------------
  // Read-only: re-runs the same selector/fallback pass genericReadTable()
  // uses, but keeps every candidate (including rejects) with the reason it
  // matched, so a stuck site can be debugged from the panel instead of guesswork.
  function diagnoseTable() {
    const primary = deepQueryAll(CARD_SELECTOR).filter((n) => n.getBoundingClientRect().width > 0);
    const usedFallback = primary.length === 0;
    const candidates = usedFallback ? fallbackTextScan() : primary;
    const rows = candidates.map((n) => {
      const faceDown = !usedFallback && isFaceDown(n);
      const detail = faceDown ? { rank: null, source: null } : textRankDetailed(n);
      return {
        el: n,
        rank: detail.rank,
        matchedVia: usedFallback ? 'fallback-text' : detail.source,
        faceDown,
        dealer: /dealer/i.test(classStr(n) + classStr(n.closest('[class*="dealer"]') || document.createElement('div'))),
      };
    });
    return { rows, usedFallback, canvases: deepQueryAll('canvas').filter((c) => c.getBoundingClientRect().width > 0) };
  }

  function flashHighlight(el) {
    const prevOutline = el.style.outline;
    const prevOffset = el.style.outlineOffset;
    el.style.outline = '3px solid #f43f5e';
    el.style.outlineOffset = '2px';
    try { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) { /* scrollIntoView options unsupported */ }
    setTimeout(() => { el.style.outline = prevOutline; el.style.outlineOffset = prevOffset; }, 1500);
  }

  // ---- shuffle handling ---------------------------------------------------
  const SHUFFLE_RE = /\bshuffl\w*\b|\bnew shoe\b/i;
  let lastShuffleCheck = 0;
  function checkReshuffle() {
    const now = Date.now();
    if (now - lastShuffleCheck < 3000) return;
    lastShuffleCheck = now;
    if (SHUFFLE_RE.test(document.body.innerText.slice(0, 5000))) {
      rcHiLo = 0; cardsSeen = 0; countedNodes = new Map(); countedRegions = new Map(); dealHistory = [];
      shuffleUnconfirmed = true;
      setBadge('UNCONFIRMED');
      status('shuffle text detected — count reset, tap "Reset shoe" to confirm and resume');
    }
  }

  // ---- canvas fallback ------------------------------------------------------
  let emptyCardTicks = 0;
  function hasLargeCanvas() {
    return deepQueryAll('canvas').some((c) => {
      const r = c.getBoundingClientRect();
      return r.width > 200 && r.height > 150;
    });
  }

  // ---- PLUGIN SYSTEM -----------------------------------------------------
  // Three plugin kinds, all plain object literals the user pastes into the
  // panels below (see EXAMPLE_SITE_ADAPTER / EXAMPLE_CANVAS_ADAPTER / EXAMPLE_A11Y_OUTPUT):
  //
  //   site-adapter    { id, type:'site-adapter', name?, version?, matches(hostname), readTable(ctx) }
  //     readTable(ctx) must return { dealer:[ranks], player:[ranks], dealerEls?:[nodes], playerEls?:[nodes] }
  //     ctx = { deepQueryAll, textRank, classStr, rankFromString, document, canvases }
  //     Omitting dealerEls/playerEls is fine but means those cards won't
  //     feed the Hi-Lo counter (no elements to dedupe against).
  //
  //   canvas-adapter  { id, type:'canvas-adapter', name?, version?, matches(hostname), findCardRegions(ctx) }
  //     findCardRegions(ctx) must return [{ id, role:'dealer'|'player', x, y, w, h }, ...]
  //     in page (viewport) coordinates. `id` must stay stable for the same
  //     visual slot across ticks — it's how the Hi-Lo counter tells "still
  //     the same card" from "a new card was dealt". Used for tables that
  //     render entirely on <canvas>/WebGL with no readable DOM: the advisor
  //     calibrates a small reference template per rank against the region's
  //     pixels (see the "Canvas calibration" panel) and pixel/shape-matches
  //     live regions against those templates. Regions that don't clear the
  //     confidence threshold are left unread rather than guessed.
  //
  //   a11y-output     { id, type:'a11y-output', name?, version?, onUpdate(ctx) }
  //     ctx = { move, why, insurance, bet, betProblems, tc, cardsSeen,
  //             playerHand, dealerUp, split, handCount, badge, status }
  //     Called only when the advisor's state actually changes (deduped).
  //
  // Plugins run as ordinary page scripts — same privileges as anything typed
  // into devtools on this page. They are NOT sandboxed. Only load code you
  // wrote or trust. In the other direction: the advisor itself only ever
  // reads the documented fields back from a plugin's return value — it never
  // calls anything else a plugin exposes, and plugins are never wired up to
  // click buttons or set bet fields.
  const PLUGINS_KEY = 'blackjackAdvisor_plugins_v1';
  const pluginRegistry = { siteAdapters: [], canvasAdapters: [], a11yOutputs: [] };
  let pluginRecords = []; // [{ id, type, name, version, source }] — successfully loaded plugins only

  const EXAMPLE_SITE_ADAPTER = `{
  id: 'my-site-adapter',
  type: 'site-adapter',
  name: 'My Site',
  matches: (hostname) => hostname.includes('example.com'),
  readTable: (ctx) => {
    const cards = ctx.deepQueryAll('.my-card');
    const dealerEls = cards.filter(n => n.closest('.dealer-area'));
    const playerEls = cards.filter(n => !n.closest('.dealer-area'));
    return {
      dealer: dealerEls.map(ctx.textRank).filter(Boolean),
      player: playerEls.map(ctx.textRank).filter(Boolean),
      dealerEls, playerEls,
    };
  },
}`;

  const EXAMPLE_CANVAS_ADAPTER = `{
  id: 'my-canvas-table',
  type: 'canvas-adapter',
  name: 'My Canvas Table',
  matches: (hostname) => hostname.includes('example.com'),
  // Return the pixel rectangles (page/viewport coordinates) where cards
  // render. Each id must stay stable for the same visual slot across ticks.
  // Find these coordinates by inspecting the table (or use "Detect regions"
  // in the Canvas calibration panel once this plugin is loaded, and adjust
  // the numbers below to match what gets highlighted).
  findCardRegions: (ctx) => {
    const canvas = ctx.canvases[0];
    if (!canvas) return [];
    const rect = canvas.getBoundingClientRect();
    return [
      { id: 'dealer-0', role: 'dealer', x: rect.left + 120, y: rect.top + 40, w: 40, h: 56 },
      { id: 'player-0', role: 'player', x: rect.left + 120, y: rect.top + 220, w: 40, h: 56 },
      { id: 'player-1', role: 'player', x: rect.left + 170, y: rect.top + 220, w: 40, h: 56 },
    ];
  },
}`;

  const EXAMPLE_A11Y_OUTPUT = `{
  id: 'speech-announcer',
  type: 'a11y-output',
  name: 'Speech announcer',
  onUpdate: (ctx) => {
    if (!ctx.move) return;
    const msg = ctx.move + (ctx.why ? ', ' + ctx.why : '');
    speechSynthesis.cancel();
    speechSynthesis.speak(new SpeechSynthesisUtterance(msg));
  },
}`;

  function loadStoredPluginSources() {
    try {
      const raw = safeStorage.get(PLUGINS_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) { return []; }
  }
  function savePluginSources() {
    safeStorage.set(PLUGINS_KEY, JSON.stringify(pluginRecords.map((r) => r.source)));
  }

  function evalPlugin(source) {
    let obj;
    try {
      obj = Function('"use strict"; return (' + source + ');')();
    } catch (e) {
      return { ok: false, error: 'parse error: ' + e.message };
    }
    if (!obj || typeof obj !== 'object') return { ok: false, error: 'plugin must evaluate to an object literal' };
    if (!obj.id || typeof obj.id !== 'string') return { ok: false, error: 'plugin needs a string "id"' };
    if (obj.type === 'site-adapter') {
      if (typeof obj.readTable !== 'function') return { ok: false, error: 'site-adapter plugin needs a readTable(ctx) function' };
    } else if (obj.type === 'canvas-adapter') {
      if (typeof obj.findCardRegions !== 'function') return { ok: false, error: 'canvas-adapter plugin needs a findCardRegions(ctx) function' };
    } else if (obj.type === 'a11y-output') {
      if (typeof obj.onUpdate !== 'function') return { ok: false, error: 'a11y-output plugin needs an onUpdate(ctx) function' };
    } else {
      return { ok: false, error: 'plugin "type" must be "site-adapter", "canvas-adapter", or "a11y-output"' };
    }
    return { ok: true, plugin: obj };
  }

  function registryFor(type) {
    if (type === 'site-adapter') return pluginRegistry.siteAdapters;
    if (type === 'canvas-adapter') return pluginRegistry.canvasAdapters;
    return pluginRegistry.a11yOutputs;
  }

  function addPlugin(source, persist) {
    const result = evalPlugin(source);
    if (!result.ok) return result;
    const { plugin } = result;
    pluginRegistry.siteAdapters = pluginRegistry.siteAdapters.filter((p) => p.id !== plugin.id);
    pluginRegistry.canvasAdapters = pluginRegistry.canvasAdapters.filter((p) => p.id !== plugin.id);
    pluginRegistry.a11yOutputs = pluginRegistry.a11yOutputs.filter((p) => p.id !== plugin.id);
    registryFor(plugin.type).push(plugin);
    pluginRecords = pluginRecords.filter((r) => r.id !== plugin.id);
    pluginRecords.push({ id: plugin.id, type: plugin.type, name: plugin.name || plugin.id, version: plugin.version || '', source });
    if (persist !== false) savePluginSources();
    return result;
  }

  function removePlugin(id) {
    pluginRegistry.siteAdapters = pluginRegistry.siteAdapters.filter((p) => p.id !== id);
    pluginRegistry.canvasAdapters = pluginRegistry.canvasAdapters.filter((p) => p.id !== id);
    pluginRegistry.a11yOutputs = pluginRegistry.a11yOutputs.filter((p) => p.id !== id);
    pluginRecords = pluginRecords.filter((r) => r.id !== id);
    savePluginSources();
  }

  function initPlugins() {
    loadStoredPluginSources().forEach((source) => {
      const result = addPlugin(source, false);
      if (!result.ok) console.error('[blackjack-advisor] stored plugin failed to load:', result.error);
    });
  }

  function pluginCtx() {
    return {
      deepQueryAll, textRank, classStr, rankFromString, document,
      canvases: deepQueryAll('canvas').filter((c) => c.getBoundingClientRect().width > 0),
    };
  }

  // ---- canvas pixel/shape matching (calibrated per plugin id + hostname) ----
  // Downsamples a card-slot region to a small grayscale grid plus a red/black
  // color hint, then compares it to reference templates the user captures via
  // the "Canvas calibration" panel. No template guessing: a region that
  // doesn't clear CANVAS_CONFIDENCE_THRESHOLD comes back unread. The
  // threshold and grid size are starting points — tune them against the
  // actual table you're calibrating against.
  const CANVAS_TEMPLATE_W = 14, CANVAS_TEMPLATE_H = 20;
  const CANVAS_CONFIDENCE_THRESHOLD = 0.82;

  function canvasTemplatesKey(adapterId) {
    return 'blackjackAdvisor_canvasTemplates_' + adapterId + '_' + window.location.hostname;
  }
  function loadCanvasTemplates(adapterId) {
    try {
      const raw = safeStorage.get(canvasTemplatesKey(adapterId));
      return raw ? JSON.parse(raw) : {};
    } catch (e) { return {}; }
  }
  function saveCanvasTemplates(adapterId, templates) {
    safeStorage.set(canvasTemplatesKey(adapterId), JSON.stringify(templates));
  }

  function findSourceCanvas(x, y) {
    const atPoint = document.elementFromPoint(x + 1, y + 1);
    if (atPoint && atPoint.tagName === 'CANVAS') return atPoint;
    return deepQueryAll('canvas').find((c) => {
      const r = c.getBoundingClientRect();
      return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
    }) || null;
  }

  function sampleCanvasRegion(x, y, w, h) {
    const canvas = findSourceCanvas(x, y);
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const sx = Math.round((x - rect.left) * scaleX);
    const sy = Math.round((y - rect.top) * scaleY);
    const sw = Math.max(1, Math.round(w * scaleX));
    const sh = Math.max(1, Math.round(h * scaleY));
    let ctx2d;
    try { ctx2d = canvas.getContext('2d'); } catch (e) { return null; }
    if (!ctx2d) return null; // WebGL/other context type — no 2D pixel readback this way
    let imageData;
    try { imageData = ctx2d.getImageData(sx, sy, sw, sh); }
    catch (e) { return null; } // tainted canvas (cross-origin draw without CORS)

    const grid = new Array(CANVAS_TEMPLATE_W * CANVAS_TEMPLATE_H).fill(0);
    let redCount = 0, darkCount = 0, sampleCount = 0;
    for (let gy = 0; gy < CANVAS_TEMPLATE_H; gy++) {
      for (let gx = 0; gx < CANVAS_TEMPLATE_W; gx++) {
        const px = Math.min(sw - 1, Math.floor((gx / CANVAS_TEMPLATE_W) * sw));
        const py = Math.min(sh - 1, Math.floor((gy / CANVAS_TEMPLATE_H) * sh));
        const idx = (py * sw + px) * 4;
        const r = imageData.data[idx], g = imageData.data[idx + 1], b = imageData.data[idx + 2];
        const lum = (r * 0.299 + g * 0.587 + b * 0.114) / 255;
        grid[gy * CANVAS_TEMPLATE_W + gx] = lum;
        if (r > 120 && r > g * 1.4 && r > b * 1.4) redCount++;
        if (lum < 0.35) darkCount++;
        sampleCount++;
      }
    }
    const colorHint = redCount > sampleCount * 0.04 ? 'red' : (darkCount > sampleCount * 0.15 ? 'black' : 'unknown');
    return { grid, colorHint };
  }

  function templateSimilarity(a, b) {
    if (!a || !b || a.length !== b.length) return 0;
    let sumSq = 0;
    for (let i = 0; i < a.length; i++) { const d = a[i] - b[i]; sumSq += d * d; }
    const mse = sumSq / a.length;
    return Math.max(0, 1 - mse * 4);
  }

  function classifyRegion(adapterId, region) {
    const sample = sampleCanvasRegion(region.x, region.y, region.w, region.h);
    if (!sample) return { rank: null, confidence: 0, reason: 'unreadable canvas (tainted or WebGL)' };
    const templates = loadCanvasTemplates(adapterId);
    let best = null, bestScore = 0;
    for (const label in templates) {
      const entry = templates[label];
      if (entry.colorHint && entry.colorHint !== 'unknown' && sample.colorHint !== 'unknown' && entry.colorHint !== sample.colorHint) continue;
      const score = templateSimilarity(sample.grid, entry.grid);
      if (score > bestScore) { bestScore = score; best = label; }
    }
    if (!best || bestScore < CANVAS_CONFIDENCE_THRESHOLD) {
      return { rank: null, confidence: bestScore, reason: best ? 'low confidence' : 'no calibrated templates matched region color' };
    }
    return { rank: best, confidence: bestScore };
  }

  let lastA11ySignature = null;
  function notifyA11yPlugins(state) {
    // Includes the hand itself, not just the recommendation text — two
    // consecutive hits both saying "HIT, basic strategy" must still both
    // reach an accessibility consumer, since the card that changed is the
    // whole reason a second announcement is needed.
    const signature = JSON.stringify([
      state.move, state.why, state.insurance, state.bet, state.badge, state.status,
      state.playerHand, state.dealerUp, state.handCount,
    ]);
    if (signature === lastA11ySignature) return;
    lastA11ySignature = signature;
    for (const p of pluginRegistry.a11yOutputs) {
      try { p.onUpdate(state); }
      catch (e) { console.error(`[blackjack-advisor] a11y plugin "${p.id}" threw:`, e); }
    }
  }

  // ---- main loop (advisory only — never clicks or fills anything) -----------
  function tick() {
    checkReshuffle();
    const { dealer, player, dealerEls, playerEls, split, handCount, canvasClassified, ambiguousFallback } = readTable();
    if (canvasClassified) {
      countNewRegions(canvasClassified.dealer);
      countNewRegions(canvasClassified.player);
    } else {
      countNewCards(dealerEls);
      countNewCards(playerEls);
    }
    const tc = tcHiLo();
    const bet = suggestedBet(tc);
    const problems = validateBetConfig();
    betEl.textContent = problems.length ? 'bet: fix config below' : `suggested bet: ${bet}`;

    const penetration = cardsSeen / (decksInShoe * 52);
    if (penetration * 100 > penetrationWarnPct && !shuffleUnconfirmed) status(`deep in shoe (${Math.round(penetration * 100)}% dealt) — verify a reshuffle hasn't happened`);

    if (!dealer.length || player.length < 2) {
      emptyCardTicks++;
      const shouldOpenManual = ambiguousFallback || (emptyCardTicks > 6 && hasLargeCanvas());
      if (shouldOpenManual && !manualBox.hasAttribute('open')) {
        manualBox.setAttribute('open', 'open');
        if (!everSeenHand) { everSeenHand = true; panel.style.display = 'block'; }
        status(ambiguousFallback
          ? 'found card-like text on the page but couldn\'t tell dealer from player apart — try manual entry, or write a site-adapter plugin'
          : 'no readable DOM cards + canvas table found — manual entry opened below');
      }
      if (everSeenHand) {
        readoutEl.textContent = 'watching...';
        setMove(null);
        whyEl.textContent = '';
        insuranceEl.textContent = '';
        if (!shuffleUnconfirmed) setBadge('WATCHING');
      }
      countEl.textContent = `TC ${tc.toFixed(1)} (${cardsSeen} seen)`;
      notifyA11yPlugins({
        move: null, why: '', insurance: '', bet: null, betProblems: problems, tc, cardsSeen,
        playerHand: [], dealerUp: null, split: false, handCount: 1,
        badge: currentBadgeMode, status: currentStatus,
      });
      return;
    }
    emptyCardTicks = 0;
    if (!everSeenHand) { everSeenHand = true; panel.style.display = 'block'; }
    if (!shuffleUnconfirmed) setBadge('READING');

    readoutEl.textContent = `you: ${player.join(' ')}  dealer: ${dealer[0]}`;
    const res = strategy(player, dealer[0], tc);
    setMove(res.move);
    whyEl.textContent = res.why || '';
    insuranceEl.textContent = res.insurance || '';
    countEl.textContent = `TC ${tc.toFixed(1)} (${cardsSeen} seen)`;
    notifyA11yPlugins({
      move: res.move, why: res.why || '', insurance: res.insurance || '', bet, betProblems: problems, tc, cardsSeen,
      playerHand: player, dealerUp: dealer[0], split: !!split, handCount: handCount || 1,
      badge: currentBadgeMode, status: currentStatus,
    });
  }

  // ---- start / init -----------------------------------------------------
  function startAdvisor() {
    initPlugins();
    buildPanel();
    setInterval(tick, POLL_MS);
    let mutTimer = null;
    const obs = new MutationObserver(() => {
      clearTimeout(mutTimer);
      mutTimer = setTimeout(tick, 150);
    });
    obs.observe(document.body, { childList: true, subtree: true });
    setTimeout(tick, 300);
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
