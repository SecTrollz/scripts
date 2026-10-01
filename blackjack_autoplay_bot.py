#!/usr/bin/env python3
"""
Blackjack Advisor - Fully Autonomous
No manual teaching, auto-discovers all selectors.
Run: python3 autobot.py --url https://casino.com/blackjack
"""

import asyncio
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from argparse import ArgumentParser

from playwright.async_api import async_playwright, Browser, Page, Frame, ElementHandle

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("blackjack_advisor")

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
CACHE_FILE = "selectors_cache.json"
HEARTBEAT_TIMEOUT = 5.0
STATE_TIMEOUT = 4.0
MAX_CLICK_RETRIES = 3
MAX_NULL_CLICKS = 3

# ------------------------------------------------------------------------------
# 1. JavaScript Hook
# ------------------------------------------------------------------------------
GAME_HOOK_SCRIPT = r"""
(function() {
    if (window.__bja_installed) return;
    window.__bja_installed = true;

    if (window.__bjaHeartbeat) {
        window.__bjaHeartbeat(window.location.href);
    }

    let lastState = null;
    function emitState(state) {
        const s = JSON.stringify(state);
        if (s === lastState) return;
        lastState = s;
        if (window.__bjaCardState) {
            window.__bjaCardState(state);
        }
    }

    function scan() {
        const state = { dealer: [], player: [], buttons: [] };
        const body = document.body;
        if (!body) return state;

        const patterns = {
            HIT: /hit|h/i,
            STAND: /stand|st/i,
            DOUBLE: /double|dbl/i,
            SPLIT: /split|sp/i,
            SURRENDER: /surrender|surr/i,
            DEAL: /deal|bet|new game|new round|start|play/i
        };
        const allBtns = document.querySelectorAll('button, [role="button"], [data-action], .btn, [class*="button"], [class*="Button"]');
        for (const btn of allBtns) {
            const text = (btn.innerText || btn.getAttribute('aria-label') || btn.getAttribute('title') || '').trim();
            const lower = text.toLowerCase();
            for (const [action, pat] of Object.entries(patterns)) {
                if (pat.test(lower)) {
                    state.buttons.push({ action, text });
                    break;
                }
            }
        }

        function getRankSuit(el) {
            const text = el.textContent || '';
            const suitMatch = text.match(/[♠♥♦♣]/);
            const rankMatch = text.match(/[2-9JQKA]|10/);
            if (suitMatch && rankMatch) return { rank: rankMatch[0], suit: suitMatch[0] };

            const rankAttr = el.getAttribute('data-rank') || el.getAttribute('data-card') || el.getAttribute('data-value');
            const suitAttr = el.getAttribute('data-suit') || el.getAttribute('data-card-suit');
            if (rankAttr && suitAttr) return { rank: rankAttr, suit: suitAttr };

            const img = el.querySelector('img');
            if (img) {
                const alt = (img.getAttribute('alt') || '').toLowerCase();
                const src = (img.getAttribute('src') || '').toLowerCase();
                const combined = alt + src;
                const rm = combined.match(/(2|3|4|5|6|7|8|9|10|j|q|k|a)/);
                const sm = combined.match(/♠|♥|♦|♣|spade|heart|diamond|club/);
                if (rm && sm) return { rank: rm[0].toUpperCase(), suit: sm[0] };
            }
            return null;
        }

        function findCards(container) {
            const cards = [];
            const seen = new Set();
            const candidates = container.querySelectorAll('[class*="card"], [class*="Card"], [data-card], [data-rank]');
            for (const el of candidates) {
                const info = getRankSuit(el);
                if (info) {
                    const key = info.rank + info.suit;
                    if (!seen.has(key)) {
                        seen.add(key);
                        cards.push(info);
                    }
                }
            }
            if (cards.length === 0) {
                const all = container.querySelectorAll('*');
                for (const el of all) {
                    const info = getRankSuit(el);
                    if (info) {
                        const key = info.rank + info.suit;
                        if (!seen.has(key)) {
                            seen.add(key);
                            cards.push(info);
                        }
                    }
                }
            }
            return cards;
        }

        const dealerZones = document.querySelectorAll('[class*="dealer"], [id*="dealer"], [class*="opponent"], [class*="banker"]');
        const playerZones = document.querySelectorAll('[class*="player"], [id*="player"], [class*="user"], [class*="hand"]');

        let dealerCards = [], playerCards = [];
        if (dealerZones.length) {
            for (const zone of dealerZones) {
                dealerCards = dealerCards.concat(findCards(zone));
            }
        }
        if (playerZones.length) {
            for (const zone of playerZones) {
                playerCards = playerCards.concat(findCards(zone));
            }
        }
        if (!dealerCards.length && !playerCards.length) {
            const rect = body.getBoundingClientRect();
            const mid = rect.height / 2;
            const all = body.querySelectorAll('*');
            for (const el of all) {
                const r = el.getBoundingClientRect();
                const info = getRankSuit(el);
                if (!info) continue;
                if (r.top < mid) dealerCards.push(info);
                else playerCards.push(info);
            }
        }

        function unique(arr) {
            const seen = new Set();
            return arr.filter(c => {
                const key = c.rank + c.suit;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
        }
        state.dealer = unique(dealerCards);
        state.player = unique(playerCards);

        return state;
    }

    let observer = null;
    function startObserver() {
        if (observer || !document.body) return;
        observer = new MutationObserver(() => {
            const state = scan();
            if (state.dealer.length || state.player.length) emitState(state);
        });
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['src', 'data-card', 'data-rank', 'style', 'class']
        });
    }
    if (document.body) startObserver();
    else document.addEventListener('DOMContentLoaded', startObserver);

    document.addEventListener('click', () => {
        setTimeout(() => {
            const state = scan();
            if (state.dealer.length || state.player.length) emitState(state);
        }, 150);
    }, true);

    setInterval(() => {
        const state = scan();
        if (state.dealer.length || state.player.length) emitState(state);
    }, 3000);

    setTimeout(() => {
        const state = scan();
        if (state.dealer.length || state.player.length) emitState(state);
    }, 0);
    setTimeout(() => {
        const state = scan();
        if (state.dealer.length || state.player.length) emitState(state);
    }, 2000);

    window.__bja_scan = scan;
    window.__bja_scan_now = () => { const s = scan(); emitState(s); return s; };
})();
"""

# ------------------------------------------------------------------------------
# 2. Strategy
# ------------------------------------------------------------------------------
class Strategy:
    """Full basic strategy tables for hard, soft, and pair hands."""

    HARD = {
        # 2    3    4    5    6    7    8    9   10    A
        4:  ['H','H','H','H','H','H','H','H','H','H'],
        5:  ['H','H','H','H','H','H','H','H','H','H'],
        6:  ['H','H','H','H','H','H','H','H','H','H'],
        7:  ['H','H','H','H','H','H','H','H','H','H'],
        8:  ['H','H','H','H','H','H','H','H','H','H'],
        9:  ['H','D','D','D','D','H','H','H','H','H'],
        10: ['D','D','D','D','D','D','D','D','H','H'],
        11: ['D','D','D','D','D','D','D','D','D','H'],
        12: ['H','H','S','S','S','H','H','H','H','H'],
        13: ['S','S','S','S','S','H','H','H','H','H'],
        14: ['S','S','S','S','S','H','H','H','H','H'],
        15: ['S','S','S','S','S','H','H','H','H','H'],
        16: ['S','S','S','S','S','H','H','H','H','H'],
        17: ['S','S','S','S','S','S','S','S','S','S'],
        18: ['S','S','S','S','S','S','S','S','S','S'],
        19: ['S','S','S','S','S','S','S','S','S','S'],
        20: ['S','S','S','S','S','S','S','S','S','S'],
        21: ['S','S','S','S','S','S','S','S','S','S'],
    }

    SOFT = {
        # 2    3    4    5    6    7    8    9   10    A
        13: ['H','H','H','D','D','H','H','H','H','H'],  # A+2
        14: ['H','H','H','D','D','H','H','H','H','H'],  # A+3
        15: ['H','H','D','D','D','H','H','H','H','H'],  # A+4
        16: ['H','H','D','D','D','H','H','H','H','H'],  # A+5
        17: ['H','D','D','D','D','H','H','H','H','H'],  # A+6
        18: ['S','D','D','D','D','S','S','H','H','H'],  # A+7
        19: ['S','S','S','S','S','S','S','S','S','S'],  # A+8
        20: ['S','S','S','S','S','S','S','S','S','S'],  # A+9
        21: ['S','S','S','S','S','S','S','S','S','S'],
    }

    PAIRS = {
        # 2    3    4    5    6    7    8    9   10    A
        2:   ['P','P','P','P','P','P','H','H','H','H'],
        3:   ['P','P','P','P','P','P','H','H','H','H'],
        4:   ['H','H','P','P','P','H','H','H','H','H'],
        5:   ['D','D','D','D','D','D','D','D','H','H'],
        6:   ['P','P','P','P','P','H','H','H','H','H'],
        7:   ['P','P','P','P','P','P','H','H','H','H'],
        8:   ['P','P','P','P','P','P','P','P','P','P'],
        9:   ['P','P','P','P','P','S','P','P','S','S'],
        10:  ['S','S','S','S','S','S','S','S','S','S'],
        'A': ['P','P','P','P','P','P','P','P','P','P'],
    }

    @classmethod
    def get_action(cls, player_cards: List[dict], dealer_upcard: int,
                   can_double: bool, can_split: bool, count: int) -> str:
        if not (2 <= dealer_upcard <= 11):
            return 'HIT'

        # ---- Pair ----
        if len(player_cards) == 2 and player_cards[0].get('rank') == player_cards[1].get('rank'):
            rank = str(player_cards[0].get('rank', '')).upper()
            if rank in ('J', 'Q', 'K'):
                pair_key = 10
            elif rank == 'A':
                pair_key = 'A'
            elif rank.isdigit():
                pair_key = int(rank)
            else:
                pair_key = None

            if pair_key in cls.PAIRS:
                action = cls.PAIRS[pair_key][dealer_upcard - 2]
                if action == 'P':
                    if can_split:
                        return 'SPLIT'
                    # fall through to soft/hard
                else:
                    if action == 'D' and not can_double:
                        action = 'H'
                    return action

        # ---- Soft ----
        total = cls.hand_total(player_cards)
        if any(str(c.get('rank', '')).upper() == 'A' for c in player_cards) and total <= 21:
            if total in cls.SOFT:
                action = cls.SOFT[total][dealer_upcard - 2]
                if action == 'D':
                    return 'DOUBLE' if can_double else 'HIT'
                return action

        # ---- Hard ----
        if total in cls.HARD:
            action = cls.HARD[total][dealer_upcard - 2]
            if action == 'D':
                return 'DOUBLE' if can_double else 'HIT'
            return action
        return 'HIT'

    @staticmethod
    def hand_total(cards: List[dict]) -> int:
        total = 0
        aces = 0
        for c in cards:
            rank = str(c.get('rank', '')).upper()
            if rank == 'A':
                aces += 1
                total += 11
            elif rank in ('J', 'Q', 'K'):
                total += 10
            elif rank.isdigit():
                total += int(rank)
        while total > 21 and aces > 0:
            total -= 10
            aces -= 1
        return total

    @staticmethod
    def hi_lo_bet_multiple(count: int) -> int:
        if count <= 0: return 1
        if count <= 2: return 2
        if count <= 4: return 3
        return 4

# ------------------------------------------------------------------------------
# 3. Selector Cache
# ------------------------------------------------------------------------------
class SelectorCache:
    def __init__(self, filename=CACHE_FILE):
        self.filename = filename
        self.data = {}
        self.load()

    def load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    self.data = json.load(f)
            except Exception:
                self.data = {}
        else:
            self.data = {}

    def save(self):
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save selector cache: {e}")

    def get(self, domain: str, action: str) -> Optional[str]:
        return self.data.get(domain, {}).get(action)

    def set(self, domain: str, action: str, selector: str):
        if domain not in self.data:
            self.data[domain] = {}
        self.data[domain][action] = selector
        self.save()

# ------------------------------------------------------------------------------
# 4. Main Automation Class
# ------------------------------------------------------------------------------
class BlackjackAdvisor:
    def __init__(self, headless: bool = False, rounds: int = 100, bet_unit: int = 1):
        self.headless = headless
        self.rounds = rounds
        self.bet_unit = bet_unit
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        self.cache = SelectorCache()
        self.confirmed_frames: Set[str] = set()
        self.last_state_update = time.time()
        self.null_click_count = 0
        self.count = 0
        self.current_state: Dict[str, Any] = {}
        self._stop = False

    # ---- Lifecycle ----
    async def launch(self, url: str):
        p = await async_playwright().start()
        self.browser = await p.chromium.launch(
            headless=self.headless,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                '--disable-setuid-sandbox',
            ]
        )
        context = await self.browser.new_context(
            viewport={'width': 1280, 'height': 800},
            user_agent=('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/120.0.0.0 Safari/537.36')
        )
        self.page = await context.new_page()

        await self.page.expose_function("__bjaHeartbeat", self._on_heartbeat)
        await self.page.expose_function("__bjaCardState", self._on_card_state)

        logger.info(f"Navigating to {url}")
        await self.page.goto(url, wait_until='domcontentloaded')
        try:
            await self.page.wait_for_load_state('networkidle', timeout=15000)
        except Exception:
            pass

        await self._inject_hooks(self.page.main_frame)

        self.page.on('frameattached', self._on_frame_attached)
        self.page.on('framenavigated', self._on_frame_navigated)
        await self._sweep_frames()

        start = time.time()
        while time.time() - start < HEARTBEAT_TIMEOUT:
            if self.confirmed_frames:
                logger.info(f"Confirmed frames: {self.confirmed_frames}")
                break
            await asyncio.sleep(0.5)
        if not self.confirmed_frames:
            logger.warning("No heartbeat received from any frame.")

        logger.info("Launch complete.")

    async def close(self):
        self._stop = True
        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass

    # ---- Injection ----
    async def _inject_hooks(self, frame: Frame):
        try:
            await frame.evaluate(GAME_HOOK_SCRIPT)
            logger.debug(f"Injected hooks into {frame.url}")
        except Exception as e:
            logger.warning(f"Injection failed for {frame.url}: {e}")

    async def _on_frame_attached(self, frame: Frame):
        if frame.parent_frame:
            logger.info(f"Frame attached: {frame.url}")
            await self._inject_hooks(frame)

    async def _on_frame_navigated(self, frame: Frame):
        if frame.parent_frame:
            logger.info(f"Frame navigated: {frame.url}")
            await self._inject_hooks(frame)

    async def _sweep_frames(self):
        if not self.page:
            return
        for frame in self.page.frames:
            await self._inject_hooks(frame)

    # ---- Callbacks ----
    async def _on_heartbeat(self, url: str):
        self.confirmed_frames.add(url)
        logger.info(f"Heartbeat from {url}")

    async def _on_card_state(self, state: dict):
        self.last_state_update = time.time()
        self.current_state = state
        dealer = state.get('dealer', [])
        player = state.get('player', [])
        for c in dealer + player:
            rank = str(c.get('rank', '')).upper()
            if rank in ('2', '3', '4', '5', '6'):
                self.count += 1
            elif rank in ('10', 'J', 'Q', 'K', 'A'):
                self.count -= 1
        logger.info(f"State: Dealer {len(dealer)} cards, Player {len(player)} cards, Count {self.count}")

    # ---- Auto-discovery ----
    async def _discover_action_button(self, action: str, frame: Frame) -> Optional[str]:
        keywords = {
            'HIT': ['hit'],
            'STAND': ['stand'],
            'DOUBLE': ['double', 'dbl'],
            'SPLIT': ['split'],
            'SURRENDER': ['surrender', 'surr'],
            'DEAL': ['deal', 'bet', 'new game', 'new round', 'start', 'play']
        }.get(action, [action.lower()])

        try:
            selector = await frame.evaluate("""
                (keywords) => {
                    const all = document.querySelectorAll('button, [role="button"], [data-action], .btn, [class*="button"], [class*="Button"]');
                    let best = null, bestScore = 0;
                    for (const el of all) {
                        const r = el.getBoundingClientRect();
                        if (r.width < 2 || r.height < 2) continue;
                        const text = (el.innerText || el.getAttribute('aria-label') || el.getAttribute('title') || '').trim().toLowerCase();
                        const dataAction = (el.getAttribute('data-action') || '').toLowerCase();
                        const cls = (el.className || '').toString().toLowerCase();
                        let score = 0;
                        for (const kw of keywords) {
                            if (text === kw) score += 20;
                            else if (text.includes(kw)) score += 10;
                            if (dataAction.includes(kw)) score += 8;
                            if (cls.includes(kw)) score += 4;
                        }
                        if (score > bestScore) {
                            bestScore = score;
                            best = el;
                        }
                    }
                    if (!best || bestScore < 6) return null;
                    if (best.id) return '#' + CSS.escape(best.id);
                    if (best.dataset && best.dataset.action)
                        return `[data-action="${best.dataset.action}"]`;
                    // nth-of-type path
                    const parts = [];
                    let cur = best;
                    for (let i = 0; i < 4 && cur && cur.nodeType === 1; i++) {
                        let tag = cur.tagName.toLowerCase();
                        if (cur.id) { parts.unshift('#' + CSS.escape(cur.id)); break; }
                        let idx = 1;
                        let sib = cur;
                        while ((sib = sib.previousElementSibling)) {
                            if (sib.tagName === cur.tagName) idx++;
                        }
                        parts.unshift(`${tag}:nth-of-type(${idx})`);
                        cur = cur.parentElement;
                    }
                    return parts.join(' > ');
                }
            """, keywords)
        except Exception as e:
            logger.debug(f"discover_action_button failed: {e}")
            return None

        if selector:
            logger.info(f"Discovered selector for {action}: {selector}")
        return selector

    async def _discover_card_areas(self, frame: Frame) -> Tuple[Optional[str], Optional[str]]:
        try:
            result = await frame.evaluate("""
                () => {
                    const dealer = [], player = [];
                    const dSel = document.querySelectorAll('[class*="dealer"], [id*="dealer"], [class*="opponent"], [class*="banker"]');
                    for (const el of dSel) {
                        if (el.children.length) {
                            dealer.push(el.tagName.toLowerCase() + (el.id ? '#'+el.id : '') + (el.className ? '.'+el.className.toString().replace(/ /g,'.') : ''));
                        }
                    }
                    const pSel = document.querySelectorAll('[class*="player"], [id*="player"], [class*="user"], [class*="hand"]');
                    for (const el of pSel) {
                        if (el.children.length) {
                            player.push(el.tagName.toLowerCase() + (el.id ? '#'+el.id : '') + (el.className ? '.'+el.className.toString().replace(/ /g,'.') : ''));
                        }
                    }
                    return { dealer: dealer[0] || null, player: player[0] || null };
                }
            """)
            return result.get('dealer'), result.get('player')
        except Exception:
            return None, None

    # ---- Clicking ----
    async def _click_action(self, action: str, frame: Frame) -> bool:
        domain = 'default'
        try:
            from urllib.parse import urlparse
            domain = urlparse(self.page.url).netloc or 'default'
        except Exception:
            pass

        # 1. Cached
        selector = self.cache.get(domain, action)
        if selector and await self._try_click_selector(selector):
            return True

        # 2. Auto-discover
        for f in self.page.frames:
            sel = await self._discover_action_button(action, f)
            if sel and await self._try_click_selector(sel):
                self.cache.set(domain, action, sel)
                return True

        # 3. Fallback: text selectors
        keywords = {
            'HIT': ['hit'],
            'STAND': ['stand'],
            'DOUBLE': ['double', 'dbl'],
            'SPLIT': ['split'],
            'SURRENDER': ['surrender', 'surr'],
            'DEAL': ['deal', 'bet', 'new game', 'new round', 'start', 'play']
        }.get(action, [action.lower()])

        for kw in keywords:
            for f in self.page.frames:
                for sel in (f"button:has-text('{kw}')",
                            f"[role='button']:has-text('{kw}')",
                            f"[data-action*='{kw}']"):
                    if await self._try_click_selector(sel, f):
                        return True

        logger.warning(f"Could not find button for action: {action}")
        return False

    async def _try_click_selector(self, selector: str, frame: Optional[Frame] = None) -> bool:
        if not self.page:
            return False
        frames = [frame] if frame else self.page.frames
        for f in frames:
            try:
                loc = f.locator(selector).first
                if await loc.count() == 0:
                    continue
                if not await loc.is_visible():
                    continue
                await loc.click(timeout=1500)
                logger.info(f"Clicked {selector} in {f.url}")
                return True
            except Exception:
                continue
        return False

    # ---- Autoplay ----
    async def autoplay(self):
        if not self.page:
            raise RuntimeError("Not launched")
        frame = self.page.main_frame

        for round_num in range(1, self.rounds + 1):
            if self._stop:
                break

            if time.time() - self.last_state_update > STATE_TIMEOUT * 2:
                logger.warning("State timeout, re-scanning...")
                await self._sweep_frames()
                try:
                    await frame.evaluate("window.__bja_scan_now && window.__bja_scan_now()")
                except Exception:
                    pass
                await asyncio.sleep(1.0)
                continue

            state = self.current_state or {}
            dealer_cards = state.get('dealer', []) or []
            player_cards = state.get('player', []) or []
            buttons = {b.get('action') for b in (state.get('buttons') or [])}

            # Nothing yet → wait
            if not dealer_cards and not player_cards:
                # If there is a DEAL button, click it to start a hand
                if 'DEAL' in buttons:
                    await self._click_action('DEAL', frame)
                    await asyncio.sleep(1.5)
                else:
                    await asyncio.sleep(1.0)
                continue

            # Player hasn't been dealt yet but dealer has → wait
            if not player_cards:
                await asyncio.sleep(0.5)
                continue

            upcard = Strategy.hand_total([dealer_cards[0]]) if dealer_cards else 0
            if not (2 <= upcard <= 11):
                await asyncio.sleep(0.5)
                continue

            can_double = len(player_cards) == 2 and 'DOUBLE' in buttons
            can_split = (len(player_cards) == 2 and 'SPLIT' in buttons and
                         str(player_cards[0].get('rank', '')).upper() ==
                         str(player_cards[1].get('rank', '')).upper())

            action = Strategy.get_action(player_cards, upcard, can_double, can_split, self.count)
            total = Strategy.hand_total(player_cards)
            logger.info(f"Round {round_num}: Player {player_cards} (={total}), "
                        f"Dealer up {upcard}, Action: {action}")

            ok = await self._click_action(action, frame)
            if ok:
                self.null_click_count = 0
            else:
                self.null_click_count += 1
                if self.null_click_count >= MAX_NULL_CLICKS:
                    logger.error("Null click limit reached, stopping.")
                    break

            await asyncio.sleep(1.5)

        logger.info("Autoplay finished.")

    # ---- Run ----
    async def run(self, url: str):
        await self.launch(url)
        try:
            await self.autoplay()
        finally:
            if not self.headless:
                try:
                    input("Press Enter to close browser...")
                except EOFError:
                    pass
            await self.close()

# ------------------------------------------------------------------------------
# 5. Entry point
# ------------------------------------------------------------------------------
async def main():
    parser = ArgumentParser(description="Autonomous Blackjack Advisor")
    parser.add_argument('--url', required=True, help='Casino blackjack table URL')
    parser.add_argument('--headless', action='store_true', help='Run headless')
    parser.add_argument('--rounds', type=int, default=100, help='Number of hands to play')
    parser.add_argument('--bet', type=int, default=1, help='Base bet unit')
    args = parser.parse_args()

    advisor = BlackjackAdvisor(headless=args.headless,
                               rounds=args.rounds,
                               bet_unit=args.bet)
    try:
        await advisor.run(args.url)
    except KeyboardInterrupt:
        logger.info("Interrupted")
    finally:
        await advisor.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
