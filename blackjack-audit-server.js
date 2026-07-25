#!/usr/bin/env node
// Blackjack Advisor — provably-fair audit server
//
// Standalone companion to blackjack-advisor.user.js. Run this on the SAME
// device as the browser that's running the userscript — a browser on your
// phone or PC can't reach a server running somewhere else (a cloud session,
// a different machine). The userscript's "Provably-fair audit" panel talks
// to this over http://127.0.0.1:9999 to check a casino's "provably fair"
// seed commitment and reconstruct its claimed shuffle, independently of
// whatever verify page the casino itself provides.
//
// Usage:
//   node blackjack-audit-server.js
//
// No dependencies — Node's built-in http/crypto only.
//
// Read before running:
//  - Binds to 127.0.0.1 only, not your network.
//  - CORS is wide open (Access-Control-Allow-Origin: *) because the
//    userscript runs on whatever casino domain you're auditing, not a
//    fixed origin — this server can't know that origin in advance. That
//    means any tab you have open, not just the casino, can reach it while
//    it's running. It only does stateless hashing/HMAC computation on
//    whatever you POST to it: no filesystem access, no secrets stored, no
//    state kept between requests. Stop it (Ctrl+C) when you're done
//    auditing.
//  - Implements the HMAC-SHA256 + Fisher-Yates convention used by most
//    "provably fair" crypto casinos. Some platforms combine the seeds
//    differently (different separator, hash algorithm, or byte layout per
//    float) — if your numbers don't match the casino's own verify page,
//    that's the first thing to check. /verify/hmac-floats and
//    /verify/shuffle both accept hashAlgo/separator/bytesPerFloat
//    overrides for exactly that reason.
'use strict';

const http = require('http');
const crypto = require('crypto');

const PORT = 9999;
const HOST = '127.0.0.1';

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function hmacHex(algo, key, message) {
  return crypto.createHmac(algo, key).update(message, 'utf8').digest('hex');
}

// Standard provably-fair float stream:
//   HMAC(serverSeed, `${clientSeed}${sep}${nonce}${sep}${cursor}`)
// sliced into bytesPerFloat-byte chunks, each divided by 2^(bytesPerFloat*8)
// to land in [0,1). Cursor increments once a digest's chunks are exhausted.
function* floatStream({ serverSeed, clientSeed, nonce, hashAlgo = 'sha256', separator = ':', bytesPerFloat = 4 }) {
  let cursor = 0;
  const hexPerFloat = bytesPerFloat * 2;
  for (;;) {
    const digest = hmacHex(hashAlgo, serverSeed, `${clientSeed}${separator}${nonce}${separator}${cursor}`);
    for (let i = 0; i + hexPerFloat <= digest.length; i += hexPerFloat) {
      const chunk = digest.slice(i, i + hexPerFloat);
      yield parseInt(chunk, 16) / Math.pow(2, bytesPerFloat * 8);
    }
    cursor++;
  }
}

function buildDeck(deckCount) {
  const ranks = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'];
  const suits = ['S', 'H', 'D', 'C'];
  const deck = [];
  for (let d = 0; d < deckCount; d++) {
    for (const s of suits) for (const r of ranks) deck.push(r + s);
  }
  return deck;
}

function fisherYatesShuffle(deck, floats) {
  const arr = deck.slice();
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(floats.next().value * (i + 1));
    const tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
  }
  return arr;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) { reject(new Error('body too large')); req.destroy(); }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Private-Network': 'true',
  });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { send(res, 204, {}); return; }

  if (req.method === 'GET' && req.url === '/health') {
    send(res, 200, { ok: true, name: 'blackjack-audit-server', version: '1.0.0' });
    return;
  }

  let body;
  try { body = JSON.parse((await readBody(req)) || '{}'); }
  catch (e) { send(res, 400, { error: 'invalid JSON body' }); return; }

  try {
    if (req.method === 'POST' && req.url === '/verify/commit') {
      const { serverSeed, commitHash } = body;
      if (!serverSeed || !commitHash) { send(res, 400, { error: 'serverSeed and commitHash are required' }); return; }
      const computed = sha256Hex(serverSeed);
      send(res, 200, { computedHash: computed, match: computed.toLowerCase() === String(commitHash).toLowerCase() });
      return;
    }

    if (req.method === 'POST' && req.url === '/verify/hmac-floats') {
      const { serverSeed, clientSeed, nonce, count = 16, hashAlgo, separator, bytesPerFloat } = body;
      if (!serverSeed || clientSeed === undefined || nonce === undefined) {
        send(res, 400, { error: 'serverSeed, clientSeed, and nonce are required' }); return;
      }
      const gen = floatStream({ serverSeed, clientSeed, nonce, hashAlgo, separator, bytesPerFloat });
      const floats = [];
      for (let i = 0; i < Math.min(Number(count) || 16, 512); i++) floats.push(gen.next().value);
      send(res, 200, { floats });
      return;
    }

    if (req.method === 'POST' && req.url === '/verify/shuffle') {
      const { serverSeed, clientSeed, nonce, deckCount = 1, hashAlgo, separator, bytesPerFloat } = body;
      if (!serverSeed || clientSeed === undefined || nonce === undefined) {
        send(res, 400, { error: 'serverSeed, clientSeed, and nonce are required' }); return;
      }
      const deck = buildDeck(Math.max(1, Math.min(8, Number(deckCount) || 1)));
      const gen = floatStream({ serverSeed, clientSeed, nonce, hashAlgo, separator, bytesPerFloat });
      const shuffled = fisherYatesShuffle(deck, gen);
      send(res, 200, { deckSize: shuffled.length, order: shuffled });
      return;
    }

    send(res, 404, { error: 'unknown endpoint', endpoints: ['GET /health', 'POST /verify/commit', 'POST /verify/hmac-floats', 'POST /verify/shuffle'] });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[blackjack-audit-server] listening on http://${HOST}:${PORT}`);
  console.log('  GET  /health');
  console.log('  POST /verify/commit        { serverSeed, commitHash }');
  console.log('  POST /verify/hmac-floats   { serverSeed, clientSeed, nonce, count? }');
  console.log('  POST /verify/shuffle       { serverSeed, clientSeed, nonce, deckCount? }');
});
