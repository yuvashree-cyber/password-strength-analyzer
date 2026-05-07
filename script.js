/**
 * PassGuard — Password Strength Analyzer
 * Fixed: accurate scoring, pattern detection, per-entry delete, better recs
 */

(() => {
  'use strict';

  /* ── DOM ── */
  const $ = id => document.getElementById(id);
  const pwInput       = $('password');
  const eyeBtn        = $('eyeBtn');
  const charCount     = $('charCount');
  const barFill       = $('barFill');
  const strengthPill  = $('strengthPill');
  const statEntropy   = $('statEntropy');
  const statCrack     = $('statCrack');
  const statPool      = $('statPool');
  const recList       = $('recList');
  const btnGenerate   = $('btnGenerate');
  const generatedWrap = $('generatedWrap');
  const genText       = $('genText');
  const copyBtn       = $('copyBtn');
  const copyLabel     = $('copyLabel');
  const saveBtn       = $('saveBtn');
  const clearBtn      = $('clearBtn');
  const histList      = $('histList');
  const reuseBanner   = $('reuseBanner');

  /* ── COMMON PASSWORDS ── */
  const COMMON = new Set([
    'password','123456','12345678','qwerty','abc123','monkey','letmein',
    'trustno1','dragon','baseball','iloveyou','master','sunshine','ashley',
    'bailey','passw0rd','shadow','123123','654321','superman','qazwsx',
    'michael','football','password1','password123','welcome','login','admin',
    'pass','test','hello','hello123','1234','12345','123456789','000000',
    'qwerty123','iloveyou1','princess','rockyou','charlie','donald','freedom',
    'password12','password2','password11','password9','pass123','pass1234',
    'abc1234','abcd1234','letmein1','admin123','root','guest','user',
  ]);

  /* ── STRENGTH LEVELS ── */
  const LEVELS = [
    { label: 'Too Short', cls: 'weak',   color: '#f87171', pct: 8   },
    { label: 'Weak',      cls: 'weak',   color: '#f87171', pct: 25  },
    { label: 'Fair',      cls: 'fair',   color: '#fb923c', pct: 50  },
    { label: 'Good',      cls: 'good',   color: '#facc15', pct: 75  },
    { label: 'Strong',    cls: 'strong', color: '#4ade80', pct: 100 },
  ];

  /* ── PATTERN DETECTION ── */
  function detectPatterns(pw) {
    const lower = pw.toLowerCase();
    const flags = [];

    // Word + digits only (e.g. Password123, hello99, admin2024)
    if (/^[a-zA-Z]+\d+$/.test(pw))
      flags.push('word_digits');

    // Digits + word (e.g. 123password)
    if (/^\d+[a-zA-Z]+$/.test(pw))
      flags.push('digits_word');

    // Keyboard walks
    const walks = ['qwerty','qwert','asdf','asdfg','zxcv','zxcvb','1234','12345','9876','abcd'];
    if (walks.some(w => lower.includes(w)))
      flags.push('keyboard_walk');

    // Repeated characters (aaa, 111)
    if (/(.)\1{2,}/.test(pw))
      flags.push('repeated_chars');

    // All same character type only (only letters OR only digits)
    if (/^[a-zA-Z]+$/.test(pw)) flags.push('only_letters');
    if (/^\d+$/.test(pw))        flags.push('only_digits');

    // Leet speak common substitutions that people think are clever
    const leet = lower.replace(/0/g,'o').replace(/1/g,'i').replace(/3/g,'e').replace(/4/g,'a').replace(/5/g,'s').replace(/@/g,'a');
    if (COMMON.has(leet) && leet !== lower)
      flags.push('leet_common');

    return flags;
  }

  /* ── SCORING ── */
  function score(pw) {
    if (!pw) return -1;

    const len      = pw.length;
    const hasUp    = /[A-Z]/.test(pw);
    const hasLo    = /[a-z]/.test(pw);
    const hasNm    = /[0-9]/.test(pw);
    const hasSy    = /[^a-zA-Z0-9]/.test(pw);
    const isCommon = COMMON.has(pw.toLowerCase());
    const patterns = detectPatterns(pw);

    // Too short — absolute floor
    if (len < 6) return 0;

    // Common password list → always Weak
    if (isCommon) return 1;

    // Leet-speak of a common password → Weak
    if (patterns.includes('leet_common')) return 1;

    // Start scoring
    let pts = 0;

    // Length scoring (most important factor)
    if (len >= 8)  pts += 1;
    if (len >= 12) pts += 1;
    if (len >= 16) pts += 1;

    // Character variety
    if (hasUp)  pts += 1;
    if (hasLo)  pts += 1;
    if (hasNm)  pts += 1;
    if (hasSy)  pts += 2; // symbols are worth more

    // Penalties for weak patterns
    if (patterns.includes('word_digits'))    pts -= 2; // Password123 type
    if (patterns.includes('digits_word'))    pts -= 2;
    if (patterns.includes('keyboard_walk'))  pts -= 2;
    if (patterns.includes('repeated_chars')) pts -= 1;
    if (patterns.includes('only_letters'))   pts -= 1;
    if (patterns.includes('only_digits'))    pts -= 2;

    // Map points to levels
    if (pts <= 2) return 1; // Weak
    if (pts <= 4) return 2; // Fair
    if (pts <= 6) return 3; // Good
    return 4;               // Strong
  }

  /* ── ENTROPY ── */
  function calcEntropy(pw) {
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
    return { bits: pool ? Math.round(pw.length * Math.log2(pool)) : 0, pool };
  }

  /* ── CRACK TIME ── */
  function crackTime(bits) {
    if (bits === 0) return '—';
    const seconds = Math.pow(2, Math.min(bits, 128)) / 1e10; // GPU offline
    if (seconds < 0.001)    return 'Instant';
    if (seconds < 1)        return '< 1 second';
    if (seconds < 60)       return `${Math.round(seconds)} sec`;
    if (seconds < 3600)     return `${Math.round(seconds/60)} min`;
    if (seconds < 86400)    return `${Math.round(seconds/3600)} hours`;
    if (seconds < 2592000)  return `${Math.round(seconds/86400)} days`;
    if (seconds < 31536000) return `${Math.round(seconds/2592000)} months`;
    const years = seconds / 31536000;
    if (years < 1e6)  return `${Math.round(years).toLocaleString()} years`;
    if (years < 1e9)  return `${(years/1e6).toFixed(1)}M years`;
    if (years < 1e12) return `${(years/1e9).toFixed(1)}B years`;
    return '> 1 trillion years';
  }

  /* ── RECOMMENDATIONS ── */
  function buildRecs(pw) {
    const len      = pw.length;
    const hasUp    = /[A-Z]/.test(pw);
    const hasLo    = /[a-z]/.test(pw);
    const hasNm    = /[0-9]/.test(pw);
    const hasSy    = /[^a-zA-Z0-9]/.test(pw);
    const isCommon = COMMON.has(pw.toLowerCase());
    const patterns = detectPatterns(pw);
    const items    = [];

    // Critical warnings first
    if (isCommon)
      items.push({ text: '🚨 This is one of the most commonly used passwords — hackers try it first. Avoid it!', ok: false });

    if (patterns.includes('leet_common'))
      items.push({ text: '🚨 Substituting letters with numbers (e.g. p@ssw0rd) is well-known — easily cracked.', ok: false });

    if (patterns.includes('word_digits') || patterns.includes('digits_word'))
      items.push({ text: '⚠️ A word followed by numbers (e.g. Password123) is a very predictable pattern.', ok: false });

    if (patterns.includes('keyboard_walk'))
      items.push({ text: '⚠️ Keyboard sequences like "qwerty" or "1234" are among the first guesses attackers try.', ok: false });

    if (patterns.includes('repeated_chars'))
      items.push({ text: '⚠️ Avoid repeating characters (e.g. "aaa" or "111") — they reduce entropy significantly.', ok: false });

    // Length
    if (len < 8)
      items.push({ text: `❌ Too short (${len} chars). Use at least 8 characters — 12+ is recommended.`, ok: false });
    else if (len < 12)
      items.push({ text: `⚠️ Length is okay (${len} chars), but 12+ characters makes passwords much harder to crack.`, ok: false });
    else
      items.push({ text: `✅ Great length! ${len} characters is solid.`, ok: true });

    // Character types
    if (!hasUp)
      items.push({ text: '❌ Add uppercase letters (A–Z) to increase complexity.', ok: false });
    else
      items.push({ text: '✅ Contains uppercase letters.', ok: true });

    if (!hasLo)
      items.push({ text: '❌ Add lowercase letters (a–z).', ok: false });
    else
      items.push({ text: '✅ Contains lowercase letters.', ok: true });

    if (!hasNm)
      items.push({ text: '❌ Include at least one number (0–9).', ok: false });
    else
      items.push({ text: '✅ Contains numbers.', ok: true });

    if (!hasSy)
      items.push({ text: '❌ Add special characters (!@#$%^&*) — they multiply the number of possible combinations.', ok: false });
    else
      items.push({ text: '✅ Contains special characters — excellent!', ok: true });

    if (patterns.includes('only_letters') && len < 16)
      items.push({ text: '⚠️ Letters-only passwords are vulnerable to dictionary attacks. Mix in numbers & symbols.', ok: false });

    if (patterns.includes('only_digits'))
      items.push({ text: '❌ Numbers-only passwords are extremely weak regardless of length.', ok: false });

    // Positive tip if strong
    const sc = score(pw);
    if (sc === 4)
      items.push({ text: '🛡️ Excellent password! Store it in a password manager like Bitwarden or 1Password.', ok: true });

    return items;
  }

  /* ── RENDER ── */
  function render() {
    const pw = pwInput.value;
    charCount.textContent = pw.length;

    if (!pw) { resetUI(); return; }

    const sc             = score(pw);
    const level          = LEVELS[sc] ?? LEVELS[0];
    const { bits, pool } = calcEntropy(pw);
    const hasUp          = /[A-Z]/.test(pw);
    const hasLo          = /[a-z]/.test(pw);
    const hasNm          = /[0-9]/.test(pw);
    const hasSy          = /[^a-zA-Z0-9]/.test(pw);
    const len            = pw.length;
    const isCommon       = COMMON.has(pw.toLowerCase());

    // Bar + pill
    barFill.style.width          = level.pct + '%';
    barFill.style.background     = level.color;
    strengthPill.textContent     = level.label;
    strengthPill.style.color     = level.color;
    strengthPill.style.borderColor = level.color;
    strengthPill.style.background  = level.color + '18';

    // Stats
    statEntropy.innerHTML = `${bits} <small>bits</small>`;
    statCrack.textContent = crackTime(bits);
    statPool.textContent  = pool;

    // Checklist
    setChk('chkLen',  len >= 8);
    setChk('chkUp',   hasUp);
    setChk('chkLo',   hasLo);
    setChk('chkNum',  hasNm);
    setChk('chkSym',  hasSy);
    setChk('chkUniq', !isCommon);

    // Recommendations
    const recs = buildRecs(pw);
    recList.innerHTML = '';
    recs.forEach(r => {
      const li = document.createElement('li');
      li.className = 'rec-item' + (r.ok ? ' ok' : '');
      li.textContent = r.text;
      recList.appendChild(li);
    });

    // Reuse check
    const hist    = loadHistory();
    const isReused = hist.some(h => h.hash === simpleHash(pw));
    reuseBanner.style.display = isReused ? 'block' : 'none';
  }

  function setChk(id, pass) {
    const row = $(id), ico = $(id + 'Ico');
    if (!row || !ico) return;
    row.className = 'chk-row' + (pass ? ' pass' : '');
    ico.className = 'chk-ico' + (pass ? ' pass' : ' fail');
  }

  function resetUI() {
    barFill.style.width        = '0%';
    barFill.style.background   = 'var(--text-dim)';
    strengthPill.textContent   = 'Not Analyzed';
    strengthPill.style.color   = '';
    strengthPill.style.borderColor = '';
    strengthPill.style.background  = '';
    statEntropy.innerHTML      = '0 <small>bits</small>';
    statCrack.textContent      = '—';
    statPool.textContent       = '0';
    recList.innerHTML          = '<li class="rec-idle">Start typing to see recommendations…</li>';
    reuseBanner.style.display  = 'none';
    ['chkLen','chkUp','chkLo','chkNum','chkSym','chkUniq'].forEach(id => {
      const row = $(id), ico = $(id + 'Ico');
      if (row) row.className = 'chk-row';
      if (ico) ico.className = 'chk-ico';
    });
  }

  /* ── TOGGLE VISIBILITY ── */
  const eyeIcon = $('eyeIcon');
  const EYE_OPEN   = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  const EYE_CLOSED = `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`;

  eyeBtn.addEventListener('click', () => {
    const hidden = pwInput.type === 'password';
    pwInput.type = hidden ? 'text' : 'password';
    eyeIcon.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;
  });

  /* ── PASSWORD GENERATOR ── */
  const CHARS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digit: '0123456789',
    sym:   '!@#$%^&*()-_=+[]{}|;:,.<>?',
  };

  function rand(max) {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return arr[0] % max;
  }

  function shuffle(str) {
    const arr = str.split('');
    for (let i = arr.length - 1; i > 0; i--) {
      const j = rand(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join('');
  }

  function generatePassword(length = 16) {
    const all = CHARS.upper + CHARS.lower + CHARS.digit + CHARS.sym;
    let pw = '';
    pw += CHARS.upper[rand(CHARS.upper.length)];
    pw += CHARS.lower[rand(CHARS.lower.length)];
    pw += CHARS.digit[rand(CHARS.digit.length)];
    pw += CHARS.sym[rand(CHARS.sym.length)];
    for (let i = pw.length; i < length; i++) pw += all[rand(all.length)];
    return shuffle(pw);
  }

  btnGenerate.addEventListener('click', () => {
    genText.textContent = generatePassword(16);
    generatedWrap.style.display = 'flex';
    copyLabel.textContent = 'Copy';
  });

  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(genText.textContent).then(() => {
      copyLabel.textContent = 'Copied!';
      setTimeout(() => copyLabel.textContent = 'Copy', 2000);
    });
  });

  /* ── HISTORY (localStorage) ── */
  const HIST_KEY = 'passguard_history';

  function simpleHash(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++)
      h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    return h.toString(36);
  }

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(HIST_KEY) || '[]'); }
    catch { return []; }
  }

  function saveHistory(hist) {
    localStorage.setItem(HIST_KEY, JSON.stringify(hist));
  }

  function maskPassword(pw) {
    if (pw.length <= 3) return '*'.repeat(pw.length);
    return pw[0] + '*'.repeat(pw.length - 2) + pw[pw.length - 1];
  }

  function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  function deleteEntry(hash) {
    const hist = loadHistory().filter(h => h.hash !== hash);
    saveHistory(hist);
    renderHistory();
    // Re-check reuse banner
    const pw = pwInput.value;
    if (pw) {
      const isReused = hist.some(h => h.hash === simpleHash(pw));
      reuseBanner.style.display = isReused ? 'block' : 'none';
    }
  }

  function renderHistory() {
    const hist = loadHistory();
    histList.innerHTML = '';

    if (!hist.length) {
      histList.innerHTML = '<li class="hist-empty">No history yet. Saved passwords will appear here.</li>';
      return;
    }

    hist.slice().reverse().forEach(entry => {
      const li = document.createElement('li');
      li.className = 'hist-item';

      // Masked password
      const pw = document.createElement('span');
      pw.className = 'hist-pw';
      pw.textContent = entry.masked;
      pw.title = 'Password is masked for security';

      // Strength badge
      const badge = document.createElement('span');
      badge.className = 'hist-badge ' + entry.level;
      badge.textContent = capitalize(entry.level);

      // Delete button
      const del = document.createElement('button');
      del.className = 'hist-del-btn';
      del.title = 'Delete this entry';
      del.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
        <polyline points="3 6 5 6 21 6"/>
        <path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/>
        <path d="M10 11v6M14 11v6"/>
        <path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/>
      </svg>`;
      del.addEventListener('click', () => deleteEntry(entry.hash));

      li.appendChild(pw);
      li.appendChild(badge);
      li.appendChild(del);
      histList.appendChild(li);
    });
  }

  saveBtn.addEventListener('click', () => {
    const pw = pwInput.value;
    if (!pw) return;
    const hist = loadHistory();
    const hash = simpleHash(pw);
    if (!hist.some(h => h.hash === hash)) {
      const sc    = score(pw);
      const level = LEVELS[Math.max(sc, 0)]?.cls ?? 'weak';
      hist.push({ hash, masked: maskPassword(pw), level, ts: Date.now() });
      if (hist.length > 30) hist.shift();
      saveHistory(hist);
    }
    renderHistory();
    saveBtn.textContent = '✓ Saved!';
    setTimeout(() => {
      saveBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save to History`;
    }, 1500);
  });

  clearBtn.addEventListener('click', () => {
    saveHistory([]);
    renderHistory();
    reuseBanner.style.display = 'none';
  });

  /* ── INIT ── */
  pwInput.addEventListener('input', render);
  renderHistory();

})();