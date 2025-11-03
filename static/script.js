async function postJSON(url, data) {
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    return res.json();
}


document.getElementById('analyzeBtn').addEventListener('click', async () => {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return alert('Enter a URL');
    const r = await postJSON('/api/analyze_url', { url });
    const container = document
})

/* script.js — PhishEye interactive behavior (no external network calls)
   - Validates URL
   - Parses domain
   - Provides a mock 'risk score' with heuristics (shows meter)
   - Actions: paste, open, copy, clear
*/

(() => {
  const urlInput = document.getElementById('urlInput');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const quickBtn = document.getElementById('quickBtn');
  const deepBtn = document.getElementById('deepBtn');
  const pasteBtn = document.getElementById('pasteBtn');
  const copyBtn = document.getElementById('copyBtn');
  const openBtn = document.getElementById('openBtn');
  const clearBtn = document.getElementById('clearBtn');

  const meterBar = document.getElementById('meterBar');
  const statusChip = document.getElementById('statusChip');
  const infoArea = document.getElementById('infoArea');
  const details = document.getElementById('details');
  const domainLabel = document.getElementById('domainLabel');
  const summaryText = document.getElementById('summaryText');
  const metaLog = document.getElementById('metaLog');

  // utility: sanitize/ensure protocol
  function normalizeUrl(input) {
    if (!input) return null;
    try {
      // add protocol if missing
      if (!/^[a-zA-Z]+:\/\//.test(input)) input = 'https://' + input;
      const url = new URL(input);
      return url;
    } catch (e) {
      return null;
    }
  }

  // basic heuristics for risk score (local only)
  function getRiskScore(urlObj, deep=false) {
    // score 0 (safe) -> 100 (danger)
    let score = 0;
    const host = urlObj.hostname || '';

    // very long host or path => suspicious
    if (host.length > 30) score += 18;
    if (urlObj.pathname && urlObj.pathname.length > 80) score += 12;

    // presence of suspicious tokens
    const suspiciousTokens = ['login', 'secure', 'account', 'verify', 'update', 'bank', 'signin', 'confirm', 'webscr'];
    const pathLower = (urlObj.pathname + urlObj.search).toLowerCase();
    suspiciousTokens.forEach(t => { if (pathLower.includes(t)) score += 6; });

    // subdomain depth (multiple dots) can be suspicious
    const subDepth = (host.match(/\./g) || []).length;
    if (subDepth >= 3) score += 10;

    // hyphens and many numbers
    if (host.includes('-')) score += 6;
    if (/\d{3,}/.test(host)) score += 6;

    // IP address used as host (like http://192.168.1.1/...) -> risky
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) score += 40;

    // weak TLDs (like .xyz, .win often used for throwaway domains)
    const riskyTLDs = ['xyz','win','top','club','pw','info'];
    const tld = host.split('.').pop();
    if (riskyTLDs.includes(tld)) score += 16;

    // deep scan adds extra weight for suspicious indicators
    if (deep) {
      if (pathLower.includes('redirect')) score += 8;
      if (/[^\x00-\x7F]/.test(host)) score += 10; // odd chars
      // small random jitter to mimic deeper heuristics
      score += Math.floor(Math.random()*10);
    } else {
      score += Math.floor(Math.random()*6);
    }

    // clamp 0..100
    score = Math.max(0, Math.min(100, score));
    return score;
  }

  function showStatus(text, busy=false) {
    statusChip.textContent = text;
    statusChip.style.background = busy ? 'linear-gradient(90deg,var(--accent),var(--accent-2))' : 'transparent';
    statusChip.style.color = busy ? '#041229' : '';
  }

  function setMeter(score) {
    meterBar.style.width = score + '%';
    // accessible label
    meterBar.setAttribute('aria-valuenow', score);
  }

  function updateInfo(urlObj, score) {
    const rows = infoArea.querySelectorAll('.row');
    rows[0].children[1].textContent = urlObj.hostname;
    rows[1].children[1].textContent = '—'; // IP lookup would require network
    rows[2].children[1].textContent = (urlObj.protocol === 'https:') ? 'TLS' : 'None';
  }

  function updateDetails(urlObj, score) {
    details.style.display = 'block';
    domainLabel.textContent = urlObj.href;
    summaryText.textContent = `Score: ${score} / 100 — ${score < 40 ? 'Low risk' : score < 70 ? 'Medium risk' : 'High risk'}. This is a heuristic preview only.`;
    metaLog.textContent = [
      `analyzed: ${new Date().toLocaleString()}`,
      `host: ${urlObj.hostname}`,
      `path: ${urlObj.pathname}${urlObj.search}`,
      `protocol: ${urlObj.protocol}`,
      `heuristic score: ${score}`
    ].join('\n');
    document.getElementById('safebadge').style.display = score < 40 ? 'inline-block' : 'none';
    document.getElementById('dangerbadge').style.display = score >= 40 ? 'inline-block' : 'none';
  }

  async function analyze(input, opts={deep:false}) {
    const normalized = normalizeUrl(input);
    if (!normalized) {
      showStatus('invalid URL');
      meterBar.style.width = '0%';
      details.style.display = 'none';
      return;
    }

    showStatus('scanning...', true);
    // simulate work
    const fakeWait = opts.deep ? 900 + Math.random()*900 : 250 + Math.random()*300;
    const spinner = document.createElement('span');
    spinner.className = 'spinner';
    analyzeBtn.disabled = true;
    analyzeBtn.appendChild(spinner);

    await new Promise(r => setTimeout(r, fakeWait));

    const score = getRiskScore(normalized, opts.deep);
    setMeter(score);
    updateInfo(normalized, score);
    updateDetails(normalized, score);

    showStatus(score < 40 ? 'safe' : score < 70 ? 'suspicious' : 'dangerous');
    analyzeBtn.disabled = false;
    analyzeBtn.removeChild(spinner);
  }

  // Event wiring
  analyzeBtn.addEventListener('click', () => analyze(urlInput.value));
  quickBtn.addEventListener('click', () => analyze(urlInput.value, {deep:false}));
  deepBtn.addEventListener('click', () => analyze(urlInput.value, {deep:true}));

  pasteBtn.addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      urlInput.value = text.trim();
    } catch (e){
      // fallback: focus input and paste (user must press)
      urlInput.focus();
    }
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    setMeter(0);
    showStatus('idle');
    details.style.display = 'none';
    infoArea.querySelectorAll('.row').forEach((r,i)=>{
      r.children[1].textContent = (i===2)?'—':'—';
    });
  });

  copyBtn.addEventListener('click', async () => {
    const normalized = normalizeUrl(urlInput.value);
    if (!normalized) return;
    // prepare small result text
    const text = `PhishEye result for ${normalized.hostname}\n${metaLog.textContent}\nScore: ${meterBar.style.width || '0%'}`;
    try {
      await navigator.clipboard.writeText(text);
      showStatus('copied');
      setTimeout(()=> showStatus('idle'), 900);
    } catch (e) {
      showStatus('unable to copy');
      setTimeout(()=> showStatus('idle'), 900);
    }
  });

  openBtn.addEventListener('click', () => {
    const normalized = normalizeUrl(urlInput.value);
    if (!normalized) return;
    // open in new tab
    window.open(normalized.href, '_blank', 'noopener');
  });

  // keyboard: enter => analyze
  urlInput.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') {
      analyze(urlInput.value);
    }
  });

  // nice: prefill example for demo
  urlInput.value = '';
  setMeter(0);
  showStatus('idle');

})();
