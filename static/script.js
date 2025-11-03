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