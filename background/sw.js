// Background service worker for the Extension Risk Analyzer

const OPENAI_API_KEY = 'API_KEY'; 

async function openPanel(windowId) {
  try {
    if (chrome.sidePanel?.open) return chrome.sidePanel.open({ windowId });
  } catch {}
  return chrome.tabs.create({ url: 'app/index.html' });
}

chrome.action.onClicked.addListener(tab => { openPanel(tab?.windowId); });

chrome.runtime.onMessage.addListener((msg, _sender, send) => {
  switch (msg?.type) {
    case 'OPENAI_CHAT':
      (async () => {
        try {
          const res = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${OPENAI_API_KEY}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(msg.body)
          });
          if (!res.ok) return send({ ok: false, error: `OpenAI ${res.status}` });
          const data = await res.json();
          send({ ok: true, content: data?.choices?.[0]?.message?.content || '' });
        } catch (e) {
          send({ ok: false, error: String(e?.message || e) });
        }
      })();
      return true; // async
  }
});

