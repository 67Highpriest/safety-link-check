const checkButton = document.getElementById('checkButton');
const urlInput = document.getElementById('urlInput');
const resultDiv = document.getElementById('result');

checkButton.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (!url) {
        resultDiv.textContent = 'Please enter a URL.';
        return;
    }

    resultDiv.textContent = 'Checking link...';

    try {
        const [googleSafe, virusTotalSafe] = await Promise.all([
            checkWithGoogleSafeBrowsing(url),
            checkWithVirusTotal(url)
        ]);

        if (googleSafe && virusTotalSafe) {
            resultDiv.textContent = 'Link is safe!';
        } else {
            resultDiv.textContent = 'Warning: Link may not be safe.';
        }
    } catch (err) {
        console.error('Error:', err);
        resultDiv.textContent = 'Something went wrong. Try again later.';
    }
});

async function checkWithGoogleSafeBrowsing(url) {
    const apiKey = 'AIzaSyAgOyH9YYunPUJlmHx3BNMTvO0L1vYJpPI';
    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const body = {
        client: {
            clientId: 'PriestSafeguardApp',
            clientVersion: '1.0'
        },
        threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
        }
    };

    const res = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });

    const data = await res.json();
    return !data.matches;
}

async function checkWithVirusTotal(url) {
    const apiKey = '7877f1f27d7ac3cb49bc33afeb87c488db547c7e3b17d604e20be6967bfea13a';
    const apiUrl = 'https://www.virustotal.com/api/v3/urls';

    // Step 1: Encode the URL
    const form = new FormData();
    form.append('url', url);

    const res1 = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'x-apikey': apiKey },
        body: form
    });

    const data1 = await res1.json();
    const analysisId = data1.data.id;

    // Step 2: Get the analysis report
    const res2 = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': apiKey }
    });

    const data2 = await res2.json();
    const stats = data2.data.attributes.stats;

    // If any engine flags it as malicious, we return false
    return stats.malicious === 0 && stats.suspicious === 0;
}


// Service Worker Registration
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('service-worker.js')
    .then(reg => console.log('Service Worker registered:', reg))
    .catch(err => console.error('Service Worker registration failed:', err));
}