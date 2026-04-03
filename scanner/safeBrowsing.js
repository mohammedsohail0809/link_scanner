import 'dotenv/config';

export async function checkSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;

  if (!key) {
    console.warn('No Safe Browsing API key found');
    return { flagged: false, score: 0, threats: [] };
  }

  const body = {
    client: { clientId: 'link-scanner', clientVersion: '1.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  const res = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`,
    { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } }
  );

  const data = await res.json();

  if (data.matches?.length > 0) {
    return {
      flagged: true,
      score: 90,
      threats: data.matches.map(m => m.threatType)
    };
  }

  return { flagged: false, score: 0, threats: [] };
}
