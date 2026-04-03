import 'dotenv/config';

export async function checkVirusTotal(url) {
  const key = process.env.VIRUSTOTAL_API_KEY;

  if (!key) {
    console.warn('No VirusTotal API key found');
    return { flagged: false, score: 0, positives: 0, total: 0 };
  }

  try {
    // VirusTotal v3 requires URLs to be base64 encoded (without padding)
    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');

    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: 'GET',
      headers: {
        'x-apikey': key,
        'Accept': 'application/json'
      }
    });

    if (res.status === 404) {
      // URL not in VT database yet, we could submit it, but for now we'll just return clean
      return { flagged: false, score: 0, positives: 0, total: 0 };
    }

    if (!res.ok) {
      const err = await res.json();
      console.error('VirusTotal Error:', err);
      return { flagged: false, score: 0, positives: 0, total: 0 };
    }

    const { data } = await res.json();
    const stats = data.attributes.last_analysis_stats;
    const positives = stats.malicious + stats.suspicious;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    // If more than 2 engines flag it, we consider it highly suspicious
    const score = positives > 5 ? 100 : positives > 0 ? 40 + (positives * 10) : 0;

    return {
      flagged: positives > 0,
      score: Math.min(score, 100),
      positives,
      total,
      stats
    };
  } catch (error) {
    console.error('VirusTotal fetch failed:', error);
    return { flagged: false, score: 0, positives: 0, total: 0 };
  }
}
