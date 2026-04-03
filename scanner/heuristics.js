const SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq'];
const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'update', 'account', 'banking', 'free-'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
const DANGEROUS_EXTENSIONS = ['.sh', '.exe', '.bat', '.cmd', '.ps1', '.msi', '.vbs', '.php'];

export function checkHeuristics(url) {
  const flags = [];
  let score = 0;

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();

    // IP address (now handles ports too)
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      flags.push('Raw IP address used instead of domain');
      score += 40;
    }

    // No HTTPS
    if (parsed.protocol !== 'https:') {
      flags.push('Not using HTTPS');
      score += 15;
    }

    // Dangerous file extension in path
    if (DANGEROUS_EXTENSIONS.some(ext => parsed.pathname.toLowerCase().endsWith(ext))) {
      flags.push(`Dangerous file type in URL: ${parsed.pathname.split('/').pop()}`);
      score += 35;
    }

    // Non-standard port
    if (parsed.port && !['80', '443'].includes(parsed.port)) {
      flags.push(`Non-standard port used: ${parsed.port}`);
      score += 20;
    }

    // Suspicious TLD
    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
      flags.push('Suspicious top-level domain');
      score += 20;
    }

    // Excessive subdomains
    if (hostname.split('.').length > 4) {
      flags.push('Excessive subdomains');
      score += 15;
    }

    // URL shortener
    if (URL_SHORTENERS.some(s => hostname.includes(s))) {
      flags.push('URL shortener detected — real destination hidden');
      score += 10;
    }

    // Suspicious keywords
    SUSPICIOUS_KEYWORDS.forEach(kw => {
      if (hostname.includes(kw)) {
        flags.push(`Suspicious keyword in domain: "${kw}"`);
        score += 10;
      }
    });

    // Lookalike domain
    if (/[0-9]/.test(hostname.split('.')[0])) {
      flags.push('Possible lookalike domain (numbers in name)');
      score += 10;
    }

  } catch {
    flags.push('Invalid or malformed URL');
    score = 100;
  }

  return { score: Math.min(score, 100), flags };
}
