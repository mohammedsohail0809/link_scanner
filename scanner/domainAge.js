import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const whois = require('whois');

function parseCreationDate(rawData) {
  if (!rawData) return null;

  const patterns = [
    /Creation Date:\s*(.+)/i,
    /Created On:\s*(.+)/i,
    /created:\s*(.+)/i,
    /Registration Date:\s*(.+)/i,
    /Domain Registration Date:\s*(.+)/i,
    /Date of creation:\s*(.+)/i,
    /Registered on:\s*(.+)/i,
    /Registered Date:\s*(.+)/i,
    /Created Date:\s*(.+)/i,
    /creation-date:\s*(.+)/i,
    /\[Registered Date\]\s*(.+)/i,
    /Record created on\s*(.+)/i,
  ];

  for (const pattern of patterns) {
    const match = rawData.match(pattern);
    if (match) {
      let raw = match[1].trim();
      // remove trailing comments like (YYYY-MM-DD)
      raw = raw.split(' ')[0];
      // normalize +0000 -> Z
      raw = raw.replace('+0000', 'Z');
      const date = new Date(raw);
      if (!isNaN(date.getTime())) return date;
    }
  }
  return null;
}

function getRegistrableDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;

  // common multi-segment TLDs
  const multiSegment = ['co.uk', 'com.au', 'org.uk', 'gov.uk', 'edu.au', 'net.au', 'co.jp', 'ne.jp', 'com.br', 'com.mx'];
  const lastTwo = parts.slice(-2).join('.');
  const lastThree = parts.slice(-3).join('.');

  if (multiSegment.includes(lastTwo)) {
    return lastThree;
  }

  return lastTwo;
}

export async function checkDomainAge(url) {
  let hostname;
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
  } catch {
    return { score: 0, flags: [], ageDays: null };
  }

  const registrableDomain = getRegistrableDomain(hostname);

  const lookup = (domain) => {
    return new Promise((resolve) => {
      whois.lookup(domain, { timeout: 5000, follow: 2 }, (err, data) => {
        if (err || !data) return resolve(null);
        resolve(data);
      });
    });
  };

  // Try the registrable domain first (e.g., google.com)
  let data = await lookup(registrableDomain);
  
  // Check if domain is truly not registered
  const isNotFound = (txt) => {
    if (!txt) return true;
    const notFoundPatterns = [
      /No match for/i,
      /NOT FOUND/i,
      /No Data Found/i,
      /has not been registered/i,
      /No entries found/i,
      /Domain not found/i
    ];
    return notFoundPatterns.some(p => p.test(txt));
  };

  if (isNotFound(data)) {
    return { 
      score: 75, // High risk if domain is not registered/parked/missing
      flags: ['Domain is not registered or WHOIS data is missing — highly suspicious'], 
      ageDays: null,
      notFound: true
    };
  }

  let creationDate = parseCreationDate(data);

  // If failed and we used a stripped domain, try the full hostname just in case
  if (!creationDate && hostname !== registrableDomain) {
    data = await lookup(hostname);
    creationDate = parseCreationDate(data);
  }

  if (!creationDate) {
    return { score: 0, flags: [], ageDays: null };
  }

  const ageDays = Math.floor((Date.now() - creationDate) / (1000 * 60 * 60 * 24));
  const flags = [];
  let score = 0;

  if (ageDays < 7) {
    flags.push(`Domain is only ${ageDays} day(s) old — very suspicious`);
    score = 60;
  } else if (ageDays < 30) {
    flags.push(`Domain is only ${ageDays} days old — recently registered`);
    score = 35;
  } else if (ageDays < 180) {
    flags.push(`Domain is ${ageDays} days old — relatively new`);
    score = 15;
  }

  return {
    score,
    flags,
    ageDays,
    createdOn: creationDate.toISOString(),
    registrar: data.match(/Registrar:\s*(.+)/i)?.[1]?.trim() || null
  };
}
