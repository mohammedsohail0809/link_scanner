import { checkHeuristics } from './heuristics.js';
import { checkSafeBrowsing } from './safeBrowsing.js';
import { checkDomainAge } from './domainAge.js';
import { checkVirusTotal } from './virusTotal.js';
import { checkRedirects } from './redirects.js';
import { checkLocation } from './location.js';

// Simple in-memory cache to save API tokens and speed up repeated scans
const scanCache = new Map();
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

export async function scanUrl(url) {
  // 1. Check Cache
  const cached = scanCache.get(url);
  if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
    return { ...cached.data, cached: true };
  }

  // 2. Start Redirection Follow & Initial Heuristics in parallel
  const [redirs, heuristicsOrig] = await Promise.all([
    checkRedirects(url),
    checkHeuristics(url)
  ]);

  const targetUrl = redirs.finalUrl;
  let targetHostname;
  try { targetHostname = new URL(targetUrl).hostname; } catch { targetHostname = targetUrl; }

  // 3. Run reputation scans on the target (final) URL in parallel
  const [heuristicsTarget, safeBrowsing, domainAge, vt, location] = await Promise.all([
    checkHeuristics(targetUrl),
    checkSafeBrowsing(targetUrl).catch(() => ({ flagged: false, score: 0, threats: [] })),
    checkDomainAge(targetUrl).catch(() => ({ score: 0, flags: [], ageDays: null })),
    checkVirusTotal(targetUrl).catch(() => ({ flagged: false, score: 0, positives: 0, total: 0 })),
    checkLocation(targetHostname).catch(() => ({ success: false }))
  ]);

  const googleScore = safeBrowsing.flagged ? 90 : 0;
  const vtScore = vt.score;
  const hScore = Math.max(heuristicsOrig.score, heuristicsTarget.score);
  const wScore = domainAge.score;

  // Final score calculation
  const weightedScore = Math.round(
    hScore * 0.15 +
    googleScore * 0.30 +
    vtScore * 0.30 +
    wScore * 0.25
  );

  const finalScore = Math.min(
    Math.max(
      hScore >= 80 ? hScore : 0,
      googleScore,
      vtScore,
      wScore >= 75 ? wScore : 0,
      weightedScore
    ),
    100
  );

  const verdict =
    finalScore >= 70 ? 'malicious' :
    finalScore >= 35 ? 'suspicious' : 'safe';

  // Combine unique flags
  const flags = [...new Set([
    ...heuristicsOrig.flags,
    ...heuristicsTarget.flags,
    ...safeBrowsing.threats.map(t => `Google flagged as: ${t}`),
    ...domainAge.flags
  ])];

  if (vt.positives > 0) {
    flags.push(`VirusTotal: ${vt.positives}/${vt.total} engines flagged this URL`);
  }

  if (redirs.redirectCount > 0) {
    flags.push(`Redirect Chain: ${redirs.redirectCount} hop(s) detected`);
  }

  const result = {
    url,
    finalUrl: targetUrl,
    redirectCount: redirs.redirectCount,
    verdict,
    score: finalScore,
    flags,
    individualScores: {
      heuristics: hScore,
      safeBrowsing: googleScore,
      whois: wScore,
      virusTotal: vtScore
    },
    details: {
      domainAgeDays: domainAge.ageDays,
      domainCreatedOn: domainAge.createdOn ?? null,
      registrar: domainAge.registrar ?? 'Unknown',
      vtPositives: vt.positives,
      vtTotal: vt.total,
      googleThreats: safeBrowsing.threats,
      location,
      redirectChain: redirs.chain
    }
  };

  // Store in cache
  scanCache.set(url, { data: result, timestamp: Date.now() });

  return result;
}
