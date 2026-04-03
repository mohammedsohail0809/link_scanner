export async function checkRedirects(url) {
  let currentUrl = url;
  let redirectCount = 0;
  const chain = [url];
  const maxRedirects = 10;

  try {
    while (redirectCount < maxRedirects) {
      // Use a short timeout and only fetch headers to be fast
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      const res = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
      });

      clearTimeout(timeout);

      // Check for redirect status codes
      if (res.status >= 300 && res.status < 400 && res.headers.has('location')) {
        let nextUrl = res.headers.get('location');

        // Handle relative URLs
        if (nextUrl.startsWith('/')) {
          const parsed = new URL(currentUrl);
          nextUrl = `${parsed.protocol}//${parsed.host}${nextUrl}`;
        } else if (!nextUrl.startsWith('http')) {
          // Some sites might give malformed relative paths
          const parsed = new URL(currentUrl);
          nextUrl = new URL(nextUrl, currentUrl).href;
        }

        currentUrl = nextUrl;
        redirectCount++;
        chain.push(currentUrl);
      } else {
        break;
      }
    }

    return {
      finalUrl: currentUrl,
      redirectCount,
      chain,
      success: true
    };
  } catch (err) {
    return {
      finalUrl: currentUrl,
      redirectCount,
      chain,
      success: false,
      error: err.message
    };
  }
}
