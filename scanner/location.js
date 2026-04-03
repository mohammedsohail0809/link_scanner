import dns from 'node:dns/promises';

export async function checkLocation(hostname) {
  try {
    // 1. Get IP address
    const result = await dns.lookup(hostname);
    const ip = result.address;

    // 2. Get Geolocation (using a free API)
    // ip-api.com is free for non-commercial use, no key needed for basic info
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,city,isp,as`);
    const data = await res.json();

    if (data.status === 'success') {
      return {
        ip,
        country: data.country,
        city: data.city,
        isp: data.isp,
        asn: data.as,
        success: true
      };
    }

    return { ip, success: true, country: 'Unknown', city: 'Unknown' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
