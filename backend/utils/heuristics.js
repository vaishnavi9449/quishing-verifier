// Layer A: Local URL heuristics (no network, instant analysis)

const SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'zip', 'top', 'xyz'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 't.co', 'short.link', 'is.gd'];
const BRAND_KEYWORDS = {
  paypal: ['paypa', 'payp1', 'paypa1'],
  amazon: ['amaz', 'amz', 'amazo'],
  apple: ['appl', 'app1', 'appple'],
  google: ['googl', 'goog1e', 'gogle'],
  microsoft: ['microsof', 'microso1t'],
  bank: ['bank', 'b@nk', 'b4nk']
};

function analyzeURLHeuristics(url) {
  const verdict = {
    riskLevel: 'green',
    flags: [],
    score: 0,
    details: []
  };

  try {
    // Parse URL
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    const protocol = urlObj.protocol;
    const pathname = urlObj.pathname;

    // Check 1: HTTP (not HTTPS)
    if (protocol === 'http:') {
      verdict.flags.push('Uses HTTP instead of HTTPS');
      verdict.details.push('Unencrypted connection');
      verdict.score += 15;
    }

    // Check 2: Suspicious TLD
    const tld = domain.split('.').pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      verdict.flags.push(`Suspicious TLD (.${tld})`);
      verdict.details.push('High-risk top-level domain commonly used in phishing');
      verdict.score += 20;
    }

    // Check 3: URL Shortener
    if (URL_SHORTENERS.some(shortener => domain.includes(shortener))) {
      verdict.flags.push('URL shortener detected');
      verdict.details.push('Destination URL is hidden - you cannot see where this link goes');
      verdict.score += 25;
    }

    // Check 4: IP Address as Domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
      verdict.flags.push('IP address used instead of domain');
      verdict.details.push('Legitimate sites use domain names, not IP addresses');
      verdict.score += 40;
    }

    // Check 5: Suspicious Domain Length
    if (domain.length < 4 || domain.length > 40) {
      verdict.flags.push('Unusual domain length');
      verdict.details.push('Domain is unusually short or long');
      verdict.score += 10;
    }

    // Check 6: Homoglyph/Lookalike Detection
    for (const [brand, variants] of Object.entries(BRAND_KEYWORDS)) {
      const normalizedDomain = domain.replace(/[1!0o]/g, 'x');
      const brandNormalized = brand.replace(/[1!0o]/g, 'x');
      
      if (normalizedDomain.includes(brandNormalized) && !domain.includes(brand)) {
        verdict.flags.push(`Possible homoglyph of "${brand}"`);
        verdict.details.push(`Domain looks like ${brand} but uses lookalike characters`);
        verdict.score += 30;
      }

      for (const variant of variants) {
        if (domain.includes(variant) && !domain.includes(brand)) {
          verdict.flags.push(`Possible typo/variant of "${brand}"`);
          verdict.details.push(`Domain "${domain}" resembles "${brand}"`);
          verdict.score += 25;
          break;
        }
      }
    }

    // Check 7: Subdomain Abuse
    const subdomainCount = domain.split('.').length;
    if (subdomainCount > 4) {
      verdict.flags.push('Excessive subdomains');
      verdict.details.push('Too many subdomains may indicate subdomain hijacking');
      verdict.score += 15;
    }

    // Check 8: Special Characters in Domain
    if (/[!@#$%^&*()+=\[\]{};:'",<>?/\\|`~]/.test(domain)) {
      verdict.flags.push('Special characters in domain');
      verdict.details.push('Legitimate domains rarely contain special characters');
      verdict.score += 20;
    }

    // Determine risk level
    if (verdict.score >= 50) {
      verdict.riskLevel = 'red';
    } else if (verdict.score >= 25) {
      verdict.riskLevel = 'yellow';
    } else {
      verdict.riskLevel = 'green';
    }

  } catch (error) {
    verdict.flags.push('Invalid URL format');
    verdict.details.push(error.message);
    verdict.riskLevel = 'red';
    verdict.score = 100;
  }

  return verdict;
}

module.exports = { analyzeURLHeuristics };