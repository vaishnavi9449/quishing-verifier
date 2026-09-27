const axios = require('axios');

async function checkGoogleSafeBrowsing(url) {
  try {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    console.log('Using Google key:', apiKey ? 'YES' : 'NO');
    
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: 'quishing-verifier', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'PHISHING'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      },
      { timeout: 5000 }
    );

    const isThreat = response.data.matches && response.data.matches.length > 0;
    return { safe: !isThreat, reason: isThreat ? response.data.matches[0].threatType : 'Safe' };
  } catch (error) {
    console.error('SafeBrowsing API error:', error.response?.data || error.message);
    return { safe: true, reason: 'Check failed' };
  }
}

async function checkVirusTotal(url) {
  try {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    const encodedUrl = Buffer.from(url).toString('base64').replace(/=/g, '');
    
    const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
      headers: { 'x-apikey': apiKey },
      timeout: 5000,
    });

    const stats = response.data.data.attributes.last_analysis_stats;
    return { safe: stats.malicious === 0, maliciousCount: stats.malicious };
  } catch (error) {
    console.error('VirusTotal error:', error.message);
    return { safe: true, maliciousCount: 0 };
  }
}

async function checkWHOISDomainAge(url) {
  try {
    const apiKey = process.env.WHOIS_API_KEY;
    const domain = new URL(url).hostname;
    
    const response = await axios.get(`https://www.whoisxmlapi.com/api/v1`, {
      params: { apiKey, domain, outputFormat: 'JSON' },
      timeout: 5000,
    });

    const createdDate = new Date(response.data.WhoisRecord?.createdDate);
    const ageInDays = Math.floor((Date.now() - createdDate) / (1000 * 60 * 60 * 24));

    return { ageInDays, riskLevel: ageInDays < 30 ? 'high' : ageInDays < 365 ? 'medium' : 'low' };
  } catch (error) {
    console.error('WHOIS error:', error.message);
    return { ageInDays: 999, riskLevel: 'unknown' };
  }
}

module.exports = { checkGoogleSafeBrowsing, checkVirusTotal, checkWHOISDomainAge };