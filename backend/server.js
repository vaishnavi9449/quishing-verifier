const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const { analyzeURLHeuristics } = require('./utils/heuristics');
const { checkGoogleSafeBrowsing, checkVirusTotal, checkWHOISDomainAge } = require('./utils/threatIntel');
const qrAnalyzer = require('./utils/qrAnalyzer');  // ADD THIS LINE

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.get('/health', (req, res) => {
  res.json({ status: '✅ Backend running', version: '1.0.0' });
});

app.post('/analyze/heuristics', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });
  try {
    const result = analyzeURLHeuristics(url);
    res.json({ layer: 'A', result, responseTime: '<100ms' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/analyze/full', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });
  
  try {
    // Layer A: Heuristics
    const heuristicsResult = analyzeURLHeuristics(url);
    
    // Layer B: Threat Intelligence (run in parallel)
    const [safeBrowsingResult, virusTotalResult, whoisResult] = await Promise.all([
      checkGoogleSafeBrowsing(url),
      checkVirusTotal(url),
      checkWHOISDomainAge(url),
    ]);

    // Layer B.5: CNN QR Analysis (NEW!)
    const cnnResult = await qrAnalyzer.analyzeQRImage(url);

    // Combine results
    let finalRiskLevel = heuristicsResult.riskLevel;
    let details = [...heuristicsResult.details];

    if (!safeBrowsingResult.safe) {
      finalRiskLevel = 'red';
      details.push(`⚠️ Google Safe Browsing: ${safeBrowsingResult.reason}`);
    }

    if (virusTotalResult.maliciousCount > 0) {
      finalRiskLevel = 'red';
      details.push(`⚠️ VirusTotal: ${virusTotalResult.maliciousCount} vendors flagged`);
    }

    if (whoisResult.riskLevel === 'high') {
      finalRiskLevel = finalRiskLevel === 'red' ? 'red' : 'yellow';
      details.push(`⚠️ Domain age: ${whoisResult.ageInDays} days (very new)`);
    }

    // Add CNN analysis to details
    if (cnnResult.isTampered) {
      finalRiskLevel = 'red';
      details.push(`⚠️ CNN QR Analysis: ${cnnResult.reason}`);
    } else {
      details.push(`✅ CNN QR Analysis: ${cnnResult.reason}`);
    }

    res.json({
      url,
      layerA: heuristicsResult,
      layerB: {
        safeBrowsing: safeBrowsingResult,
        virusTotal: virusTotalResult,
        whois: whoisResult,
      },
      layerB5: cnnResult,  // NEW CNN LAYER
      finalRiskLevel,
      details,
      recommendation: finalRiskLevel === 'red' ? '⛔ DO NOT CLICK' : finalRiskLevel === 'yellow' ? '⚠️ BE CAREFUL' : '✅ SAFE',
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = 3001;
app.listen(PORT, () => console.log(`\n✅ Quishing Verifier running on http://localhost:${PORT}\n`));