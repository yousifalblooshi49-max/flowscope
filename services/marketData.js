/**
 * marketData.js
 * Fetches live Gold (XAUUSD) price from Yahoo Finance (GC=F).
 * Returns: { symbol, price, change, changePercent, prevClose, timestamp }
 */

const https = require('https');

const SYMBOL = 'GC=F';
const DISPLAY_SYMBOL = 'XAUUSD';

function fetchLivePrice() {
  return new Promise((resolve, reject) => {
    const url = `https://query1.finance.yahoo.com/v8/finance/chart/${SYMBOL}?interval=1m&range=1d`;
    const options = {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; FlowScope/1.0)',
        'Accept': 'application/json'
      }
    };

    const req = https.get(url, options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const meta = json.chart.result[0].meta;
          const price = meta.regularMarketPrice;
          const prevClose = meta.chartPreviousClose || meta.previousClose || price;
          const change = parseFloat((price - prevClose).toFixed(2));
          const changePercent = parseFloat(((change / prevClose) * 100).toFixed(2));

          resolve({
            symbol: DISPLAY_SYMBOL,
            price: parseFloat(price.toFixed(2)),
            change,
            changePercent,
            prevClose: parseFloat(prevClose.toFixed(2)),
            timestamp: new Date().toISOString()
          });
        } catch (e) {
          reject(new Error('Failed to parse market data: ' + e.message));
        }
      });
    });

    req.on('error', (e) => reject(e));
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

module.exports = { fetchLivePrice };
