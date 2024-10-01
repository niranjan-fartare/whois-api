const express = require('express');
const whois = require('whois');
const app = express();
const port = process.env.PORT || 3000;  // Render uses PORT from environment variables

// WHOIS Lookup Route
app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  whois.lookup(domain, (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Error performing WHOIS lookup' });
    }

    res.status(200).json({ domain, whois: data });
  });
});

// Start server
app.listen(port, () => {
  console.log(`WHOIS API is running on http://localhost:${port}`);
});
