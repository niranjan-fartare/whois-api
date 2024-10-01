const express = require('express');
const whois = require('whois');
const app = express();
const port = process.env.PORT || 3000;  // Render uses PORT from environment variables

// Utility function to extract required fields from the WHOIS data
function extractRelevantInfo(rawData) {
  const lines = rawData.split('\n');
  const relevantData = {
    DomainRegistrar: '',
    RegisteredOn: '',
    ExpiresOn: '',
    UpdatedOn: '',
    Status: '',
    NameServers: [],
    RegistrantContact: {
      Organization: '',
      State: '',
      Country: '',
      Email: ''
    }
  };

  lines.forEach(line => {
    const trimmedLine = line.trim();
    if (trimmedLine.startsWith('Registrar:')) {
      relevantData.DomainRegistrar = trimmedLine.split(': ')[1];
    }
    if (trimmedLine.startsWith('Creation Date:')) {
      relevantData.RegisteredOn = trimmedLine.split(': ')[1];
    }
    if (trimmedLine.startsWith('Registry Expiry Date:')) {
      relevantData.ExpiresOn = trimmedLine.split(': ')[1];
    }
    if (trimmedLine.startsWith('Updated Date:')) {
      relevantData.UpdatedOn = trimmedLine.split(': ')[1];
    }
    if (trimmedLine.startsWith('Domain Status:')) {
      relevantData.Status = trimmedLine.split(': ')[1];
    }
    if (trimmedLine.startsWith('Name Server:')) {
      relevantData.NameServers.push(trimmedLine.split(': ')[1]);
    }
    if (trimmedLine.startsWith('Registrant Organization:')) {
      relevantData.RegistrantContact.Organization = trimmedLine.split(': ')[1];
    }
    if (trimmedLine.startsWith('Registrant State/Province:')) {
      relevantData.RegistrantContact.State = trimmedLine.split(': ')[1];
    }
    if (trimmedLine.startsWith('Registrant Country:')) {
      relevantData.RegistrantContact.Country = trimmedLine.split(': ')[1];
    }
    if (trimmedLine.startsWith('Registrant Email:')) {
      relevantData.RegistrantContact.Email = trimmedLine.split(': ')[1];
    }
  });

  return relevantData;
}

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

    const filteredData = extractRelevantInfo(data);
    res.status(200).json({ domain, whois: filteredData });
  });
});

// Start server
app.listen(port, () => {
  console.log(`WHOIS API is running on http://localhost:${port}`);
});
