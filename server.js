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
    Status: [],
    NameServers: [],
    RegistrantContact: {
      Name: '',
      Organization: '',
      State: '',
      Country: '',
      Email: ''
    }
  };

  lines.forEach(line => {
    const trimmedLine = line.trim().toLowerCase();

    if (trimmedLine.includes('registrar:')) {
      relevantData.DomainRegistrar = trimmedLine.split(':')[1].trim();
    }
    if (trimmedLine.includes('creation date:') || trimmedLine.includes('created:') || trimmedLine.includes('registered:')) {
      relevantData.RegisteredOn = trimmedLine.split(':')[1].trim();
    }
    if (trimmedLine.includes('registry expiry date:') || trimmedLine.includes('expiration date:') || trimmedLine.includes('expires:')) {
      relevantData.ExpiresOn = trimmedLine.split(':')[1].trim();
    }
    if (trimmedLine.includes('updated date:') || trimmedLine.includes('last updated:')) {
      relevantData.UpdatedOn = trimmedLine.split(':')[1].trim();
    }
    if (trimmedLine.includes('domain status:')) {
      relevantData.Status.push(trimmedLine.split(':')[1].trim());
    }
    if (trimmedLine.includes('name server:')) {
      relevantData.NameServers.push(trimmedLine.split(':')[1].trim());
    }
    if (trimmedLine.includes('registrant name:')) {
      relevantData.RegistrantContact.Name = trimmedLine.split(':')[1].trim();
    }
    if (trimmedLine.includes('registrant organization:')) {
      relevantData.RegistrantContact.Organization = trimmedLine.split(':')[1].trim();
    }
    if (trimmedLine.includes('registrant state/province:')) {
      relevantData.RegistrantContact.State = trimmedLine.split(':')[1].trim();
    }
    if (trimmedLine.includes('registrant country:')) {
      relevantData.RegistrantContact.Country = trimmedLine.split(':')[1].trim();
    }
    if (trimmedLine.includes('registrant email:')) {
      relevantData.RegistrantContact.Email = trimmedLine.split(':')[1].trim();
    }
  });

  // Clean up empty arrays
  if (relevantData.Status.length === 0) delete relevantData.Status;
  if (relevantData.NameServers.length === 0) delete relevantData.NameServers;

  // Remove empty fields from RegistrantContact
  Object.keys(relevantData.RegistrantContact).forEach(key => {
    if (!relevantData.RegistrantContact[key]) delete relevantData.RegistrantContact[key];
  });
  if (Object.keys(relevantData.RegistrantContact).length === 0) delete relevantData.RegistrantContact;

  // Remove empty fields from the main object
  Object.keys(relevantData).forEach(key => {
    if (!relevantData[key] || (Array.isArray(relevantData[key]) && relevantData[key].length === 0)) {
      delete relevantData[key];
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

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(port, () => {
  console.log(`WHOIS API is running on http://localhost:${port}`);
});
