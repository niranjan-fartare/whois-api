const express = require('express');
const whois = require('whois');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());

function sanitizeAndFormatDate(dateString) {
  if (!dateString) return '';
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return dateString; // Return original if invalid
  return date.toISOString();
}

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
    const [key, ...valueParts] = line.split(':').map(part => part.trim());
    const value = valueParts.join(':').toLowerCase();

    switch (key.toLowerCase()) {
      case 'registrar':
        relevantData.DomainRegistrar = value;
        break;
      case 'creation date':
      case 'created':
      case 'registered':
        relevantData.RegisteredOn = sanitizeAndFormatDate(value);
        break;
      case 'registry expiry date':
      case 'expiration date':
      case 'expires':
        relevantData.ExpiresOn = sanitizeAndFormatDate(value);
        break;
      case 'updated date':
      case 'last updated':
        relevantData.UpdatedOn = sanitizeAndFormatDate(value);
        break;
      case 'domain status':
        relevantData.Status.push(value.split(' ')[0]); // Only keep the status code
        break;
      case 'name server':
        relevantData.NameServers.push(value);
        break;
      case 'registrant name':
        relevantData.RegistrantContact.Name = '[Redacted for Privacy]';
        break;
      case 'registrant organization':
        relevantData.RegistrantContact.Organization = value;
        break;
      case 'registrant state/province':
        relevantData.RegistrantContact.State = value;
        break;
      case 'registrant country':
        relevantData.RegistrantContact.Country = value.toUpperCase();
        break;
      case 'registrant email':
        relevantData.RegistrantContact.Email = '[Redacted for Privacy]';
        break;
    }
  });

  // Clean up empty arrays and objects
  if (relevantData.Status.length === 0) delete relevantData.Status;
  if (relevantData.NameServers.length === 0) delete relevantData.NameServers;

  Object.keys(relevantData.RegistrantContact).forEach(key => {
    if (!relevantData.RegistrantContact[key]) delete relevantData.RegistrantContact[key];
  });
  if (Object.keys(relevantData.RegistrantContact).length === 0) delete relevantData.RegistrantContact;

  Object.keys(relevantData).forEach(key => {
    if (!relevantData[key] || (Array.isArray(relevantData[key]) && relevantData[key].length === 0)) {
      delete relevantData[key];
    }
  });

  return relevantData;
}

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

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(port, () => {
  console.log(`WHOIS API is running on http://localhost:${port}`);
});
