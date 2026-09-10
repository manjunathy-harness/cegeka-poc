/**
 * Demo app for Harness CI/CD + STO + Jira automation.
 *
 * This app intentionally declares old, known-vulnerable npm packages
 * for security scanning demonstrations.
 *
 * DO NOT deploy this anywhere real.
 */

const http = require('http');
const _ = require('lodash');
const axios = require('axios');
const minimist = require('minimist');

const args = minimist(process.argv.slice(2));

const server = http.createServer((req, res) => {
  res.writeHead(200, {
    'Content-Type': 'application/json'
  });

  res.end(JSON.stringify({
    message: 'Harness CI/CD + STO + Jira automation demo app',
    randomId: _.random(1000, 9999),
    environment: args.env || 'demo',
    axiosVersion: axios.VERSION
  }));
});

const port = process.env.PORT || 3000;

server.listen(port, () => {
  console.log(`Demo app listening on port ${port}`);
});