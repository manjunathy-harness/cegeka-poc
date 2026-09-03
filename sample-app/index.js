/**
 * Demo app for the Harness CI/CD + STO(OWASP) + Jira automation walkthrough.
 *
 * This app intentionally does nothing interesting - its only job is to
 * declare a handful of old, known-vulnerable npm packages in package.json
 * so that a security scan (npm audit / OWASP Dependency-Check) reliably
 * finds real CVEs to demo the Jira ticket automation against.
 *
 * DO NOT deploy this anywhere real or use these dependency versions in
 * an actual project.
 */
const _ = require('lodash');
const express = require('express');

const app = express();

app.get('/', (req, res) => {
  res.json({
    message: 'Harness CI/CD + STO + Jira automation demo app',
    randomId: _.random(1000, 9999),
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Demo app listening on port ${port}`);
});
