# vuln-demo-app

A throwaway Node.js app whose only purpose is to pin a few old, known-vulnerable
npm packages so a security scan has real CVEs to find. Used to demo:

1. A Harness CI/CD pipeline (build stage)
2. A Harness STO OWASP Dependency-Check scan stage
3. Jira automation that files one parent "release" ticket plus one child
   sub-task per vulnerability found

**Do not deploy this app anywhere, and do not copy these dependency
versions into a real project.**
