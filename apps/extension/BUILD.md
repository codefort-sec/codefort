# Building CodeFort Guard from Source

This extension is built using Vite, React, and TypeScript.

### Prerequisites
- Node.js >= 18.0.0 (tested on Node 20 LTS and Node 22+)
- npm >= 9.0.0

### Build Steps
1. Install dependencies:
   ```bash
   npm install
   ```
2. Build and package the extension:
   ```bash
   npm run package
   ```
3. Artifacts generated:
   - `dist/firefox/` directory: Unpacked extension directory with Firefox Manifest V3.
   - `codefort-guard-firefox-v0.1.2.zip`: The identical packaged archive submitted for review.
