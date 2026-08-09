const fs = require('fs');

const fixTimestampExpirado = () => {
  const file = 'tests/attack-simulation/timestamp-expirado.test.ts';
  let content = fs.readFileSync(file, 'utf8');
  content = content.replace(
    /computeHmac\(`\$\{oldTimestamp\}\.\$\{rawBody\}`,\s*realSecret\)/,
    'computeHmac(realSecret, `${oldTimestamp}.${rawBody}`)'
  );
  fs.writeFileSync(file, content);
};

const fixReplayAttack = () => {
  const file = 'tests/attack-simulation/replay-attack.test.ts';
  let content = fs.readFileSync(file, 'utf8');
  // First fix computeHmac params and add timestamp
  content = content.replace(
    /const signature = await computeHmac\(rawBody,\s*realSecret\);/,
    `const timestamp = Math.floor(Date.now() / 1000);
    const signature = await computeHmac(realSecret, \`\${timestamp}.\${rawBody}\`);`
  );
  // Then fix the header injection to use timestamp
  content = content.replace(
    /Stripe-Signature': `t=\$\{Math\.floor\(Date\.now\(\) \/ 1000\)\},v1=\$\{signature\}`/,
    `Stripe-Signature': \`t=\${timestamp},v1=\${signature}\``
  );
  fs.writeFileSync(file, content);
};

const fixOthers = () => {
  const files = [
    'tests/attack-simulation/firma-invalida.test.ts',
    'tests/attack-simulation/firma-timing-attack.test.ts',
    'tests/attack-simulation/body-reparseado.test.ts',
    'tests/attack-simulation/secreto-en-logs.test.ts'
  ];
  for (const file of files) {
    let content = fs.readFileSync(file, 'utf8');
    content = content.replace(/computeHmac\(rawBody,\s*'wrong_secret'\)/g, "computeHmac('wrong_secret', rawBody)");
    
    // For timing attack, body-reparseado, and secreto-en-logs, they use Stripe validation but the test logic 
    // computes HMAC without timestamp. Stripe requires timestamp. 
    // Wait! Stripe requires `${timestamp}.${rawBody}` for ALL valid signatures!
    content = content.replace(
      /const validSignature = await computeHmac\([^,]+,\s*realSecret\);/,
      `const timestamp = Math.floor(Date.now() / 1000);
    const validSignature = await computeHmac(realSecret, \`\${timestamp}.\${rawBody}\`);`
    );
    // same for validSignatureForOriginal
    content = content.replace(
      /const validSignatureForOriginal = await computeHmac\([^,]+,\s*realSecret\);/,
      `const timestamp = Math.floor(Date.now() / 1000);
    const validSignatureForOriginal = await computeHmac(realSecret, \`\${timestamp}.\${originalRawBody}\`);`
    );
    // update headers to use same timestamp
    content = content.replace(
      /Stripe-Signature': `t=\$\{Math\.floor\(Date\.now\(\) \/ 1000\)\},v1=\$\{/g,
      `Stripe-Signature': \`t=\${timestamp},v1=\${`
    );
    fs.writeFileSync(file, content);
  }
};

fixTimestampExpirado();
fixReplayAttack();
fixOthers();

console.log('Fixed tests');
