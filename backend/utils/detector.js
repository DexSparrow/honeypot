// backend/utils/detector.js

const he = require('he'); // Pour décoder les entités HTML

const patterns = [
  // SQL Injection (dangerosité élevée sauf certaines qui sont medium)
  { name: 'SQLi basique', regex: /('|")[\s]*?(or|and)[\s]+[\w\d]+[\s]*?=|--|;|\/\*|\*\//i, severity: 'high' },
  { name: 'SQLi UNION SELECT', regex: /(UNION(\s+ALL)?\s+SELECT)/i, severity: 'high' },
  { name: 'Commandes SQL', regex: /(\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|\bDROP\b|\bALTER\b)/i, severity: 'medium' },
  { name: 'SQL sleep', regex: /sleep\s*\(\s*\d+\s*\)/i, severity: 'high' },
  { name: 'SQL benchmark', regex: /benchmark\s*\(/i, severity: 'high' },
  { name: 'SQL cast', regex: /cast\s*\(/i, severity: 'medium' },
  { name: 'SQL declare', regex: /declare\s+@/i, severity: 'medium' },
  { name: 'SQL xp_ procedures', regex: /xp_/i, severity: 'high' },
  { name: 'SQL union select', regex: /union.*?select.*?from/i, severity: 'high' },
  { name: 'SQL insert into values', regex: /insert\s+into\s+values/i, severity: 'medium' },
  { name: 'SQL update set', regex: /update\s+.*\s+set/i, severity: 'medium' },
  { name: 'SQL drop table', regex: /drop\s+table/i, severity: 'high' },
  { name: 'SQL alter table', regex: /alter\s+table/i, severity: 'high' },
  { name: 'SQL truncate table', regex: /truncate\s+table/i, severity: 'high' },
  { name: 'SQL comment', regex: /--\s*$/m, severity: 'medium' },
  { name: 'SQLi OR 1=1', regex: /\b(or|and)\s+1\s*=\s*1\b/i, severity: 'high' },
  { name: 'SQLi tautologie simple', regex: /\b(or|and)\b\s+('?\d+'?)\s*=\s*('?\d+'?)/i, severity: 'high' },

  // XSS (généralement high car risque critique)
  { name: 'XSS script tag', regex: /<script.*?>.*?<\/script>/gi, severity: 'high' },
  { name: 'XSS on* handlers', regex: /<.*?on\w+\s*?=\s*?.*?>/gi, severity: 'high' },
  { name: 'XSS image & media', regex: /(<img\s+[^>]*src[^>]*=|<iframe|<svg|<math|<object|<embed|<link|<style)/i, severity: 'medium' },
  { name: 'XSS onerror', regex: /onerror\s*=/i, severity: 'high' },
  { name: 'XSS document.cookie', regex: /document\.cookie/i, severity: 'high' },
  { name: 'XSS alert', regex: /alert\s*\(/i, severity: 'medium' },
  { name: 'XSS location redirection', regex: /window\.location/i, severity: 'medium' },
  { name: 'XSS encoded script', regex: /%3Cscript%3E/i, severity: 'high' },
  { name: 'XSS <style>', regex: /<style.*?>.*?<\/style>/gi, severity: 'medium' },
  { name: 'XSS <link rel=stylesheet>', regex: /<link.*?rel=["']stylesheet["'].*?>/i, severity: 'low' },

  // Commandes système (danger élevé)
  { name: 'Commandes système', regex: /(cat\s+\/etc\/passwd|ls\s+-la|whoami|rm\s+-rf\s+\/)/i, severity: 'high' },
  { name: 'Commandes bash, perl, python', regex: /\b(wget|curl|perl|bash|sh|nc|netcat|python|php)\b/i, severity: 'medium' },

  // Path traversal (medium à high selon la technique)
  { name: 'Path traversal ../', regex: /(\.\.\/)+/, severity: 'medium' },
  { name: 'Path traversal encodé', regex: /%2e%2e%2f|%2e%2e\/|%2e%2e/i, severity: 'high' },
  { name: 'Fichiers système sensibles', regex: /\/etc\/passwd|\/etc\/shadow|\/proc\/self\/environ/i, severity: 'high' },

  // Injection shell / PHP (high)
  { name: 'eval()', regex: /eval\s*\(/i, severity: 'high' },
  { name: 'base64_decode()', regex: /base64_decode\s*\(/i, severity: 'medium' },
  { name: 'shell_exec()', regex: /shell_exec\s*\(/i, severity: 'high' },
  { name: 'phpinfo()', regex: /phpinfo\s*\(/i, severity: 'medium' },

  // Encodages suspects (low à medium)
  { name: 'Encodages HTML dangereux', regex: /%3c|%3e|%22|%27|%3b|%28|%29|%7c/i, severity: 'low' },

  // Input injection suspecte (medium)
  { name: 'Input injection', regex: /input\s*=\s*['"][^'"]*('|--|;|<|>)[^'"]*['"]/i, severity: 'medium' },
  { name: "Path traversal Windows ..\\", regex: /(\.\.\\)+/i, severity: 'medium' },
];


// 🔧 Prétraitement du texte pour décodage
function preprocessPayload(payload) {
  if (typeof payload !== 'string') return '';

  try {
    // 1. Décodage URL (ex: %3Cscript%3E → <script>)
    let decoded = decodeURIComponent(payload);

    // 2. Décodage entités HTML (ex: &lt; → <)
    decoded = he.decode(decoded);

    // 3. Suppression des caractères invisibles (nul, tab, etc.)
    decoded = decoded.replace(/[\x00-\x1F\x7F]+/g, '');

    // 4. Nettoyage des espaces superflus
    decoded = decoded.replace(/\s+/g, ' ').trim();

    return decoded;
  } catch (e) {
    return payload; // En cas d’erreur, on renvoie le texte brut
  }
}

function severityLevel(sev) {
  const levels = { low: 1, medium: 2, high: 3 };
  return levels[sev] || 0;
}

// 🔍 Détection des patterns malveillants
function detectMaliciousPatterns(rawPayload) {
  const payload = preprocessPayload(rawPayload);

  let isMalicious = false;
  const patternsFound = [];
  let maxSeverityLevel = 0;
  let maxSeverity = 'low';

  for (const p of patterns) {
    if (p.regex.test(payload)) {
      isMalicious = true;
      patternsFound.push({ name: p.name, severity: p.severity }); // stocker objet complet
      if (severityLevel(p.severity) > maxSeverityLevel) {
        maxSeverityLevel = severityLevel(p.severity);
        maxSeverity = p.severity;
      }
    }
  }

  return { isMalicious, patterns: patternsFound, severity: maxSeverity, payload };
}



module.exports = { detectMaliciousPatterns };
