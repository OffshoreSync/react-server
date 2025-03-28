// utils/logger.js
const isProduction = process.env.NODE_ENV === 'production';

/**
 * Safe logging utility that only logs in non-production environments
 * @param {string} message - The log message
 * @param {*} [data] - Optional data to log
 * @param {'log'|'warn'|'error'} [level='log'] - Logging level
 */
function safeLog(message, data, level = 'log') {
  if (!isProduction) {
    // Check if data is undefined or null
    const logData = data === undefined || data === null 
      ? '' 
      : typeof data === 'object' 
        ? redactSensitiveData(data) 
        : data;

    switch (level) {
      case 'log':
        console.log(message, logData);
        break;
      case 'warn':
        console.warn(message, logData);
        break;
      case 'error':
        console.error(message, logData);
        break;
    }
  }
}

/**
 * Redact sensitive information from logs
 * @param {*} data - Data to redact
 * @param {string[]} [customFields=[]] - Additional fields to redact
 * @returns {*} Redacted data
 */
function redactSensitiveData(data, customFields = [], seen = new WeakSet()) {
  const sensitiveFields = [
    'password', 'email', 'token', 'verificationToken', 
    'accessKey', 'secretKey', 'apiKey', 'refreshToken',
    'ssn', 'creditCard', 'phone', 'address', 
    'username', 'fullname', 
    ...customFields
  ];

  function deepRedact(value) {
    // Prevent circular references
    if (value && typeof value === 'object') {
      if (seen.has(value)) return '[Circular]';
      seen.add(value);
    }

    if (value === null || value === undefined) return value;

    if (typeof value === 'string') {
      return sensitiveFields.some(field => 
        value.toLowerCase().includes(field.toLowerCase())
      ) ? '**REDACTED**' : value;
    }

    if (typeof value === 'object') {
      if (Array.isArray(value)) {
        return value.map(deepRedact);
      }

      const redactedObj = { ...value };
      for (const [key, val] of Object.entries(redactedObj)) {
        if (sensitiveFields.some(field => 
          key.toLowerCase().includes(field.toLowerCase())
        )) {
          redactedObj[key] = '**REDACTED**';
        } else {
          redactedObj[key] = deepRedact(val);
        }
      }
      return redactedObj;
    }

    return value;
  }

  return deepRedact(data);
}

module.exports = {
  safeLog,
  redactSensitiveData
};