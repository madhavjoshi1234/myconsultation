import fs from 'fs/promises';

let tail = [];
export const tailSettings = {
  tailSize: 3000 // Default size of the log tail
};
let appendFailed = false;
export function writeLog(...args) {
  const message = format(args);
  tail.push(message);
  if (tail.length > tailSettings.tailSize) {
    tail.shift(); // Keep the last 100 logs
  }
  if (!appendFailed) {
    fs.appendFile('app.log', message, (err) => {
      if (err) {
        appendFailed = true;
        tail.push(format('Failed to write to app.log:', err));
      }
    });
  }
  try {
    console.log(...args);
  } catch (e) {
    // ignore
  }
}

function format(args) {
  return [new Date().toISOString(), ...args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : `${arg}`
  )].join(' ') + '\n';
}

export function readLogs() {
  return tail;
}

export function setupHealthRoute(router) {
  if (process.env.NODE_ENV === 'development') {
    router.post('/api/health', async (req, res) => {
      if (!req.body || !req.body.token || req.body.token !== process.env.HEALTH_CHECK_TOKEN) {
        res.status(400).json({ error: 'Bad Request' });
        return;
      }
      try {
        res.json({ status: 'OK', timestamp: new Date().toISOString(), logs: readLogs() });
      } catch (error) {
        writeLog('Error reading logs:', error);
        res.status(500).json({ error: 'Failed to read logs' });
      }
    });
  }
}

export function checkPasswordPolicy(password) {
  // ensure strong password
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  const policy = ` Policy: Password is required and must be at least ${minLength} characters long, include an uppercase letter, a lowercase letter, a number, and a special character.`;

  if (password.length < minLength) {
    return { isValid: false, message: `Password must be at least ${minLength} characters long.` + policy };
  }
  if (!hasUpperCase) {
    return { isValid: false, message: 'Password must contain at least one uppercase letter.' + policy };
  }
  if (!hasLowerCase) {
    return { isValid: false, message: 'Password must contain at least one lowercase letter.' + policy };
  }
  if (!hasNumbers) {
    return { isValid: false, message: 'Password must contain at least one number.' + policy };
  }
  if (!hasSpecialChar) {
    return { isValid: false, message: 'Password must contain at least one special character (e.g., !@#$%^&*).' + policy };
  }

  return { isValid: true, message: 'Password meets policy requirements.' };

}