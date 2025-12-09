import express from 'express';
import { readLogs, writeLog } from './utils.mjs';
import mysql from 'mysql2';
import dotenv from 'dotenv';
dotenv.config(); // Load environment variables from .env file
import { runSetup } from './setup.mjs';

const app = express();
app.use(express.json()); // Middleware for parsing JSON bodies

const router = express.Router();
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

app.use(process.env.APP_CONTEXT, router);
const ENC_KEY = process.env.ENC_KEY || 'default';
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost', // Or your MySQL host
    user: process.env.DB_USER,      // Your MySQL username
    password: process.env.DB_PASSWORD,  // Your MySQL password from environment variable
    database: process.env.DB_NAME, // Your database name
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise(); // Use promise-based API for cleaner async/await

if (false ) {
     await runSetup(db, ENC_KEY);
}

const port = process.env.PORT || 3020;
app.listen(port, () => {
    writeLog('Server listening on http://127.0.0.1:' + port, process.env.PORT);
});
