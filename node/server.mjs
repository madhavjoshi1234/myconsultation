import dotenv from 'dotenv';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import { setupAuthRoutes } from './authRoutes.mjs';
import { setupAdminRoutes } from './adminRoutes.mjs';
import { setupClientRoutes } from './clientRoutes.mjs';
import { setupDbSetupRoute, startDatabase } from './common/database.mjs';
import { setupHealthRoute, writeLog } from './common/utils.mjs';
import { setupStaffRoutes } from './staffRoutes.mjs';
import { executeSql } from './common/database.mjs';

writeLog("--- SERVER.JS EXECUTION STARTED ---");
dotenv.config(); // Load environment variables from .env file

let port = process.env.PORT || 3020;
let appContext = process.env.APP_CONTEXT || '/';
let appUrl = `http://127.0.0.1:${port}${appContext}`;
writeLog('appUrl: ', appUrl, ', appContext: ', appContext);

const app = express();
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(express.json()); // Middleware for parsing JSON bodies

// Serve static files (HTML, CSS, frontend JS) from a 'public' directory
// Create a folder named 'public' in your project root and put register.html and style.css there.
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.redirect('/login.html');
});
const router = express.Router();

setupHealthRoute(router);

// Get encryption key from a secure env var (not in .env file)
// Database connection
const db = await startDatabase({
    host: process.env.DB_HOST || 'localhost', // Or your MySQL host
    user: process.env.DB_USER,      // Your MySQL username
    password: process.env.DB_PASSWORD,  // Your MySQL password from environment variable
    db: process.env.DB_DATABASE, // Your database name
});

setupRoutes(router, db);

app.use('/', router);

app.listen(port, () => {
    writeLog('Server listening on http://127.0.0.1:' + port, process.env.PORT);
});

function setupRoutes(router, db) {
    const JWT_SECRET = process.env.JWT_SECRET;
    const EMAIL_USER = process.env.EMAIL_USER || ''; // Your email for sending
    const EMAIL_PASS = process.env.EMAIL_PASS;
    writeLog(' Email User:', EMAIL_USER);
    // Email transporter setup
    const transporter = nodemailer.createTransport({
        service: 'Gmail', // Or your email provider
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS,
        },
    });

    setupDbSetupRoute(router, db);

    setupAuthRoutes({ router, db, JWT_SECRET, EMAIL_USER, transporter, appUrl });

    setupAdminRoutes({ router, db, JWT_SECRET, EMAIL_USER, transporter, appUrl });

    setupClientRoutes({ router, db, JWT_SECRET, EMAIL_USER, transporter, appUrl });

    setupStaffRoutes({ router, db, JWT_SECRET, EMAIL_USER, transporter, appUrl });
}
