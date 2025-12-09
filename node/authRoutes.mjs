import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { executeSql } from './common/database.mjs';
import { writeLog, checkPasswordPolicy } from './common/utils.mjs';

export function setupAuthRoutes({ router, db, JWT_SECRET, EMAIL_USER, transporter, appUrl }) {

    // Unified Login
    router.post('/api/login', async (req, res) => {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        try {
            const [users] = await executeSql(db,
                `SELECT u.user_id, u.email, u.password_hash, u.is_active, u.is_email_verified, GROUP_CONCAT(r.role_name) as roles
                 FROM users_v2 u
                 JOIN user_roles ur ON u.user_id = ur.user_id
                 JOIN roles r ON ur.role_id = r.role_id
                 WHERE u.email = ?
                 GROUP BY u.user_id`,
                [email]
            );

            if (users.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const user = users[0];
            const isPasswordValid = await bcrypt.compare(password, user.password_hash);

            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const userRoles = user.roles ? user.roles.split(',') : [];

            // Role-specific checks
            if (userRoles.includes('client')) {
                if (!user.is_email_verified) {
                    return res.status(403).json({ error: 'Email not verified. Please verify your email first.' });
                }
                if (!user.is_active) {
                    return res.status(403).json({ error: 'Your account has not been activated by the admin yet. Please wait for the activation email.' });
                }
            } else if (!userRoles.some(role => ['admin', 'nutritionist', 'executive'].includes(role))) {
                // If user is not a client and not a staff/admin, they can't log in.
                return res.status(403).json({ error: 'You do not have a role that can log in.' });
            }

            const token = jwt.sign(
                { userId: user.user_id, email: user.email, roles: userRoles },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.json({ message: 'Login successful', token, roles: userRoles });

        } catch (error) {
            writeLog('Login error:', error);
            res.status(500).json({ error: 'Login failed' });
        }
    });

    // Unified Forgot Password
    router.post('/api/forgot-password', async (req, res) => {
        const { email } = req.body;
        writeLog(`[Unified Forgot Pwd] Request for email: ${email}`);

        if (email) {
            try {
                const [users] = await executeSql(db,
                    `SELECT u.user_id, u.first_name, GROUP_CONCAT(r.role_name) as roles
                     FROM users_v2 u
                     LEFT JOIN user_roles ur ON u.user_id = ur.user_id
                     LEFT JOIN roles r ON ur.role_id = r.role_id
                     WHERE u.email = ?
                     GROUP BY u.user_id`,
                    [email]
                );

                if (users.length > 0) {
                    const user = users[0];
                    const userRoles = user.roles ? user.roles.split(',') : [];

                    // Check if user has any valid role
                    if (userRoles.some(role => ['client', 'admin', 'nutritionist', 'executive'].includes(role))) {
                        const resetToken = crypto.randomBytes(32).toString('hex');
                        const resetTokenExpiry = new Date(Date.now() + 3600000); // Token expires in 1 hour

                        await executeSql(db,
                            'UPDATE users_v2 SET password_reset_token = ?, password_reset_expires_at = ? WHERE user_id = ?',
                            [resetToken, resetTokenExpiry, user.user_id]
                        );

                        const resetLink = `${appUrl}reset-password.html?token=${resetToken}`;
                        const mailOptions = {
                            from: `"Consultation Service" <${EMAIL_USER}>`,
                            to: email,
                            subject: 'Password Reset Request',
                            html: `<p>Dear ${user.first_name},</p><p>You requested a password reset. Click <a href="${resetLink}">here</a> to reset your password. This link will expire in 1 hour.</p><p>If you did not request this, please ignore this email.</p>`
                        };

                        if (EMAIL_USER && transporter) {
                            await transporter.sendMail(mailOptions);
                            writeLog(`[Unified Forgot Pwd] Password reset email sent to ${email}`);
                        } else {
                            writeLog(`[Unified Forgot Pwd] Email not sent for password reset to ${email}. Token for testing: ${resetToken}`);
                        }
                    }
                }
            } catch (error) {
                writeLog('[Unified Forgot Pwd] Error during DB/token operations:', error);
            }
        }
        // Always send a generic success message to prevent email enumeration
        res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    });

    // Unified Reset Password
    router.post('/api/reset-password', async (req, res) => {
        const { token, newPassword } = req.body;
        writeLog(`[Unified Reset Pwd] Attempt with token: ${token ? token.substring(0, 10) + '...' : 'No Token'}`);

        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password are required.' });
        }

        const passwordPolicyResult = checkPasswordPolicy(newPassword);
        if (!passwordPolicyResult.isValid) {
            return res.status(400).json({ error: passwordPolicyResult.message });
        }

        try {
            const [users] = await executeSql(db,
                "SELECT user_id, password_reset_expires_at FROM users_v2 WHERE password_reset_token = ?",
                [token]
            );

            if (users.length === 0) {
                return res.status(400).json({ error: 'Invalid or expired password reset token.' });
            }
            const user = users[0];

            if (new Date() > new Date(user.password_reset_expires_at)) {
                await executeSql(db, 'UPDATE users_v2 SET password_reset_token = NULL, password_reset_expires_at = NULL WHERE user_id = ?', [user.user_id]);
                return res.status(400).json({ error: 'Password reset token has expired.' });
            }

            const newPasswordHash = await bcrypt.hash(newPassword, 10);
            await executeSql(db,
                'UPDATE users_v2 SET password_hash = ?, password_reset_token = NULL, password_reset_expires_at = NULL WHERE user_id = ?',
                [newPasswordHash, user.user_id]
            );

            writeLog(`Password reset successfully for user ID: ${user.user_id}`);
            res.json({ message: 'Password has been reset successfully. You can now login with your new password.' });
        } catch (error) {
            writeLog('Error resetting password:', error);
            res.status(500).json({ error: 'Failed to reset password. The link may be invalid or expired. Please try again.' });
        }
    });

    // API endpoint to send a login OTP to a client's email
    router.post('/api/client/login-otp/send', async (req, res) => {
        const { email } = req.body;
        writeLog(`[${new Date().toISOString()}] /api/client/login-otp/send request for email: ${email}`);

        if (email) {
            try {
                const [users] = await executeSql(db,
                    `SELECT u.user_id, u.first_name, u.is_email_verified, u.is_active, GROUP_CONCAT(r.role_name) as roles
                     FROM users_v2 u
                     LEFT JOIN user_roles ur ON u.user_id = ur.user_id
                     LEFT JOIN roles r ON ur.role_id = r.role_id
                     WHERE u.email = ?
                     GROUP BY u.user_id`,
                    [email]
                );

                if (users.length > 0) {
                    const user = users[0];
                    const userRoles = user.roles ? user.roles.split(',') : [];

                    // Only proceed if the user is a client, is verified, and is active.
                    if (userRoles.includes('client') && user.is_email_verified && user.is_active) {
                        const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
                        const otp = generateOTP();
                        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

                        await executeSql(db,
                            'UPDATE users_v2 SET email_otp = ?, email_otp_expires_at = ? WHERE user_id = ?',
                            [otp, otpExpiry, user.user_id]
                        );

                        const mailOptions = {
                            from: `"Consultation Service" <${EMAIL_USER}>`,
                            to: email,
                            subject: 'Your Login OTP for Consultation Service',
                            html: `<p>Dear ${user.first_name},</p><p>Your One-Time Password (OTP) for login is: <b>${otp}</b></p><p>This OTP will expire in 10 minutes.</p><p>If you did not request this, please ignore this email.</p>`
                        };

                        if (EMAIL_USER && transporter) {
                            await transporter.sendMail(mailOptions);
                            writeLog(`[OTP Login] Login OTP sent to ${email}`);
                        } else {
                            writeLog(`[OTP Login] Email not sent to ${email}. EMAIL_USER not configured. OTP for testing: ${otp}`);
                        }
                    }
                }
            } catch (error) {
                writeLog('Error sending login OTP:', error);
            }
        }
        // Always send a generic success message to prevent email enumeration.
        res.json({ message: 'If an account with that email exists and is active, an OTP has been sent.' });
    });

    // Client Verify Login OTP
    router.post('/api/client/login-otp/verify', async (req, res) => {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required.' });
        }

        try {
            const [users] = await executeSql(db,
                'SELECT user_id, email, is_active, is_email_verified FROM users_v2 WHERE email = ? AND email_otp = ? AND email_otp_expires_at > NOW()',
                [email, otp]
            );

            if (users.length === 0) {
                return res.status(400).json({ error: 'Invalid or expired OTP.' });
            }

            const user = users[0];

            if (!user.is_email_verified) {
                return res.status(403).json({ error: 'Your email address has not been verified.' });
            }
            console.log(`LOGIN CHECK: User ${user.user_id} has is_active status of:`, user.is_active);
            
            if (!user.is_active) {
               return res.status(403).json({ error: 'Your account has not been activated by the admin yet. Please wait for the activation email.' });
            }

            // Clear the OTP from the table
            await executeSql(db, 'UPDATE users_v2 SET email_otp = NULL, email_otp_expires_at = NULL WHERE user_id = ?', [user.user_id]);

            const [roleRows] = await executeSql(db, 'SELECT r.role_name FROM user_roles ur JOIN roles r ON ur.role_id = r.role_id WHERE ur.user_id = ?', [user.user_id]);
            const roles = roleRows.map(r => r.role_name);

            const token = jwt.sign({ clientId: user.user_id, email: user.email, roles: roles }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ message: 'Login successful', token });
        } catch (error) {
            writeLog('Error verifying login OTP:', error);
            res.status(500).json({ error: 'Login failed. Please try again.' });
        }
    });
}