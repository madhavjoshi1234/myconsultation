import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { writeLog, checkPasswordPolicy } from './common/utils.mjs';
import sanitizeHtml from 'sanitize-html';
import { executeSql } from './common/database.mjs';

export function setupAdminRoutes({ router, db, JWT_SECRET, EMAIL_USER, transporter, appUrl }) {
    // Middleware to verify Admin JWT
    const verifyAdminToken = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7, authHeader.length);
            writeLog('[verifyAdminToken] Token received by server:', token);
            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (err) {
                    writeLog('[verifyAdminToken] JWT verification error:', err.name, err.message, 'ExpiredAt:', err.expiredAt); // Log specific JWT error
                    return res.status(403).json({ error: `Forbidden: Token verification failed (${err.name})` });
                }
                let userRoles = [];
                if (decoded.roles && Array.isArray(decoded.roles)) {
                    userRoles = decoded.roles;
                } else if (typeof decoded.role === 'string') {
                    userRoles = [decoded.role];
                }

                if (userRoles.length === 0) {
                    return res.status(403).json({ error: 'Forbidden: No roles found in token' });
                }

                const hasAdmnRole = userRoles.includes('admin');
                if (!hasAdmnRole) {
                    return res.status(403).json({ error: 'Forbidden: Invalid or missing admin token' });
                }

                req.user = { ...decoded, roles: userRoles };
                next();
            });
        } else {
            writeLog('[verifyAdminToken] Unauthorized: Missing admin token in headers.');
            res.status(401).json({ error: 'Unauthorized: Missing admin token' });
        }
    };

    const verifyNutritionistToken = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7, authHeader.length);
            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (err) {
                    writeLog(`[verifyNutritionistToken] JWT verification error: ${err.name}`);
                    return res.status(403).json({ error: `Forbidden: Token verification failed (${err.name})` });
                }
                let userRoles = [];
                if (decoded.roles && Array.isArray(decoded.roles)) {
                    userRoles = decoded.roles;
                } else if (typeof decoded.role === 'string') {
                    userRoles = [decoded.role];
                }

                if (!userRoles.includes('nutritionist')) {
                    return res.status(403).json({ error: 'Forbidden: Access denied. Not a nutritionist.' });
                }

                req.user = { ...decoded, userId: decoded.userId, roles: userRoles };
                next();
            });
        } else {
            writeLog('[verifyNutritionistToken] Unauthorized: Missing staff token.');
            res.status(401).json({ error: 'Unauthorized: Missing staff token' });
        }
    };

    const verifyExecutiveToken = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7, authHeader.length);
            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (err) {
                    writeLog(`[verifyExecutiveToken] JWT verification error: ${err.name}`);
                    return res.status(403).json({ error: `Forbidden: Token verification failed (${err.name})` });
                }
                let userRoles = [];
                if (decoded.roles && Array.isArray(decoded.roles)) {
                    userRoles = decoded.roles;
                } else if (typeof decoded.role === 'string') {
                    userRoles = [decoded.role];
                }

                if (!userRoles.includes('executive')) {
                    return res.status(403).json({ error: 'Forbidden: Access denied. Not an executive.' });
                }

                req.user = { ...decoded, userId: decoded.userId, roles: userRoles };
                next();
            });
        } else {
            writeLog('[verifyExecutiveToken] Unauthorized: Missing staff token.');
            res.status(401).json({ error: 'Unauthorized: Missing staff token' });
        }
    };

    // --- Initial Admin Setup ---
    router.post('/api/setup/first-admin', async (req, res) => {
        const { first_name, last_name, email, password } = req.body;

        if (!first_name || !last_name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        const passwordPolicyResult = checkPasswordPolicy(password);
        if (!passwordPolicyResult.isValid) {
            return res.status(400).json({ error: passwordPolicyResult.message });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Check if an admin already exists
            const [adminUsers] = await executeSql(connection, `
                SELECT ur.user_id FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                WHERE r.role_name = 'admin' LIMIT 1
            `);
            if (adminUsers.length > 0) {
                await connection.rollback();
                return res.status(403).json({ error: 'Forbidden: An admin account already exists. Setup is complete.' });
            }

            // Check if the email is already in use
            const [existingEmail] = await executeSql(connection, "SELECT user_id FROM users_v2 WHERE email = ?", [email]);
            if (existingEmail.length > 0) {
                await connection.rollback();
                return res.status(409).json({ error: 'Email already in use.' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            // Insert into the new users_v2 table. is_email_verified is true for admin by default.
            const [newUserResult] = await executeSql(connection,
                'INSERT INTO users_v2 (first_name, last_name, email, password_hash, is_active, is_email_verified) VALUES (?, ?, ?, ?, ?, ?)',
                [first_name, last_name, email, hashedPassword, true, true]
            );
            const newUserId = newUserResult.insertId;

            // Link user to 'admin' role
            const [adminRole] = await executeSql(connection, "SELECT role_id FROM roles WHERE role_name = 'admin'");
            if (adminRole.length === 0) throw new Error("Critical: 'admin' role not found in roles table.");
            await executeSql(connection, 'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [newUserId, adminRole[0].role_id]);

            await connection.commit();
            res.status(201).json({ message: 'First admin account created successfully!', user_id: newUserId });

        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error creating first admin:', error);
            res.status(500).json({ error: 'Failed to create first admin' });
        } finally {
            if (connection) connection.release();
        }
    });

    // --- Admin Authentication ---
    router.get('/admin.html', verifyAdminToken, (req, res) => {
        res.sendFile(__dirname + '/public/admin.html');
    });

    // --- Admin Routes ---
    // Get all staff (nutritionists and executives)
    router.get('/api/admin/staff', verifyAdminToken, async (req, res) => {
        try {
            const [staff] = await executeSql(db, `
                SELECT
                    u.user_id,
                    u.first_name,
                    u.last_name,
                    u.email,
                    u.is_active,
                    GROUP_CONCAT(r.role_name) as roles
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id
                JOIN roles r ON ur.role_id = r.role_id
                GROUP BY u.user_id, u.first_name, u.last_name, u.email, u.is_active
                HAVING SUM(CASE WHEN r.role_name = 'client' THEN 0 ELSE 1 END) > 0
                ORDER BY u.user_id + 0
            `);
            const staffWithRoles = staff.map(user => {
                return { ...user, roles: user.roles ? user.roles.split(',') : [] };
            });
            res.json(staffWithRoles);
        } catch (error) {
            writeLog('Error fetching staff:', error);
            res.status(500).json({ error: 'Failed to fetch staff' });
        }
    });

    // Add a new nutritionist
    // Add new staff
    router.post('/api/admin/staff', verifyAdminToken, async (req, res) => {
        const { first_name, last_name, email, password, roles } = req.body; // Expecting roles as ['N', 'E']
 
        if (!first_name || !last_name || !email || !password || !Array.isArray(roles) || roles.length === 0) {
            return res.status(400).json({ error: 'All fields and at least one role are required' });
        }
 
        const passwordPolicyResult = checkPasswordPolicy(password);
        if (!passwordPolicyResult.isValid) {
            return res.status(400).json({ error: passwordPolicyResult.message });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
 
        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();
 
            const [existingUser] = await executeSql(connection, 'SELECT user_id FROM users_v2 WHERE email = ?', [email]);
            let userId;
            let message;

            if (existingUser.length > 0) {
                // User exists, so we update their roles.
                userId = existingUser[0].user_id;
                message = 'Existing user roles updated successfully.';
                // Note: We are ignoring the password from the form in this case.
            } else {
                // User does not exist, create a new one.
                const hashedPassword = await bcrypt.hash(password, 10);
                const [newUserResult] = await executeSql(connection,
                    'INSERT INTO users_v2 (first_name, last_name, email, password_hash, is_active, is_email_verified) VALUES (?, ?, ?, ?, ?, ?)',
                    [first_name, last_name, email, hashedPassword, true, true] // Staff are auto-verified
                );
                userId = newUserResult.insertId;
                message = 'New staff member added successfully.';
            }
 
            const roleMap = { 'A': 'admin', 'N': 'nutritionist', 'E': 'executive' };
            const roleNames = roles.map(code => roleMap[code]).filter(Boolean);

            if (roleNames.length !== roles.length) {
                await connection.rollback();
                return res.status(400).json({ error: 'Invalid role code provided.' });
            }
 
            const placeholders = roleNames.map(() => '?').join(',');
            const [roleRows] = await executeSql(connection, `SELECT role_id FROM roles WHERE role_name IN (${placeholders})`, roleNames);
 
            if (roleRows.length !== roleNames.length) {
                await connection.rollback();
                return res.status(500).json({ error: 'Could not find all specified roles in the database.' });
            }
 
            const userRolesData = roleRows.map(row => [userId, row.role_id]);
            if (userRolesData.length > 0) {
                // Use INSERT IGNORE to prevent errors if the user already has one of the roles.
                await connection.query('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES ?', [userRolesData]);
            }
 
            await connection.commit();
            res.status(201).json({ message: message, user_id: userId });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error adding staff:', error);
            res.status(500).json({ error: 'Failed to add staff' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Update user roles
    router.patch('/api/admin/users/:userId/roles', verifyAdminToken, async (req, res) => {
        const { userId } = req.params;
        const { roles } = req.body; // Expecting an array of role codes, e.g., ['N', 'E']

        if (!Array.isArray(roles)) {
            return res.status(400).json({ error: 'Roles must be an array' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Delete existing non-client roles from `user_roles` for this user
            await executeSql(connection, 'DELETE FROM user_roles WHERE user_id = ? AND role_id != (SELECT role_id FROM roles WHERE role_name = "client")', [userId]);

            // Insert new roles into `user_roles`
            if (roles.length > 0) {
                const roleMap = { 'A': 'admin', 'N': 'nutritionist', 'E': 'executive' };
                const roleNames = roles.map(code => roleMap[code]).filter(Boolean);

                if (roleNames.length !== roles.length) {
                    await connection.rollback();
                    return res.status(400).json({ error: 'Invalid role code provided.' });
                }

                const placeholders = roleNames.map(() => '?').join(',');
                const [roleRows] = await executeSql(connection, `SELECT role_id FROM roles WHERE role_name IN (${placeholders})`, roleNames);

                if (roleRows.length !== roleNames.length) {
                    await connection.rollback();
                    return res.status(500).json({ error: 'Could not find all specified roles in the database.' });
                }

                const userRolesData = roleRows.map(row => [userId, row.role_id]);
                await connection.query('INSERT INTO user_roles (user_id, role_id) VALUES ?', [userRolesData]);
            }

            await connection.commit();
            res.json({ message: 'User roles updated successfully' });

        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error updating user roles:', error);
            res.status(500).json({ error: 'Failed to update user roles' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Activate/Deactivate staff user
    router.patch('/api/admin/users/:userId/status', verifyAdminToken, async (req, res) => {
        const { userId } = req.params;
        const { is_active } = req.body;

        if (typeof is_active !== 'boolean') {
            return res.status(400).json({ error: 'is_active field must be a boolean' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Update new table
            const [result] = await executeSql(connection, 'UPDATE users_v2 SET is_active = ? WHERE user_id = ?', [is_active, userId]);

            if (result.affectedRows === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'User not found' });
            }

            await connection.commit();
            res.json({ message: `User status updated successfully` });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error updating user status:', error);
            res.status(500).json({ error: 'Failed to update user status' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Admin: Update staff details
    router.put('/api/admin/staff/:userId', verifyAdminToken, async (req, res) => {
        const { userId } = req.params;
        const { first_name, last_name, email } = req.body;

        if (!first_name || !last_name || !email) {
            return res.status(400).json({ error: 'First name, last name, and email are required.' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Check if the new email already exists for another user
            const [existingUser] = await executeSql(connection,
                'SELECT user_id FROM users_v2 WHERE email = ? AND user_id != ?',
                [email, userId]
            );

            if (existingUser.length > 0) {
                await connection.rollback();
                return res.status(409).json({ error: 'This email address is already in use by another user.' });
            }

            const [result] = await executeSql(connection,
                'UPDATE users_v2 SET first_name = ?, last_name = ?, email = ? WHERE user_id = ?',
                [first_name, last_name, email, userId]
            );

            if (result.affectedRows === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'Staff member not found.' });
            }

            await connection.commit();
            res.json({ message: 'Staff details updated successfully.' });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog(`Error updating staff details for user ${userId}:`, error);
            res.status(500).json({ error: 'Failed to update staff details.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Route to serve admin.html, protected by admin token
    router.get('/api/admin/clients', verifyAdminToken, async (req, res) => {
        try {
            const [clients] = await executeSql(db, `
                SELECT
                    u.user_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number,
                    u.created_at as registration_date,
                    u.is_email_verified,
                    u.is_active as is_account_active,
                    u.assigned_nutritionist_id as nutritionist_id,
                    CONCAT(nutri.first_name, ' ', nutri.last_name) as nutritionist_name,
                    cc.is_finalized,
                    cc.is_food_plan_complete,
                    (SELECT COUNT(*) > 0 FROM client_food_plans cfp WHERE cfp.client_consultation_id = cc.client_consultation_id) as has_food_plan_suggested,
                    u.assigned_executive_id as enrolled_by_executive_id,
                    CONCAT(exec.first_name, ' ', exec.last_name) as executive_name
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id AND ur.role_id = (SELECT role_id FROM roles WHERE role_name = 'client')
                LEFT JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
                LEFT JOIN users_v2 nutri ON u.assigned_nutritionist_id = nutri.user_id
                LEFT JOIN users_v2 exec ON u.assigned_executive_id = exec.user_id
                ORDER BY u.user_id ASC
            `);
            res.json(clients);
        } catch (error) {
            writeLog('Error fetching all clients for admin:', error);
            res.status(500).json({ error: 'Failed to fetch clients' });
        }
    });
    // Toggle client account active status by Admin
    router.patch('/api/admin/clients/:clientId/status', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        const { is_active } = req.body; // Expecting { is_active: true/false }

        if (typeof is_active !== 'boolean') {
            return res.status(400).json({ error: 'is_active field must be a boolean' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            const [result] = await executeSql(connection,
                'UPDATE users_v2 SET is_active = ? WHERE user_id = ?',
                [is_active, clientId]
            );

            if (result.affectedRows === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'Client not found' });
            }

            // If account was activated, send an email to the client
            if (is_active) {
                const [users] = await executeSql(connection,
                    'SELECT email, first_name FROM users_v2 WHERE user_id = ?',
                    [clientId]);
                if (users.length > 0) {
                    const client = users[0];
                    const mailOptions = {
                        from: `"Consultation Service" <${EMAIL_USER}>`,
                        to: client.email,
                        subject: 'Your Account Has Been Activated!',
                        html: `
                            <p>Dear ${client.first_name},</p>
                            <p>Great news! Your account with Consultation Service has been activated by our admin team.</p>
                            <p>You can now log in using your registered email address and the password you created during registration.</p>
                            <p>If you have any questions or need assistance, please feel free to contact us.</p>
                            <p>Welcome aboard!</p>
                            <p>Sincerely,<br>The Consultation Service Team</p>
                        `,
                    };
                    if (EMAIL_USER !== '') {
                        try {
                            await transporter.sendMail(mailOptions);
                            writeLog(`Sent account activation email to ${client.email}`);
                        } catch (emailError) {
                            writeLog('Error sending activation email:', emailError);
                        }
                    } else {
                        writeLog(`Could not send account activation email to ${client.email} due to missing email setup.`);
                    }
                }
            }
            await connection.commit();
            res.json({ message: `Client account ${is_active ? 'activated' : 'deactivated'} successfully` });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error updating client account status:', error);
            res.status(500).json({ error: 'Failed to update client account status' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Admin: Assign Nutritionist to Client
    router.patch('/api/admin/clients/:clientId/assign-nutritionist', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        const { staff_id } = req.body; // staff_id here is the nutritionist's user_id

        if (!staff_id) {
            return res.status(400).json({ error: 'Nutritionist ID (staff_id) is required.' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Optional: Verify staff_id is a valid active nutritionist
            const [nutritionistUser] = await executeSql(connection,
                `SELECT u.user_id FROM users_v2 u
                 JOIN user_roles ur ON u.user_id = ur.user_id
                 JOIN roles r ON ur.role_id = r.role_id
                 WHERE u.user_id = ? AND r.role_name = 'nutritionist' AND u.is_active = TRUE`,
                [staff_id]
            );
            if (nutritionistUser.length === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'Active nutritionist not found with the provided ID.' });
            }

            const [result] = await executeSql(connection,
                `UPDATE users_v2 SET assigned_nutritionist_id = ? WHERE user_id = ?`,
                [staff_id, clientId]
            );

            // If the main client record wasn't updated, it's an error.
            if (result.affectedRows === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'Client not found or no change made.' });
            }

            await connection.commit();
            res.json({ message: 'Nutritionist assigned successfully to client.' });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error assigning nutritionist to client:', error);
            res.status(500).json({ error: 'Failed to assign nutritionist.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Admin: Assign Executive to Client
    router.patch('/api/admin/clients/:clientId/assign-executive', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        const { staff_id } = req.body; // staff_id here is the executive's user_id

        if (!staff_id) {
            return res.status(400).json({ error: 'Executive ID (staff_id) is required.' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Verify staff_id is a valid active executive from the new tables
            const [executiveUser] = await executeSql(connection,
                `SELECT u.user_id FROM users_v2 u
                 JOIN user_roles ur ON u.user_id = ur.user_id
                 JOIN roles r ON ur.role_id = r.role_id
                 WHERE u.user_id = ? AND r.role_name = 'executive' AND u.is_active = TRUE`,
                [staff_id]
            );
            if (executiveUser.length === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'Active executive not found with the provided ID.' });
            }

            const [result] = await executeSql(connection,
                `UPDATE users_v2 SET assigned_executive_id = ? WHERE user_id = ?`,
                [staff_id, clientId]
            );

            if (result.affectedRows === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'Client not found or no change made.' });
            }
            await connection.commit();
            res.json({ message: 'Executive linked successfully to client.' });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error linking executive to client:', error);
            res.status(500).json({ error: 'Failed to link executive.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Admin: Get specific client details
    router.get('/api/admin/clients/:clientId/details', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        try {
            const [clients] = await executeSql(db, `
                SELECT
                   u.user_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number
                FROM users_v2 u
                WHERE u.user_id = ?`,
                [clientId]
            );
            if (clients.length === 0) {
                return res.status(404).json({ error: 'Client not found' });
            }
            res.json(clients[0]);
        } catch (error) {
            writeLog('Error fetching client details for admin:', error);
            res.status(500).json({ error: 'Failed to fetch client details' });
        }
    });

    // Admin: Update specific client details
    router.put('/api/admin/clients/:clientId/details', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        const { first_name, last_name, email, mobile_number } = req.body;

        if (!first_name || !last_name || !email || !mobile_number) {
            return res.status(400).json({ error: 'All fields (first_name, last_name, email, mobile_number) are required' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Check if the new email already exists for another user in the new system
            const [existingV2Users] = await executeSql(connection,
                `SELECT user_id FROM users_v2 WHERE email = ? AND user_id != ?`,
                [email, clientId]
            );
            if (existingV2Users.length > 0) {
                await connection.rollback();
                return res.status(409).json({ error: 'Email already registered for another user.' });
            }

            // Update new `users_v2` table
            const [result] = await executeSql(connection,
                `UPDATE users_v2 SET first_name = ?, last_name = ?, email = ?, mobile_number = ? WHERE user_id = ?`,
                [first_name, last_name, email, mobile_number, clientId]
            );

            if (result.affectedRows === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'Client not found or no changes made' });
            }

            await connection.commit();
            res.json({ message: 'Client details updated successfully' });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error updating client details by admin:', error);
            res.status(500).json({ error: 'Failed to update client details' });
        } finally {
            if (connection) connection.release();
        }
    });

    router.get('/api/admin/clients/:clientId/consultations', verifyAdminToken, async (req, res) => {
        writeLog(`[${new Date().toISOString()}] /api/admin/clients/${req.params.clientId}/consultations HIT`);
        try {
            const [consultations] = await executeSql(db, `
                SELECT * FROM client_consultations
                WHERE user_id = (SELECT new_user_id FROM client_id_to_user_id_mapping WHERE old_client_id = ?)
                ORDER BY created_at DESC`,
                [req.params.clientId]
            );
            res.json(consultations);
        } catch (error) {
            writeLog('Error fetching client consultations for admin:', error);
            res.status(500).json({ error: 'Failed to fetch client consultations' });
        }
    });

    router.post('/api/admin/clients/:clientId/consultations', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        writeLog(`[${new Date().toISOString()}] POST /api/admin/clients/${clientId}/consultations HIT`);
        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();
            const userId = clientId;

            // 2. Find the latest finalized consultation for this user
            const [latestConsultations] = await executeSql(connection,
                'SELECT * FROM client_consultations WHERE user_id = ? AND is_finalized = TRUE ORDER BY created_at DESC LIMIT 1',
                [userId]
            );
            if (latestConsultations.length === 0) {
                await connection.rollback();
                return res.status(400).json({ error: 'Cannot create a follow-up consultation until the previous one is finalized by the client.' });
            }
            const latestConsultation = latestConsultations[0];

            // 3. Set all previous consultations for this user to is_latest = FALSE
            await executeSql(connection,
                'UPDATE client_consultations SET is_latest = FALSE WHERE user_id = ?',
                [userId]
            );

            // 4. Create the new consultation by copying data from the latest one
            const fieldsToCopy = [
                'user_id', 'gender', 'marital_status', 'height_cms', 'weight_kg', 'age_years',
                'shift_duty', 'joint_family', 'is_vegetarian', 'is_vegan', 'is_jain', 'has_lactose_intolerance',
                'date_of_payment', 'health_issues', 'food_liking', 'food_disliking', 'job_description', 'job_timings',
                'sedentary_status', 'travelling_frequency'
            ];
            const [newConsultationResult] = await executeSql(connection, `
                INSERT INTO client_consultations (is_latest, ${fieldsToCopy.join(', ')})
                SELECT TRUE, ${fieldsToCopy.join(', ')}
                FROM client_consultations
                WHERE client_consultation_id = ?`,
                [latestConsultation.client_consultation_id]
            );
            const newConsultationId = newConsultationResult.insertId;

            // 5. Copy the medical history from the latest consultation to the new one
            const [latestHistory] = await executeSql(connection,
                'SELECT * FROM client_medical_history WHERE client_consultation_id = ? ORDER BY created_at DESC LIMIT 1',
                [latestConsultation.client_consultation_id]
            );

            if (latestHistory.length > 0) {
                const [newHistoryResult] = await executeSql(connection, `
                    INSERT INTO client_medical_history (client_consultation_id, family_medical_history)
                    VALUES (?, ?)`,
                    [newConsultationId, latestHistory[0].family_medical_history]
                );
                const newHistoryId = newHistoryResult.insertId;

                // 6. Copy medications from the latest history to the new one
                const [medications] = await executeSql(connection,
                    'SELECT * FROM client_medications WHERE history_id = ?',
                    [latestHistory[0].history_id]
                );

                if (medications.length > 0) {
                    const medicationValues = medications.map(med =>
                        [newHistoryId, med.diagnosis, med.medicine_name, med.power, med.timing, med.since_when]
                    );
                    await connection.query(
                        'INSERT INTO client_medications (history_id, diagnosis, medicine_name, power, timing, since_when) VALUES ?',
                        [medicationValues]
                    );
                }
            }

            await connection.commit();
            res.json({ message: 'New follow-up consultation created successfully. Client forms have been re-opened.' });

        } catch (error) {
            if (connection) { await connection.rollback(); }
            writeLog('Error creating new consultation:', error);
            res.status(500).json({ error: 'Failed to create new consultation.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Admin: Search Clients
    router.get('/api/admin/clients/search', verifyAdminToken, async (req, res) => {
        writeLog(`[${new Date().toISOString()}] /api/admin/clients/search HIT with query:`, req.query);

        try {
            let baseQuery = `
                SELECT
                    u.user_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number,
                    u.created_at as registration_date,
                    u.is_email_verified,
                    u.is_active as is_account_active,
                    u.assigned_nutritionist_id as nutritionist_id,
                    CONCAT(nutri.first_name, ' ', nutri.last_name) as nutritionist_name,
                    cc.is_finalized,
                    cc.is_food_plan_complete,
                    (SELECT COUNT(*) > 0 FROM client_food_plans cfp WHERE cfp.client_consultation_id = cc.client_consultation_id) as has_food_plan_suggested,
                    u.assigned_executive_id as enrolled_by_executive_id,
                    CONCAT(exec.first_name, ' ', exec.last_name) as executive_name
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id AND ur.role_id = (SELECT role_id FROM roles WHERE role_name = 'client')
                LEFT JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
                LEFT JOIN users_v2 nutri ON u.assigned_nutritionist_id = nutri.user_id
                LEFT JOIN users_v2 exec ON u.assigned_executive_id = exec.user_id
            `;
            const conditions = [];
            const params = [];

            if (req.query.client_id) {
                conditions.push("u.user_id = ?");
                params.push(req.query.client_id);
            }
            if (req.query.first_name) {
                conditions.push("u.first_name LIKE ?");
                params.push(`%${req.query.first_name}%`);
            }
            if (req.query.last_name) {
                conditions.push("u.last_name LIKE ?");
                params.push(`%${req.query.last_name}%`);
            }
            if (req.query.email) {
                conditions.push("u.email LIKE ?");
                params.push(`%${req.query.email}%`);
            }

            if (conditions.length > 0) {
                baseQuery += " WHERE " + conditions.join(" AND ");
            }
            baseQuery += " ORDER BY u.created_at DESC";

            const [clients] = await executeSql(db, baseQuery, params);
            res.json(clients);
        } catch (error) {
            writeLog('Error searching clients for admin:', error);
            res.status(500).json({ error: 'Failed to search clients' });
        }
    });

    // --- Client Staff Selection API Routes ---
    // API to list active nutritionists for client selection
    router.post('/api/admin/general-food-recommendations', verifyAdminToken, async (req, res) => {
        const { recommendations_text } = req.body;
        const adminUserId = req.user.userId; // From verifyAdminToken

        writeLog(`[${new Date().toISOString()}] ADMIN /api/admin/general-food-recommendations HIT by admin_id: ${adminUserId}`);

        if (typeof recommendations_text === 'undefined') { // Allow empty string, but not missing field
            return res.status(400).json({ error: 'recommendations_text field is required.' });
        }

        try {
            // Simple approach: Delete existing and insert new, or update if one exists.
            // For simplicity, let's assume we update row with id=1, or insert if it doesn't exist.
            // A more robust way might be to always update the single row or create if not present.
            await executeSql(db,
                'INSERT INTO general_food_recommendations (id, recommendations_text, last_updated_by) VALUES (1, ?, ?) ON DUPLICATE KEY UPDATE recommendations_text = VALUES(recommendations_text), last_updated_by = VALUES(last_updated_by)',
                [recommendations_text, adminUserId]
            );
            res.json({ message: 'General food recommendations updated successfully.' });
        } catch (error) {
            writeLog('Error updating general food recommendations by admin:', error);
            res.status(500).json({ error: 'Failed to update general food recommendations.' });
        }
    });

    // API endpoint for client to save/update their medical history
    router.get('/api/admin/clients/:clientId/food-plan/latest', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        writeLog(`[${new Date().toISOString()}] ADMIN /api/admin/clients/${clientId}/food-plan/latest HIT`);

        try {
            // 1. Get the latest plan_id for the client
            const [latestPlanMeta] = await executeSql(db, `
                SELECT cfp.plan_id, cfp.additional_personal_recommendations, cfp.created_at, cfp.updated_at
                FROM client_food_plans cfp
                JOIN client_consultations cc ON cfp.client_consultation_id = cc.client_consultation_id
                WHERE cc.user_id = ? AND cc.is_latest = 1
                ORDER BY cfp.updated_at DESC
                LIMIT 1`,
                [clientId]
            );

            if (latestPlanMeta.length === 0) {
                return res.json({ message: 'No food plan found for this client.' });
            }

            const plan = latestPlanMeta[0];
            const planId = plan.plan_id;

            // 2. Get all hourly details for that plan_id
            const [hourlyDetails] = await executeSql(db,
                `SELECT *
             FROM client_food_plan_hourly_details
             WHERE plan_id = ?
             ORDER BY time_slot ASC`, // Ensure consistent order
                [planId]
            );

            res.json({
                ...plan,
                hourly_details: hourlyDetails
            });
        } catch (error) {
            writeLog(`Error fetching latest food plan for client ${clientId} by admin:`, error);
            res.status(500).json({ error: 'Failed to fetch latest food plan for client.' });
        }
    });

    // Admin: Save/Update food plan for a specific client
    router.post('/api/admin/clients/:clientId/food-plan', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        const adminUserId = req.user.userId; // Admin who is making the change
        const { hourly_plan } = req.body;

        // Sanitize the HTML content to prevent XSS attacks
        const sanitizedRecommendations = sanitizeHtml(req.body.additional_personal_recommendations || '', {
            allowedTags: [ 'p', 'b', 'i', 'em', 'strong', 'ul', 'ol', 'li', 'br', 'h1', 'h2', 'h3' ],
            allowedAttributes: {} // No attributes allowed
        });

        writeLog(`[${new Date().toISOString()}] ADMIN /api/admin/clients/${clientId}/food-plan POST HIT by admin_id: ${adminUserId}`);
        writeLog('Received food plan data from admin:', JSON.stringify(req.body, null, 2));

        if (!hourly_plan || typeof hourly_plan !== 'object') {
            return res.status(400).json({ error: 'Hourly plan data is missing or invalid.' });
        }

        const connection = await db.getConnection();

        try {
            await connection.beginTransaction();
            writeLog(`Admin food plan save for client ${clientId}: Transaction started.`);

            // Find the latest consultation for the client using the new user_id
            const [consultations] = await executeSql(connection,
                `SELECT client_consultation_id FROM client_consultations WHERE user_id = ? AND is_latest = TRUE`,
                [clientId]
            );

            if (consultations.length === 0) {
                throw new Error('No active consultation found for this client to save the food plan against.');
            }
            const consultationId = consultations[0].client_consultation_id;

            // Delete any existing food plan for this specific consultation to avoid duplicates.
            await executeSql(connection,
                `DELETE FROM client_food_plans WHERE client_consultation_id = ?`,
                [consultationId]
            );

            // Step 1: Insert the new food plan into client_food_plans
            const [planResult] = await executeSql(connection, `
                INSERT INTO client_food_plans (client_consultation_id, additional_personal_recommendations, created_by_admin_id)
                VALUES (?, ?, ?)`,
                [consultationId, sanitizedRecommendations || null, adminUserId]
            );
            const planId = planResult.insertId;
            writeLog(`Admin food plan save: Inserted into client_food_plans, planId: ${planId}`);

            // Step 2: Prepare and insert hourly details
            const hourlyDetailsToInsert = [];
            for (const timeSlot in hourly_plan) {
                if (hourly_plan.hasOwnProperty(timeSlot)) {
                    const slotData = hourly_plan[timeSlot];
                    if (slotData.present_intake || slotData.proposed_structure || slotData.additional_points) {
                        hourlyDetailsToInsert.push([
                            planId, timeSlot, slotData.present_intake || null,
                            slotData.proposed_structure || null, slotData.additional_points || null
                        ]);
                    }
                }
            }

            if (hourlyDetailsToInsert.length > 0) {
                await connection.query(
                    'INSERT INTO client_food_plan_hourly_details (plan_id, time_slot, present_intake, proposed_structure, additional_points) VALUES ?',
                    [hourlyDetailsToInsert]
                );
                writeLog(`Admin food plan save: Inserted ${hourlyDetailsToInsert.length} hourly details for planId: ${planId}`);
            }
            await connection.commit();
            writeLog(`Admin food plan save for client ${clientId}: Transaction committed successfully.`);
            res.json({ message: 'Client food plan updated successfully by admin.', planId: planId });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog(`Error saving food plan for client ${clientId} by admin (ROLLBACK EXECUTED):`, error);
            res.status(500).json({ error: 'Failed to save client food plan.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Admin: Get latest medical history for a specific client
    router.get('/api/admin/clients/:clientId/medical-history/latest', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        writeLog(`[${new Date().toISOString()}] ADMIN /api/admin/clients/${clientId}/medical-history/latest HIT`);

        try {
            const [latestHistoryMeta] = await executeSql(db, `
                SELECT cmh.history_id, cmh.family_medical_history, cc.is_finalized, cc.is_food_plan_complete, cmh.created_at, cmh.updated_at
                FROM client_medical_history cmh
                JOIN client_consultations cc ON cmh.client_consultation_id = cc.client_consultation_id
                WHERE cc.user_id = ? AND cc.is_latest = 1
                ORDER BY cmh.updated_at DESC
                LIMIT 1`,
                [clientId]
            );

            if (latestHistoryMeta.length === 0) {
                return res.json({ message: 'No medical history found for this client.' });
            }

            const history = latestHistoryMeta[0];
            const historyId = history.history_id;

            const [medications] = await executeSql(db,
                `SELECT medication_id, diagnosis, medicine_name, power, timing, since_when
             FROM client_medications
             WHERE history_id = ?`,
                [historyId]
            );
            res.json({ ...history, medications: medications });
        } catch (error) {
            writeLog(`Error fetching latest medical history for client ${clientId} by admin:`, error);
            res.status(500).json({ error: 'Failed to fetch latest medical history for client.' });
        }
    });

    // Admin: Get personal details for a specific client
    router.get('/api/admin/clients/:clientId/personal-details', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        writeLog(`[${new Date().toISOString()}] ADMIN /api/admin/clients/${clientId}/personal-details HIT`);
        try {
            const [clients] = await executeSql(db, `
                SELECT
                    u.user_id as client_id,
                    u.first_name, u.last_name, u.mobile_number, u.email,
                    u.address_1, u.address_2, u.address_3, u.city, u.pincode,
                    u.reference_source,
                    u.assigned_executive_id as enrolled_by_executive_id,
                    u.assigned_nutritionist_id as nutritionist_id,
                    u.created_at as registration_date,
                    u.is_email_verified,
                    u.is_active as is_account_active,
                    cc.height_cms, cc.weight_kg, cc.age_years, cc.gender, cc.marital_status,
                    cc.shift_duty, cc.joint_family, cc.is_vegetarian, cc.is_vegan, cc.is_jain,
                    cc.has_lactose_intolerance, cc.date_of_payment,
                    cc.health_issues, cc.food_liking, cc.food_disliking,
                    cc.job_description, cc.job_timings, cc.sedentary_status, cc.travelling_frequency
                FROM users_v2 u
                LEFT JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
                WHERE u.user_id = ?`,
                [clientId]
            );
            if (clients.length === 0) {
                return res.status(404).json({ error: 'Client not found' });
            }
            res.json(clients[0]);
        } catch (error) {
            writeLog(`Error fetching personal details for client ${clientId} by admin:`, error);
            res.status(500).json({ error: 'Failed to fetch client personal details.' });
        }
    });

    // Admin: Get latest blood test results for a specific client
    router.get('/api/admin/clients/:clientId/blood-tests/latest', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        writeLog(`[${new Date().toISOString()}] ADMIN /api/admin/clients/${clientId}/blood-tests/latest HIT`);

        try {
            // 1. Get the latest report_id for the client
            const [latestReportMeta] = await executeSql(db, `
                SELECT cbtr.report_id, cbtr.report_date, cbtr.created_at
                FROM client_blood_test_reports cbtr
                JOIN client_consultations cc ON cbtr.client_consultation_id = cc.client_consultation_id
                WHERE cc.user_id = ? AND cc.is_latest = 1
                ORDER BY cbtr.created_at DESC
                LIMIT 1`,
                [clientId]
            );

            if (latestReportMeta.length === 0) {
                return res.json({ message: 'No blood test reports found for this client.' });
            }

            const report = latestReportMeta[0];
            const reportId = report.report_id;

            // 2. Get all results for that report_id
            const [results] = await executeSql(db,
                `SELECT test_code, value
             FROM client_blood_test_results
             WHERE report_id = ?`,
                [reportId]
            );
            res.json({ ...report, results: results });
        } catch (error) {
            writeLog(`Error fetching latest blood tests for client ${clientId} by admin:`, error);
            res.status(500).json({ error: 'Failed to fetch latest blood tests for client.' });
        }
    });

    // Admin: Unfinalize/Re-open client's latest medical history
    router.patch('/api/admin/clients/:clientId/medical-history/unfinalize', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        const adminUserId = req.user.userId; // Admin performing the action

        writeLog(`[${new Date().toISOString()}] ADMIN ${adminUserId} /api/admin/clients/${clientId}/medical-history/unfinalize HIT`);

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            const [submissionResult] = await executeSql(connection, `
                UPDATE client_consultations SET is_finalized = FALSE WHERE user_id = ? AND is_latest = TRUE`,
                [clientId]
            );
            writeLog('Final Submission set to FALSE for client ', clientId);

            await connection.commit();
            res.json({ message: `Client ${clientId}'s forms (Personal Details, Blood Tests, Food Plan, Medical History) have been re-opened for edits.` });

        } catch (error) {
            if (connection) await connection.rollback();
            writeLog(`Error unfinalizing medical history for client ${clientId} by admin ${adminUserId}:`, error);
            res.status(500).json({ error: 'Failed to re-open medical history.' });
        } finally {
            if (connection) connection.release();
        }
    });

    router.patch('/api/admin/clients/:clientId/food-plan/complete', verifyAdminToken, async (req, res) => {
        const { clientId } = req.params;
        const adminUserId = req.user.userId; // Admin performing the action

        writeLog(`[${new Date().toISOString()}] ADMIN ${adminUserId} /api/admin/clients/${clientId}/food-plan/complete HIT`);

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            await executeSql(connection, `
                    UPDATE client_consultations SET is_food_plan_complete = TRUE WHERE user_id = ? AND is_latest = TRUE`,
                [clientId]
            );
            writeLog('Food plan marked as complete for client ', clientId);

            const [users] = await executeSql(db, `SELECT email, first_name FROM users_v2 WHERE user_id = ?`,
                [clientId]);
            if (users.length > 0) {
                const client = users[0];
                const mailOptions = {
                    from: `"Consultation Service" <${EMAIL_USER}>`,
                    to: client.email,
                    subject: 'Your Food Plan is Ready!',
                    html: `
                        <p>Dear ${client.first_name},</p>
                        <p>Great news! Your personalized food plan has been prepared and is now available for you to view.</p>
                        <p>You can log in to your account to access it.</p>
                        <p>If you have any questions, please feel free to contact us.</p>
                        <p>Sincerely,<br>The Consultation Service Team</p>
                    `,
                };
                if (EMAIL_USER !== '') {
                    try {
                        await transporter.sendMail(mailOptions);
                        writeLog(`Sent food plan completion email to ${client.email}`);
                    } catch (emailError) {
                        writeLog('Error sending food plan completion email:', emailError);
                        // Don't fail the whole request, but log the error
                    }
                } else {
                    writeLog(`Could not send food plan completion email to ${client.email} due to missing email setup.`);
                }
            }

            await connection.commit();
            res.json({ message: `Client ${clientId}'s food plan has been marked as complete.` });

        } catch (error) {
            if (connection) await connection.rollback();
            writeLog(`Error completing food plan for client ${clientId} by admin ${adminUserId}:`, error);
            res.status(500).json({ error: 'Failed to complete food plan.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // Get statistics counts
    router.get('/api/admin/stats/counts', verifyAdminToken, async (req, res) => {
        try {
            const [results] = await executeSql(db, `
                SELECT
                    (SELECT COUNT(DISTINCT u.user_id) FROM users_v2 u JOIN user_roles ur ON u.user_id = ur.user_id JOIN roles r ON ur.role_id = r.role_id WHERE r.role_name = 'nutritionist' AND u.is_active = TRUE) as nutritionist_count,
                    (SELECT COUNT(DISTINCT u.user_id) FROM users_v2 u JOIN user_roles ur ON u.user_id = ur.user_id JOIN roles r ON ur.role_id = r.role_id WHERE r.role_name = 'executive' AND u.is_active = TRUE) as executive_count,
                    (SELECT COUNT(DISTINCT u.user_id) FROM users_v2 u JOIN user_roles ur ON u.user_id = ur.user_id JOIN roles r ON ur.role_id = r.role_id WHERE r.role_name = 'client' AND u.is_active = TRUE) as client_count,
                    (SELECT COUNT(DISTINCT u.user_id) FROM users_v2 u JOIN user_roles ur ON u.user_id = ur.user_id JOIN roles r ON ur.role_id = r.role_id WHERE r.role_name = 'client' AND u.is_active = FALSE) as pending_activation_count,
                    (SELECT COUNT(*) FROM client_consultations WHERE is_latest = 1 AND is_finalized = 1) as final_history_submitted_count,
                    (SELECT COUNT(DISTINCT cfp.client_consultation_id) FROM client_food_plans cfp JOIN client_consultations cc ON cfp.client_consultation_id = cc.client_consultation_id WHERE cc.is_latest = 1) as food_plan_completed_count,
                    (SELECT COUNT(*) FROM client_consultations WHERE is_latest = 1 AND is_food_plan_complete = 1) as food_plan_sent_count;
            `);

            const counts = results[0];
            res.json(counts);

        } catch (error) {
            writeLog('Error fetching statistics counts:', error);
            res.status(500).json({ error: 'Failed to fetch statistics' });
        }
    });

    // Admin: Get current admin's details for welcome message
    router.get('/api/admin/me', verifyAdminToken, async (req, res) => {
        const adminId = req.user.userId;
        try {
            const [admins] = await executeSql(db, `
                SELECT first_name, last_name FROM users_v2 WHERE user_id = ?
            `, [adminId]);

            if (admins.length === 0) {
                return res.status(404).json({ error: 'Admin user not found in database.' });
            }
            res.json(admins[0]);
        } catch (error) {
            writeLog(`Error fetching details for admin ${adminId}:`, error);
            res.status(500).json({ error: 'Failed to fetch admin details.' });
        }
    });

    // Nutritionist: Get current nutritionist's details for welcome message
    router.get('/api/nutritionist/me', verifyNutritionistToken, async (req, res) => {
        const nutritionistId = req.user.userId;
        try {
            const [nutritionists] = await executeSql(db, `
                SELECT first_name, last_name FROM users_v2 WHERE user_id = ?
            `, [nutritionistId]);

            if (nutritionists.length === 0) {
                return res.status(404).json({ error: 'Nutritionist user not found in database.' });
            }
            res.json(nutritionists[0]);
        } catch (error) {
            writeLog(`Error fetching details for nutritionist ${nutritionistId}:`, error);
            res.status(500).json({ error: 'Failed to fetch nutritionist details.' });
        }
    });
    router.get('/api/nutritionist/stats/counts', verifyNutritionistToken, async (req, res) => {
        const nutritionistId = req.user.userId;
        try {
            const [results] = await executeSql(db, `
                SELECT
                    (SELECT COUNT(user_id) FROM users_v2 WHERE assigned_nutritionist_id = ? AND is_active = TRUE) as total_assigned_clients_count,
                    (SELECT COUNT(cc.client_consultation_id) FROM client_consultations cc JOIN users_v2 u ON cc.user_id = u.user_id WHERE u.assigned_nutritionist_id = ? AND cc.is_latest = 1 AND cc.is_finalized = 1) as final_history_submitted_count,
                    (SELECT COUNT(DISTINCT cc.client_consultation_id) FROM client_food_plans cfp JOIN client_consultations cc ON cfp.client_consultation_id = cc.client_consultation_id JOIN users_v2 u ON cc.user_id = u.user_id WHERE u.assigned_nutritionist_id = ? AND cc.is_latest = 1) as food_plan_suggested_count,
                    (SELECT COUNT(cc.client_consultation_id) FROM client_consultations cc JOIN users_v2 u ON cc.user_id = u.user_id WHERE u.assigned_nutritionist_id = ? AND cc.is_latest = 1 AND cc.is_food_plan_complete = 1) as food_plan_sent_count;
            `, [nutritionistId, nutritionistId, nutritionistId, nutritionistId]);

            const counts = results[0];
            res.json(counts);

        } catch (error) {
            writeLog(`Error fetching statistics for nutritionist ${nutritionistId}:`, error);
            res.status(500).json({ error: 'Failed to fetch nutritionist statistics' });
        }
    });

    // Nutritionist: Get all assigned clients
    router.get('/api/nutritionist/my-clients', verifyNutritionistToken, async (req, res) => {
        const nutritionistId = req.user.userId;
        try {
            const [clients] = await executeSql(db, `
                SELECT
                    u.user_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number,
                    u.created_at as registration_date,
                    cc.is_finalized,
                    (SELECT COUNT(*) > 0 FROM client_food_plans cfp WHERE cfp.client_consultation_id = cc.client_consultation_id) as has_food_plan_suggested,
                    cc.is_food_plan_complete
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id AND ur.role_id = (SELECT role_id FROM roles WHERE role_name = 'client')
                LEFT JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
                WHERE u.assigned_nutritionist_id = ?
                ORDER BY u.user_id ASC
            `, [nutritionistId]);
            res.json(clients);
        } catch (error) {
            writeLog(`Error fetching clients for nutritionist ${nutritionistId}:`, error);
            res.status(500).json({ error: 'Failed to fetch assigned clients' });
        }
    });

    // Nutritionist: Search assigned clients
    router.get('/api/nutritionist/my-clients/search', verifyNutritionistToken, async (req, res) => {
        const nutritionistId = req.user.userId;
        try {
            let baseQuery = `
                SELECT
                    u.user_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number,
                    u.created_at as registration_date,
                    cc.is_finalized,
                    (SELECT COUNT(*) > 0 FROM client_food_plans cfp WHERE cfp.client_consultation_id = cc.client_consultation_id) as has_food_plan_suggested,
                    cc.is_food_plan_complete
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id AND ur.role_id = (SELECT role_id FROM roles WHERE role_name = 'client')
                LEFT JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
            `;
            const conditions = ["u.assigned_nutritionist_id = ?"];
            const params = [nutritionistId];

            if (req.query.client_id) { conditions.push("u.user_id = ?"); params.push(req.query.client_id); }
            if (req.query.first_name) { conditions.push("u.first_name LIKE ?"); params.push(`%${req.query.first_name}%`); }
            if (req.query.last_name) { conditions.push("u.last_name LIKE ?"); params.push(`%${req.query.last_name}%`); }
            if (req.query.email) { conditions.push("u.email LIKE ?"); params.push(`%${req.query.email}%`); }

            baseQuery += " WHERE " + conditions.join(" AND ");
            baseQuery += " ORDER BY u.created_at DESC";

            const [clients] = await executeSql(db, baseQuery, params);
            res.json(clients);
        } catch (error) {
            writeLog(`Error searching clients for nutritionist ${nutritionistId}:`, error);
            res.status(500).json({ error: 'Failed to search assigned clients' });
        }
    });

    router.get('/api/executive/stats/counts', verifyExecutiveToken, async (req, res) => {
        const executiveId = req.user.userId;
        try {
            const [results] = await executeSql(db, `
                SELECT
                    (SELECT COUNT(user_id) FROM users_v2 WHERE assigned_executive_id = ? AND is_active = TRUE) as total_enrolled_clients_count,
                    (SELECT COUNT(user_id) FROM users_v2 WHERE assigned_executive_id = ? AND is_active = FALSE) as clients_pending_activation_count,
                    (SELECT COUNT(cc.client_consultation_id) FROM client_consultations cc JOIN users_v2 u ON cc.user_id = u.user_id WHERE u.assigned_executive_id = ? AND cc.is_latest = 1 AND cc.is_finalized = 1) as final_history_submitted_count,
                    (SELECT COUNT(DISTINCT cc.client_consultation_id) FROM client_food_plans cfp JOIN client_consultations cc ON cfp.client_consultation_id = cc.client_consultation_id JOIN users_v2 u ON cc.user_id = u.user_id WHERE u.assigned_executive_id = ? AND cc.is_latest = 1) as food_plan_suggested_count,
                    (SELECT COUNT(cc.client_consultation_id) FROM client_consultations cc JOIN users_v2 u ON cc.user_id = u.user_id WHERE u.assigned_executive_id = ? AND cc.is_latest = 1 AND cc.is_food_plan_complete = 1) as food_plan_sent_count;
            `, [executiveId, executiveId, executiveId, executiveId, executiveId]);

            const counts = results[0];
            res.json(counts);

        } catch (error) {
            writeLog(`Error fetching statistics for executive ${executiveId}:`, error);
            res.status(500).json({ error: 'Failed to fetch executive statistics' });
        }
    });

    // Executive: Get all enrolled clients
    router.get('/api/executive/my-clients', verifyExecutiveToken, async (req, res) => {
        const executiveId = req.user.userId;
        try {
            const [clients] = await executeSql(db, `
                SELECT
                    u.user_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number,
                    u.created_at as registration_date,
                    u.is_active as is_account_active,
                    cc.is_finalized,
                    (SELECT COUNT(*) > 0 FROM client_food_plans cfp WHERE cfp.client_consultation_id = cc.client_consultation_id) as has_food_plan_suggested,
                    cc.is_food_plan_complete
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id AND ur.role_id = (SELECT role_id FROM roles WHERE role_name = 'client')
                LEFT JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
                WHERE u.assigned_executive_id = ?
                ORDER BY u.user_id ASC
            `, [executiveId]);
            res.json(clients);
        } catch (error) {
            writeLog(`Error fetching clients for executive ${executiveId}:`, error);
            res.status(500).json({ error: 'Failed to fetch enrolled clients' });
        }
    });

    // Executive: Search enrolled clients
    router.get('/api/executive/my-clients/search', verifyExecutiveToken, async (req, res) => {
        const executiveId = req.user.userId;
        try {
            let baseQuery = `
                SELECT
                    u.user_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number,
                    u.created_at as registration_date,
                    u.is_active as is_account_active,
                    cc.is_finalized,
                    (SELECT COUNT(*) > 0 FROM client_food_plans cfp WHERE cfp.client_consultation_id = cc.client_consultation_id) as has_food_plan_suggested,
                    cc.is_food_plan_complete
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id AND ur.role_id = (SELECT role_id FROM roles WHERE role_name = 'client')
                LEFT JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
            `;
            const conditions = ["u.assigned_executive_id = ?"];
            const params = [executiveId];

            if (req.query.client_id) { conditions.push("u.user_id = ?"); params.push(req.query.client_id); }
            if (req.query.first_name) { conditions.push("u.first_name LIKE ?"); params.push(`%${req.query.first_name}%`); }
            if (req.query.last_name) { conditions.push("u.last_name LIKE ?"); params.push(`%${req.query.last_name}%`); }
            if (req.query.email) { conditions.push("u.email LIKE ?"); params.push(`%${req.query.email}%`); }

            baseQuery += " WHERE " + conditions.join(" AND ");
            baseQuery += " ORDER BY u.created_at DESC";

            const [clients] = await executeSql(db, baseQuery, params);
            res.json(clients);
        } catch (error) {
            writeLog(`Error searching clients for executive ${executiveId}:`, error);
            res.status(500).json({ error: 'Failed to search enrolled clients' });
        }
    });

    // Executive: Get current executive's details for welcome message
    router.get('/api/executive/me', verifyExecutiveToken, async (req, res) => {
        const executiveId = req.user.userId;
        try {
            const [executives] = await executeSql(db, `
                SELECT first_name, last_name FROM users_v2 WHERE user_id = ?
            `, [executiveId]);

            if (executives.length === 0) {
                return res.status(404).json({ error: 'Executive user not found in database.' });
            }
            res.json(executives[0]);
        } catch (error) {
            writeLog(`Error fetching details for executive ${executiveId}:`, error);
            res.status(500).json({ error: 'Failed to fetch executive details.' });
        }
    });
}
