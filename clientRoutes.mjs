import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { writeLog } from './common/utils.mjs';
import sanitizeHtml from 'sanitize-html';
import { checkPasswordPolicy } from './common/utils.mjs';
import { executeSql } from './common/database.mjs';
import { isStaffAuthorizedForClient } from './staffRoutes.mjs';

export function setupClientRoutes({ router, db, JWT_SECRET, EMAIL_USER, transporter, appUrl }) {
    router.post('/api/client/update-staff-preference', async (req, res) => {
        // IMPORTANT: In a real app, get client_id from a verified client JWT
        const { client_id, nutritionist_id, executive_id } = req.body;

        if (!client_id) {
            return res.status(400).json({ error: 'Client ID is required.' });
        }

        // Use null as default if no selection is made or if '0' or empty string is passed
        const finalNutritionistId = (nutritionist_id && nutritionist_id !== "0" && nutritionist_id !== "") ? nutritionist_id : null;
        const finalExecutiveId = (executive_id && executive_id !== "0" && executive_id !== "") ? executive_id : null;

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Update new table
            const [result] = await executeSql(connection,
                `UPDATE users_v2 SET assigned_nutritionist_id = ?, assigned_executive_id = ?
                 WHERE user_id = (SELECT new_user_id FROM client_id_to_user_id_mapping WHERE old_client_id = ?)`,
                [finalNutritionistId, finalExecutiveId, client_id]
            );

            if (result.affectedRows === 0) {
                await connection.rollback();
                return res.status(404).json({ error: 'Client not found or no update made.' });
            }
            await connection.commit();
            res.json({ message: 'Staff preferences updated successfully.' });

        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error updating client staff preferences:', error);
            res.status(500).json({ error: 'Failed to update staff preferences.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // 1. Client Registration
    router.post('/register', async (req, res) => {
        const connection = await db.getConnection();
        const { first_name, last_name, mobile_number, email, password } = req.body;

        // Input Validation
        if (!first_name || !last_name || !mobile_number || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Basic email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }
        const passwordPolicyResult = checkPasswordPolicy(password);
        if (!passwordPolicyResult.isValid) {
            return res.status(400).json({ error: passwordPolicyResult.message });
        }

        const generateOTP = () => {
            return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
        };
        const otp = generateOTP();

        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + 10); // OTP expires in 10 minutes

        try {
            await connection.beginTransaction();

            // Check if email or mobile number already exists
            const [existingV2Users] = await executeSql(connection,
                'SELECT user_id FROM users_v2 WHERE email = ? OR mobile_number = ?',
                [email, mobile_number]
            );

            if (existingV2Users.length > 0) {
                await connection.rollback();
                return res.status(409).json({ error: 'Email or mobile number already registered.' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            // Insert new user with OTP details
            const [newUserResult] = await executeSql(connection,
                'INSERT INTO users_v2 (first_name, last_name, email, password_hash, mobile_number, email_otp, email_otp_expires_at, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [first_name, last_name, email, hashedPassword, mobile_number, otp, otpExpiry, 0]
            );
            const newUserId = newUserResult.insertId;

            // Link user to 'client' role
            const [clientRole] = await executeSql(connection, "SELECT role_id FROM roles WHERE role_name = 'client'");
            if (clientRole.length === 0) throw new Error("Critical: 'client' role not found in roles table.");
            await executeSql(connection, 'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [newUserId, clientRole[0].role_id]);

            // Create a corresponding entry in the client_consultations table
            await executeSql(connection, 'INSERT INTO client_consultations (user_id) VALUES (?)', [newUserId]);

            await connection.commit();

            // *** Send Email ***
            const mailOptions = {
                from: `"Consultation Service" <${EMAIL_USER}>`,
                to: email,
                subject: 'Welcome to Consultation Service - Verify Your Email & Next Steps',
                html: `
                    <p>Dear ${first_name},</p>
                    <p>Thank you for registering with our Consultation Service!</p>
                    <p>Your One-Time Password (OTP) for email verification is: <b>${otp}</b></p>
                    <p>This OTP will expire in 10 minutes. Please use it to verify your email address promptly.</p>
                    
                    <h2>Next Steps:</h2>
                    <ol>
                        <li><strong>Verify Your Email:</strong> Use the OTP above on our verification page (you'll be directed there or can find a link on our site).</li>
                        <li><strong>Payment of Fees:</strong> To activate your account and access our full services, a one-time fee is required.
                            <ul>
                                <li>Fee Amount: [Specify Fee Amount Here, e.g., $50 USD]</li>
                                <li>Payment Methods: We accept [Specify Methods, e.g., Credit Card, PayPal, Bank Transfer].</li>
                                <li>Bank Account Details (for Bank Transfer):
                                    <ul>
                                        <li>Bank Name: [Your Bank Name]</li>
                                        <li>Account Name: [Your Account Name]</li>
                                        <li>Account Number: [Your Account Number]</li>
                                        <li>SWIFT/BIC Code: [Your SWIFT Code]</li>
                                        <li>Reference: Please use your Client ID (which will be provided upon successful registration) or your email address as the payment reference.</li>
                                    </ul>
                                </li>
                                <li>Once payment is made, please allow up to [e.g., 24-48 hours] for verification and account activation. You will receive another email once your account is active.</li>
                            </ul>
                        </li>
                        <li><strong>Login:</strong> After your account is activated, you can log in using your email and the password you registered with. Initially, your access might be to specific sections until full activation.</li>
                    </ol>
                    <p>Your password is currently set but your account will require activation after payment to gain full access.</p>
                    <p>If you have any questions, please don't hesitate to contact our support team.</p>
                    <p>Sincerely,<br>The Consultation Service Team</p>
                `,
            };
            try {
                if (EMAIL_USER !== '' && transporter) {
                    await transporter.sendMail(mailOptions);
                    writeLog(`Sent verification email to ${email}`);
                } else {
                    if (EMAIL_USER === '') {
                        writeLog(`

 -----> Generated OTP: ${otp}

`);
                    } else {
                        throw 'Email Transporter is not Configured';
                    }
                }
            } catch (emailError) {
                writeLog('Error sending email:', emailError);
                // Handle email sending failure gracefully.  You might want to log this or retry.
                // For now, we'll just proceed with registration but inform the client.
                return res.status(500).json({
                    message: 'Client registered, but email sending failed. Please try again later.',
                    client_id: newUserId,
                });
            }

            // If the email sends successfully, proceed with the registration success message:
            res.status(201).json({ message: 'Client registered successfully', client_id: newUserId });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Registration error:', error);
            res.status(500).json({ error: 'Registration failed' }); // Improved error message
        } finally {
            if (connection) connection.release();
        }
    });

    // 2. Email OTP Verification
    router.post('/verify-email', async (req, res) => {
        const connection = await db.getConnection();
        const { email, otp } = req.body;

        // Input Validation for verify-email
        if (!email || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required' });
        }

        try {
            await connection.beginTransaction();

            // Find the user in the new users_v2 table
            const [users] = await executeSql(connection,
                'SELECT user_id, first_name, last_name FROM users_v2 WHERE email = ? AND email_otp = ? AND email_otp_expires_at > NOW()',
                [email, otp]
            );

            if (users.length === 0) {
                await connection.rollback();
                return res.status(400).json({ error: 'Invalid or expired OTP' });
            }

            const user = users[0];

            // Update is_email_verified and clear OTP fields in the new table
            await executeSql(connection,
                'UPDATE users_v2 SET is_email_verified = TRUE, email_otp = NULL, email_otp_expires_at = NULL WHERE user_id = ?',
                [user.user_id]
            );

            await connection.commit();

            // send email to admin that this user was registered
            const adminMailOptions = {
                from: `"Consultation Service" <${EMAIL_USER}>`,
                to: EMAIL_USER, // Send to the admin's email (your EMAIL_USER)
                subject: 'New Client Email Verified',
                html: `
                    <p>Dear Admin,</p>
                    <p>A new client has successfully verified their email address:</p>
                    <ul>
                        <li><strong>Client ID:</strong> ${user.user_id}</li>
                        <li><strong>Email:</strong> ${email}</li>
                        <li><strong>Name:</strong> ${user.first_name} ${user.last_name}</li>
                    </ul>
                    <p>Please review their account and proceed with activation if all conditions are met.</p>
                    <p>Sincerely,<br>The System Notification Service</p>
                `,
            };
            try {
                if (EMAIL_USER !== '' && transporter) {
                    await transporter.sendMail(adminMailOptions);
                    writeLog(`Sent admin notification email for verified client ${email}`);
                } else {
                    writeLog(`Admin notification email not sent for ${email} due to missing email setup.`);
                }
            } catch (adminEmailError) {
                writeLog('Error sending admin notification email:', adminEmailError);
                // Continue processing, as this is an admin notification, not critical for client
            }

            res.json({ message: 'Email verified successfully' });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Email verification error:', error);
            res.status(500).json({ error: 'Email verification failed' });
        } finally {
            if (connection) connection.release();
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
                    } else {
                        writeLog(`[OTP Login] Attempt for non-client or inactive/unverified user: ${email}`);
                    }
                } else {
                    writeLog(`[OTP Login] Attempt for non-existent email: ${email}`);
                }
            } catch (error) {
                writeLog('Error sending login OTP:', error);
            }
        }
        // Always send a generic success message to prevent email enumeration.
        res.json({ message: 'If an account with that email exists and is active, an OTP has been sent.' });
    });

    // Middleware to verify Client JWT
    const verifyClientToken = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7, authHeader.length);
            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (err) {
                    writeLog('[verifyClientToken] JWT verification error:', err.name, err.message);
                    return res.status(403).json({ error: `Forbidden: Token verification failed (${err.name})` });
                }
                let userRoles = [];
                if (decoded.roles && Array.isArray(decoded.roles)) {
                    userRoles = decoded.roles;
                } else if (typeof decoded.role === 'string') {
                    userRoles = [decoded.role];
                }
                // Ensure it's a client token, e.g., by checking for clientId
                if ((!decoded || !decoded.clientId) && userRoles.length === 0) {
                    writeLog('[verifyClientToken] Verification failed. Decoded payload:', decoded, 'clientId missing.');
                    return res.status(403).json({ error: 'Forbidden: Invalid client token' });
                }
                if (!decoded.clientId && userRoles.length === 0) {
                    return res.status(403).json({ error: 'Forbidden: No roles found in token' });
                }
                req.client = decoded; // Add client info to request object
                req.userRoles = userRoles; // Add roles to request object
                next();
            });
        } else {
            writeLog('[verifyClientToken] Unauthorized: Missing client token in headers.');
            res.status(401).json({ error: 'Unauthorized: Missing client token' });
        }
    };

    // API endpoint for client to get their own details
    router.get('/api/client/me', verifyClientToken, async (req, res) => {
        try {
            const [users] = await executeSql(db,
                'SELECT user_id as client_id, first_name, last_name, email FROM users_v2 WHERE user_id = ?',
                [req.client.clientId]
            );
            if (users.length === 0) {
                return res.status(404).json({ error: 'Client not found' });
            }
            res.json(users[0]);
        } catch (error) {
            writeLog('Error fetching client details for /api/client/me:', error);
            res.status(500).json({ error: 'Failed to fetch client details' });
        }
    });

    const childTables = {
        'client_blood_test_reports': 'client_blood_test_results/report_id/result_id/test_code=value',
        'client_medical_history': 'client_medications/history_id/medication_id/_index',
        'client_food_plans': 'client_food_plan_hourly_details/plan_id/detail_id/time_slot=present_intake,proposed_structure,additional_points'
    }

    router.get('/api/client/compare/:clientId', verifyClientToken, async (req, res) => {
        let { clientId } = req.params;
        const staffId = req.user?.userId || req.client?.userId;
        if (clientId === 'me') {
            clientId = req.client.clientId;
        } else if (req.userRoles.includes('admin')) {
            // allowed
        } else if (!await isStaffAuthorizedForClient(db, staffId, req.userRoles, clientId)) {
            res.status(403).json({ error: 'Forbidden: You are not authorized to view other client\'s data.' });
            return;
        }
        writeLog(`[${new Date().toISOString()}] /api/client/compare/${clientId} HIT`);
        try {
            const [consultations] = await executeSql(db,
                `SELECT * FROM client_consultations WHERE user_id = ? ORDER BY created_at`,
                [clientId]
            );
            let fieldSet = new Set();
            for (let consultation of consultations) {
                for (let [table, subTable] of Object.entries(childTables)) {
                    const [children] = await executeSql(db,
                        // Fetch the most RECENT record for the consultation to ensure
                        // the latest data (e.g., from an admin update) is shown.
                        `SELECT * FROM ${table} WHERE client_consultation_id = ? ORDER BY created_at DESC LIMIT 1`,
                        [consultation.client_consultation_id]
                    );
                    let [name, key, subKey, matchFields] = subTable.split('/');
                    let [f, v] = matchFields.split('=');
                    matchFields = f.split(',');
                    for (let child of children) {
                        let fk = child[key];
                        delete child[key];
                        if (fk) {
                            const [grandChildren] = await executeSql(db,
                                `SELECT * FROM ${name} WHERE ${key} = ?`,
                                [fk]
                            );
                            let flattened = {};
                            let index = 1;
                            for (let grandChild of grandChildren) {
                                let matchValues = [];
                                for (let field of matchFields) {
                                    if (field === '_index') {
                                        matchValues.push(index);
                                    } else {
                                        matchValues.push(grandChild[field]);
                                    }
                                }
                                if (v) {
                                    for (let field of v.split(',')) {
                                        flattened[name.replace('client_', '') + '_' + field + '_' + matchValues.join(', ')] = grandChild[field];
                                    }
                                } else {
                                    flattened[name.replace('client_', '') + '_' + matchValues.join(', ')] = Object.entries(grandChild).filter(([k, v]) => k !== key && k !== subKey).map(([k, v]) => `${v}`).join(', ');
                                }
                                delete grandChild[key];
                                delete grandChild[subKey];
                                index++;
                            }
                            Object.assign(child, flattened);
                        } else {
                            child[name] = [];
                        }
                        delete child['client_consultation_id'];
                    }
                    if (children.length > 0) {
                        // When processing blood test reports, rename 'report_date' to match what the frontend expects.
                        // This ensures the correct date is used for the column header in the comparison view.
                        if (table === 'client_blood_test_reports' && children[0].report_date) {
                            children[0].blood_test_results_report_date = children[0].report_date;
                            delete children[0].report_date;
                        }
                        Object.assign(consultation, children[0]);
                        for (let name of Object.keys(children[0])) {
                            fieldSet.add(name);
                        }
                    }
                }
            }
            for (let consultation of consultations) {
                for (let field of fieldSet) {
                    if (!field in consultation) {
                        consultation[field] = '';
                    }
                }
                for (let field of Object.keys(consultation)) {
                    if (consultation[field] === null || typeof consultation[field] === 'undefined') {
                        consultation[field] = '';
                    } else if (consultation[field] instanceof Date) {
                        consultation[field] = JSON.stringify(consultation[field]);
                    } else {
                        consultation[field] = `${consultation[field]}`;
                    }
                }
            }
            res.json(consultations);
        } catch (error) {
            writeLog('Error fetching client consultations for admin:', error);
            res.status(500).json({ error: 'Failed to fetch client consultations' });
        }
    });

    // API endpoint for client to save/update their personal details
    router.post('/api/client/personal-details', verifyClientToken, async (req, res) => {
        writeLog(`[${new Date().toISOString()}] HIT: POST /api/client/personal-details`); // <-- ADD THIS LINE
        const clientId = req.client.clientId; // Get clientId from verified token
        const {
            first_name, last_name, mobile_number, email, // Core details, might also be updatable here
            height_cms, weight_kg, age_years, gender, marital_status, address_1, address_2, address_3, city, pincode, shift_duty, joint_family, is_vegetarian,  is_vegan, is_jain, has_lactose_intolerance, date_of_payment: raw_date_of_payment, reference_source,
            // health_executive_id, // This is enrolled_by_executive_id, handle separately if needed or via admin
            health_issues, food_liking, food_disliking, job_description, job_timings, sedentary_status, travelling_frequency
        } = req.body;

        // Basic validation (you can add more specific validation as needed)
        if (!first_name || !last_name || !email || !mobile_number) {
            return res.status(400).json({ error: 'Basic contact information (name, email, mobile) is required.' });
        }

        // Handle date_of_payment: convert empty string to null
        const date_of_payment = (raw_date_of_payment === '' || raw_date_of_payment === undefined) ? null : raw_date_of_payment;

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Check if the new email (if changed) already exists for another user
            const [existingUsers] = await executeSql(connection,
                'SELECT user_id FROM users_v2 WHERE email = ? AND user_id <> ?',
                [email.trim(), clientId]
            );
            if (existingUsers.length > 0) {
                await connection.rollback();
                return res.status(409).json({ error: 'Email already registered for another user.' });
            }

            // 1. Update the new users_v2 table
            await executeSql(connection, `
                UPDATE users_v2 SET
                    first_name = ?, last_name = ?, mobile_number = ?, email = ?,
                    address_1 = ?, address_2 = ?, address_3 = ?, city = ?, pincode = ?,
                    reference_source = ?, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?`,
                [
                    first_name, last_name, mobile_number, email,
                    address_1, address_2, address_3, city, pincode,
                    reference_source, clientId
                ]
            );

            // 3. Update the latest client_consultations record
            const [result] = await executeSql(connection, `
                UPDATE client_consultations SET
                    height_cms = ?, weight_kg = ?, age_years = ?, gender = ?, marital_status = ?,
                    shift_duty = ?, joint_family = ?, is_vegetarian = ?, is_vegan = ?, is_jain = ?,
                    has_lactose_intolerance = ?, date_of_payment = ?,
                    health_issues = ?, food_liking = ?, food_disliking = ?,
                    job_description = ?, job_timings = ?, sedentary_status = ?, travelling_frequency = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ? AND is_latest = TRUE`,
                [
                    height_cms, weight_kg, age_years, gender, marital_status,
                    shift_duty, joint_family, is_vegetarian, is_vegan, is_jain,
                    has_lactose_intolerance, date_of_payment,
                    health_issues, food_liking, food_disliking,
                    job_description, job_timings, sedentary_status, travelling_frequency,
                    clientId
                ]
            );

            if (result.affectedRows === 0) {
                writeLog(`Warning: Client ${clientId} updated personal details, but no 'latest' consultation record was found to update.`);
            }

            await connection.commit();
            res.json({ message: 'Personal details updated successfully.' });

        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error updating client personal details:', error);
            res.status(500).json({ error: 'Failed to update personal details.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // API endpoint for client to GET their own full personal details
    router.get('/api/client/me/personal-details', verifyClientToken, async (req, res) => {
        const clientId = req.client.clientId;
        try {
            const [clients] = await executeSql(db, `
                SELECT
                    u.first_name, u.last_name, u.mobile_number, u.email,
                    u.address_1, u.address_2, u.address_3, u.city, u.pincode,
                    u.reference_source,
                    u.assigned_executive_id as enrolled_by_executive_id,
                    u.assigned_nutritionist_id as nutritionist_id,
                    CONCAT(exec.first_name, ' ', exec.last_name) as executive_name,
                    cc.height_cms, cc.weight_kg, cc.age_years, cc.gender, cc.marital_status,
                    cc.shift_duty, cc.joint_family, cc.is_vegetarian,  cc.is_vegan, cc.is_jain,
                    cc.has_lactose_intolerance, cc.date_of_payment,
                    cc.health_issues, cc.food_liking, cc.food_disliking,
                    cc.job_description, cc.job_timings, cc.sedentary_status, cc.travelling_frequency
                FROM users_v2 u
                LEFT JOIN users_v2 exec ON u.assigned_executive_id = exec.user_id
                LEFT JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
                WHERE u.user_id = ?`,
                [clientId]
            );
            if (clients.length === 0) {
                return res.status(404).json({ error: 'Client not found' });
            }
            res.json(clients[0]); // Send all fetched details
        } catch (error) {
            writeLog('Error fetching client personal details for /api/client/me/personal-details:', error);
            res.status(500).json({ error: 'Failed to fetch your personal details' });
        }
    });

    // API endpoint for client to save their blood test results
    router.post('/api/client/blood-tests', verifyClientToken, async (req, res) => {
        const clientId = req.client.clientId;
        const formData = req.body; // This is the raw data from the client
        writeLog(`[${new Date().toISOString()}] /api/client/blood-tests HIT for clientId: ${clientId}`);
        writeLog('Received blood test formData:', JSON.stringify(formData, null, 2));
        // Extract report dates, convert empty strings to null
        const report_date = formData.report_date;

        writeLog('Parsed report dates:', { report_date });
        const connection = await db.getConnection(); // Get a connection from the pool for transaction

        try {
            await connection.beginTransaction();
            writeLog('Transaction started.');

            // Find the latest consultation for the client using the new user_id
            const [consultations] = await executeSql(connection,
                `SELECT client_consultation_id FROM client_consultations WHERE user_id = ? AND is_latest = TRUE`,
                [clientId]
            );

            if (consultations.length === 0) {
                throw new Error('No active consultation found for this client to save the blood test results against.');
            }
            const consultationId = consultations[0].client_consultation_id;

            // 0. remove old reports for this specific consultation
            await executeSql(connection,
                `DELETE FROM client_blood_test_reports WHERE client_consultation_id = ?`,
                [consultationId]
            );

            // 1. Insert into client_blood_test_reports
            const [reportResult] = await executeSql(connection,
                `INSERT INTO client_blood_test_reports (client_consultation_id, report_date)
             VALUES (?, ?)`,
                [consultationId, report_date]
            );
            const reportId = reportResult.insertId;
            writeLog('Inserted into client_blood_test_reports, reportId:', reportId);

            // 2. Prepare and insert into client_blood_test_results
            const testResults = [];
            const testData = {}; // To group values by test_code

            for (const key in formData) {
                if (key.startsWith('report_date')) continue; // Skip already processed report dates
                const testCode = key;
                testData[testCode] = { value: formData[key] === '' ? null : formData[key] };
            }

            writeLog('Processed testData object:', JSON.stringify(testData, null, 2));
            for (const testCode in testData) {
                if (Object.values(testData[testCode]).some(val => val !== null)) { // Only insert if there's at least one value
                    testResults.push([
                        reportId,
                        testCode,
                        testData[testCode].value
                    ]);
                }
            }

            writeLog('Prepared testResults for bulk insert (first 5 rows if many):', JSON.stringify(testResults.slice(0, 5), null, 2));
            writeLog('Total testResult rows to insert:', testResults.length);

            if (testResults.length > 0) {
                const [resultsInsertResult] = await connection.query(
                    'INSERT INTO client_blood_test_results (report_id, test_code, value) VALUES ?',
                    [testResults] // Bulk insert
                );
                writeLog('Bulk insert into client_blood_test_results result:', resultsInsertResult);
            } else {
                writeLog('No test results to insert into client_blood_test_results.');
            }

            // Update the consultation's timestamp to signal a change to the frontend.
            await executeSql(connection,
                `UPDATE client_consultations SET updated_at = CURRENT_TIMESTAMP WHERE client_consultation_id = ?`,
                [consultationId]
            );
            writeLog(`Updated consultation timestamp for blood test submission for client ${clientId}`);

            await connection.commit();
            writeLog('Transaction committed successfully.');
            res.json({ message: 'Blood test results saved successfully.', reportId: reportId });

        } catch (error) {
            if (connection) await connection.rollback(); // Ensure connection exists before rollback
            writeLog('Error saving blood test results (ROLLBACK EXECUTED):', error);
            res.status(500).json({ error: 'Failed to save blood test results.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // API endpoint for client to GET their latest blood test results
    router.get('/api/client/blood-tests/latest', verifyClientToken, async (req, res) => {
        const clientId = req.client.clientId;
        writeLog(`[${new Date().toISOString()}] /api/client/blood-tests/latest HIT for clientId: ${clientId}`);

        try {
            // 1. Get the latest report_id for the client
            const [latestReportMeta] = await executeSql(db, `
                SELECT cbtr.report_id, cbtr.report_date
                FROM client_blood_test_reports cbtr
                JOIN client_consultations cc ON cbtr.client_consultation_id = cc.client_consultation_id
                WHERE cc.user_id = ? AND cc.is_latest = 1
                ORDER BY cbtr.created_at DESC
                LIMIT 1`,
                [clientId]
            );

            if (latestReportMeta.length === 0) {
                return res.json({ message: 'No blood test reports found for this client.' }); // Not an error, just no data
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

            // Combine report dates and results into a single response object
            const fullReportData = {
                ...report, // Includes report_id and the 5 report_date_N fields
                results: results // Array of test results
            };

            res.json(fullReportData);
        } catch (error) {
            writeLog('Error fetching latest blood test results:', error);
            res.status(500).json({ error: 'Failed to fetch latest blood test results.' });
        }
    });

    // API endpoint for client to save their food plan
    router.post('/api/client/food-plan', verifyClientToken, async (req, res) => {
        const clientId = req.client.clientId;
        const { hourly_plan } = req.body;

        // Sanitize the HTML content to prevent XSS attacks, then ensure it's null if empty
        const sanitizedRecommendations = sanitizeHtml(req.body.additional_personal_recommendations || '', {
            allowedTags: [ 'p', 'b', 'i', 'em', 'strong', 'ul', 'ol', 'li', 'br', 'h1', 'h2', 'h3' ],
            allowedAttributes: {} // No attributes allowed
        });

        writeLog(`[${new Date().toISOString()}] /api/client/food-plan HIT for clientId: ${clientId}`);
        writeLog('Received food plan data:', JSON.stringify(req.body, null, 2));

        if (!hourly_plan || typeof hourly_plan !== 'object') {
            return res.status(400).json({ error: 'Hourly plan data is missing or invalid.' });
        }

        const connection = await db.getConnection();

        try {
            await connection.beginTransaction();
            writeLog('Food plan save: Transaction started.');

            // Find the latest consultation for the client using the new user_id
            const [consultations] = await executeSql(connection,
                `SELECT client_consultation_id FROM client_consultations WHERE user_id = ? AND is_latest = TRUE`,
                [clientId]
            );

            if (consultations.length === 0) {
                throw new Error('No active consultation found for this client to save the food plan against.');
            }
            const consultationId = consultations[0].client_consultation_id;

            // 0. remove old client_food_plans for this specific consultation
            await executeSql(connection,
                `DELETE FROM client_food_plans WHERE client_consultation_id = ?`,
                [consultationId]
            );

            writeLog(`Food plan save: Deleted existing plans for consultation_id: ${consultationId}`);

            // Step 2: Insert the new food plan into client_food_plans
            const [planResult] = await executeSql(connection, `
                INSERT INTO client_food_plans (client_consultation_id, additional_personal_recommendations) 
                VALUES (?, ?)`,
                [consultationId, sanitizedRecommendations || null]
            );
            const planId = planResult.insertId;
            writeLog(`Food plan save: Inserted into client_food_plans, planId: ${planId}`);

            // Step 3: Prepare and insert hourly details
            const hourlyDetailsToInsert = [];
            for (const timeSlot in hourly_plan) {
                if (hourly_plan.hasOwnProperty(timeSlot)) {
                    const slotData = hourly_plan[timeSlot];
                    // Only insert if at least one field for the time slot has data
                    if (slotData.present_intake || slotData.proposed_structure || slotData.additional_points) {
                        hourlyDetailsToInsert.push([
                            planId,
                            timeSlot, // e.g., "06:00"
                            slotData.present_intake || null,
                            slotData.proposed_structure || null,
                            slotData.additional_points || null
                        ]);
                    }
                }
            }

            if (hourlyDetailsToInsert.length > 0) {
                await connection.query(
                    'INSERT INTO client_food_plan_hourly_details (plan_id, time_slot, present_intake, proposed_structure, additional_points) VALUES ?',
                    [hourlyDetailsToInsert] // Bulk insert
                );
                writeLog(`Food plan save: Inserted ${hourlyDetailsToInsert.length} hourly details for planId: ${planId}`);
            } else {
                writeLog(`Food plan save: No hourly details to insert for planId: ${planId}`);
            }

            // Update the consultation's timestamp to signal a change to the frontend.
            await executeSql(connection,
                `UPDATE client_consultations SET updated_at = CURRENT_TIMESTAMP WHERE client_consultation_id = ?`,
                [consultationId]
            );
            writeLog(`Updated consultation timestamp for food plan submission for client ${clientId}`);

            await connection.commit();
            writeLog('Food plan save: Transaction committed successfully.');
            res.json({ message: 'Food plan saved successfully.', planId: planId });

        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error saving food plan (ROLLBACK EXECUTED):', error);
            res.status(500).json({ error: 'Failed to save food plan.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // API endpoint for client to GET their own latest food plan
    router.get('/api/client/food-plan/latest', verifyClientToken, async (req, res) => {
        const clientId = req.client.clientId; // Get clientId from verified token
        writeLog(`[${new Date().toISOString()}] CLIENT ${clientId} /api/client/food-plan/latest HIT`);

        try {
            // 1. Get the latest plan_id for the client
            // Ensure we get the one marked as is_latest = TRUE, and order by updated_at to be sure.
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
                // It's not an error if no plan is found, just means the client doesn't have one yet.
                return res.json({ message: 'No food plan found for this client.' });
            }

            const plan = latestPlanMeta[0];
            const planId = plan.plan_id;

            // 2. Get all hourly details for that plan_id
            const [hourlyDetails] = await executeSql(db,
                `SELECT time_slot, present_intake, proposed_structure, additional_points
             FROM client_food_plan_hourly_details
             WHERE plan_id = ?
             ORDER BY time_slot ASC`, // Ensure consistent order
                [planId]
            );

            res.json({ ...plan, hourly_details: hourlyDetails });

        } catch (error) {
            writeLog(`Error fetching latest food plan for client ${clientId}:`, error);
            res.status(500).json({ error: 'Failed to fetch your latest food plan.' });
        }
    });
    // API endpoint for clients to GET general food recommendations
    router.post('/api/client/medical-history', verifyClientToken, async (req, res) => {
        const clientId = req.client.clientId;
        const { family_medical_history, medications, is_final_submission } = req.body;

        writeLog(`[${new Date().toISOString()}] /api/client/medical-history HIT for clientId: ${clientId}`);
        writeLog(`Value of is_final_submission from request body: ${is_final_submission} (Type: ${typeof is_final_submission})`);
        writeLog('Received medical history data:', JSON.stringify(req.body, null, 2));

        if ( typeof family_medical_history === 'undefined') {
            return res.status(400).json({ error: ' family medical history fields are required, even if empty.' });
        }

        const connection = await db.getConnection();

        try {
            await connection.beginTransaction();
            writeLog('Medical history save: Transaction started.');

            // Find the latest consultation for the client using the new user_id
            const [consultations] = await executeSql(connection,
                `SELECT client_consultation_id FROM client_consultations WHERE user_id = ? AND is_latest = TRUE`,
                [clientId]
            );

            if (consultations.length === 0) {
                throw new Error('No active consultation found for this client to save the medical history against.');
            }
            const consultationId = consultations[0].client_consultation_id;

            // 0. remove old medical history for this specific consultation
            await executeSql(connection,
                `DELETE FROM client_medical_history WHERE client_consultation_id = ?`,
                [consultationId]
            );

            // Step 1: Insert the new medical history into client_medical_history
            const [historyResult] = await executeSql(connection, `
                INSERT INTO client_medical_history (client_consultation_id, family_medical_history) 
                VALUES (?, ?)`,
                [consultationId, family_medical_history]
            );
            const historyId = historyResult.insertId;
            writeLog(`Medical history save: Inserted into client_medical_history, historyId: ${historyId}`);

            const updateQuery = `
                UPDATE client_consultations SET updated_at = CURRENT_TIMESTAMP ${is_final_submission ? ', is_finalized = TRUE' : ''}
                WHERE client_consultation_id = ?
                ${is_final_submission ? ' AND (is_finalized = FALSE OR is_finalized IS NULL)' : ''}
            `;
            const [updateResult] = await executeSql(connection, updateQuery, [consultationId]);

            if (updateResult.affectedRows > 0) {
                if (is_final_submission) {
                    writeLog(`Final Submission set to TRUE and timestamp updated for consultation ${consultationId}`);
                } else {
                    writeLog(`Timestamp updated for draft medical history for consultation ${consultationId}`);
                }
            } else {
                if (is_final_submission) {
                    writeLog(`Final submission for consultation ${consultationId} was already set or consultation not found. No update made.`);
                } else {
                    writeLog(`Consultation timestamp for consultation ${consultationId} not updated (no record found or already up-to-date).`);
                }
            }
            // Step 2: Prepare and insert medications, if any
            if (medications && Array.isArray(medications) && medications.length > 0) {
                const medicationsToInsert = medications.map(med => [
                    historyId,
                    med.diagnosis || null,
                    med.medicine_name || null,
                    med.power || null,
                    med.timing || null,
                    med.since_when || null
                ]);

                if (medicationsToInsert.length > 0) {
                    await connection.query(
                        'INSERT INTO client_medications (history_id, diagnosis, medicine_name, power, timing, since_when) VALUES ?',
                        [medicationsToInsert] // Bulk insert
                    );
                    writeLog(`Medical history save: Inserted ${medicationsToInsert.length} medications for historyId: ${historyId}`);
                }
            } else {
                writeLog(`Medical history save: No medications to insert for historyId: ${historyId}`);
            }

            await connection.commit();
            writeLog('Medical history save: Transaction committed successfully.');
            res.json({ message: `Medical history ${is_final_submission ? 'submitted' : 'saved'} successfully.`, historyId: historyId });

        } catch (error) {
            if (connection) await connection.rollback();
            writeLog('Error saving medical history (ROLLBACK EXECUTED):', error);
            res.status(500).json({ error: 'Failed to save medical history.' });
        } finally {
            if (connection) connection.release();
        }
    });

    // API endpoint for client to GET their latest medical history
    router.get('/api/client/medical-history/latest', verifyClientToken, async (req, res) => {
        const clientId = req.client.clientId;
        writeLog(`[${new Date().toISOString()}] /api/client/medical-history/latest HIT for clientId: ${clientId}`);

        try {
            // 1. Get the latest history_id for the client
            const [latestHistoryMeta] = await executeSql(db, `
                SELECT cmh.history_id, cmh.family_medical_history, cc.is_finalized, cmh.created_at, cmh.updated_at
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

            // 2. Get all medications for that history_id
            const [medications] = await executeSql(db,
                `SELECT medication_id, diagnosis, medicine_name, power, timing, since_when
             FROM client_medications
             WHERE history_id = ?`,
                [historyId]
            );

            res.json({ ...history, medications: medications });
        } catch (error) {
            writeLog('Error fetching latest medical history:', error);
            res.status(500).json({ error: 'Failed to fetch latest medical history.' });
        }
    });

    // Admin: Get latest food plan for a specific client
}
