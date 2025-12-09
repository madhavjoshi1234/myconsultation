import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { writeLog } from './common/utils.mjs';
import { checkPasswordPolicy } from './common/utils.mjs';
import { executeSql } from './common/database.mjs';

export function setupStaffRoutes({ router, db, JWT_SECRET, EMAIL_USER, transporter, appUrl }) {

    // Middleware to verify Staff (Nutritionist/Executive) JWT
    const verifyStaffToken = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7, authHeader.length);
            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(403).json({ error: 'Forbidden: Invalid token' });
                }

                // Handle both new 'roles' array and old 'role' string for backward compatibility
                let userRoles = [];
                if (decoded.roles && Array.isArray(decoded.roles)) {
                    userRoles = decoded.roles;
                } else if (typeof decoded.role === 'string') {
                    userRoles = [decoded.role];
                }

                if (userRoles.length === 0) {
                    return res.status(403).json({ error: 'Forbidden: No roles found in token' });
                }

                const hasStaffRole = userRoles.includes('nutritionist') || userRoles.includes('executive');
                if (!hasStaffRole) {
                    return res.status(403).json({ error: 'Forbidden: User does not have a valid staff role.' });
                }

                // For consistency, ensure req.user.roles is always an array
                req.user = { ...decoded, roles: userRoles };
                next();
            });
        } else {
            res.status(401).json({ error: 'Unauthorized: Missing staff token' });
        }
    };

    // Serve nutritionist dashboard, protected by staff token
    router.get('/nutritionist-dashboard.html', (req, res) => {
        res.sendFile(__dirname + '/public/nutritionist-dashboard.html');
    });

    // Serve executive dashboard, protected by staff token
    router.get('/executive-dashboard.html', (req, res) => {
        res.sendFile(__dirname + '/public/executive-dashboard.html');
    });

    // API endpoint for a nutritionist to get their assigned clients
    router.get('/api/nutritionist/my-clients', verifyStaffToken, async (req, res) => {
        if (!req.user.roles.includes('nutritionist')) {
            return res.status(403).json({ error: 'Forbidden: Access denied for this role' });
        }
        const nutritionistId = req.user.userId;
 
        try {
            // A nutritionist can view all active clients.
            const [clients] = await executeSql(db, `
                SELECT
                    u.user_id as client_id, u.first_name, u.last_name, u.email, u.mobile_number
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id
                JOIN roles r ON ur.role_id = r.role_id
                WHERE r.role_name = 'client' AND u.is_active = TRUE
                ORDER BY u.last_name, u.first_name`
            );
            res.json(clients);
        } catch (error) {
            writeLog('Error fetching nutritionist clients:', error);
            res.status(500).json({ error: 'Failed to fetch clients' });
        }
    });

    // API endpoint for a nutritionist to search their assigned clients
    router.get('/api/nutritionist/my-clients/search', verifyStaffToken, async (req, res) => {
        if (!req.user.roles.includes('nutritionist')) {
            return res.status(403).json({ error: 'Forbidden: Access denied for this role' });
        }
        const nutritionistId = req.user.userId;
        writeLog(`[${new Date().toISOString()}] NUTRITIONIST ${nutritionistId} /api/nutritionist/my-clients/search HIT with query:`, req.query);

        try {
            let sql = `
                SELECT
                    u.user_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number
                FROM users_v2 u
                WHERE u.assigned_nutritionist_id = ? AND u.is_active = TRUE`;
            const params = [nutritionistId];

            if (req.query.client_id) {
                sql += " AND u.user_id = ?";
                params.push(req.query.client_id);
            }
            if (req.query.first_name) {
                sql += " AND u.first_name LIKE ?";
                params.push(`%${req.query.first_name}%`);
            }
            if (req.query.last_name) {
                sql += " AND u.last_name LIKE ?";
                params.push(`%${req.query.last_name}%`);
            }
            if (req.query.email) {
                sql += " AND u.email LIKE ?";
                params.push(`%${req.query.email}%`);
            }
            sql += " ORDER BY u.last_name, u.first_name";

            const [clients] = await executeSql(db, sql, params);
            res.json(clients);
        } catch (error) {
            writeLog('Error searching nutritionist clients:', error);
            res.status(500).json({ error: 'Failed to search assigned clients' });
        }
    });


    // API endpoint for an executive to get their enrolled clients
    router.get('/api/executive/my-clients', verifyStaffToken, async (req, res) => {
        if (!req.user.roles.includes('executive')) {
            return res.status(403).json({ error: 'Forbidden: Access denied for this role' });
        }
        const executiveId = req.user.userId;

        try {
            const [clients] = await executeSql(db, `
                SELECT
                    m.old_client_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number, u.created_at as registration_date
                FROM users_v2 u
                JOIN client_id_to_user_id_mapping m ON u.user_id = m.new_user_id
                WHERE u.assigned_executive_id = ? AND u.is_active = TRUE
                ORDER BY u.created_at DESC, u.last_name, u.first_name
            `,
                [executiveId]
            );
            res.json(clients);
        } catch (error) {
            writeLog('Error fetching executive clients:', error);
            res.status(500).json({ error: 'Failed to fetch enrolled clients' });
        }
    });

    // API endpoint for an executive to search their enrolled clients
    router.get('/api/executive/my-clients/search', verifyStaffToken, async (req, res) => {
        if (!req.user.roles.includes('executive')) {
            return res.status(403).json({ error: 'Forbidden: Access denied for this role' });
        }
        const executiveId = req.user.userId;
        writeLog(`[${new Date().toISOString()}] EXECUTIVE ${executiveId} /api/executive/my-clients/search HIT with query:`, req.query);

        try {
            let sql = `
                SELECT
                    m.old_client_id as client_id,
                    u.first_name, u.last_name, u.email, u.mobile_number, u.created_at as registration_date
                FROM users_v2 u
                JOIN client_id_to_user_id_mapping m ON u.user_id = m.new_user_id
                WHERE u.assigned_executive_id = ? AND u.is_active = TRUE`;
            const params = [executiveId];

            if (req.query.client_id) {
                sql += " AND m.old_client_id = ?";
                params.push(req.query.client_id);
            }
            if (req.query.first_name) {
                sql += " AND u.first_name LIKE ?";
                params.push(`%${req.query.first_name}%`);
            }
            if (req.query.last_name) {
                sql += " AND u.last_name LIKE ?";
                params.push(`%${req.query.last_name}%`);
            }
            if (req.query.email) {
                sql += " AND u.email LIKE ?";
                params.push(`%${req.query.email}%`);
            }
            sql += " ORDER BY u.created_at DESC, u.last_name, u.first_name";

            const [clients] = await executeSql(db, sql, params);
            res.json(clients);
        } catch (error) {
            writeLog('Error searching executive clients:', error);
            res.status(500).json({ error: 'Failed to search enrolled clients' });
        }
    });

    // --- Admin Client Management Routes ---
    // Get all clients for Admin
    router.get('/api/staff/list/nutritionists', async (req, res) => {
        writeLog(`[${new Date().toISOString()}] Request received for /api/staff/list/nutritionists`); // Adjusted log
        try {
            const [nutritionists] = await executeSql(db, `
                SELECT u.user_id, u.first_name, u.last_name
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id
                JOIN roles r ON ur.role_id = r.role_id
                WHERE r.role_name = 'nutritionist' AND u.is_active = TRUE
                ORDER BY u.last_name, u.first_name`
            );
            res.json(nutritionists);
        } catch (error) {
            writeLog('Error fetching list of nutritionists:', error);
            res.status(500).json({ error: 'Failed to fetch nutritionists list.' });
        }
    });

    // API to list active executives for client selection
    router.get('/api/staff/list/executives', async (req, res) => {
        writeLog(`[${new Date().toISOString()}] Request received for /api/staff/list/executives`);
        try {
            const [executives] = await executeSql(db, `
                SELECT u.user_id, u.first_name, u.last_name
                FROM users_v2 u
                JOIN user_roles ur ON u.user_id = ur.user_id
                JOIN roles r ON ur.role_id = r.role_id
                WHERE r.role_name = 'executive' AND u.is_active = TRUE
                ORDER BY u.last_name, u.first_name`
            );
            res.json(executives);
        } catch (error) {
            writeLog('Error fetching list of executives:', error);
            res.status(500).json({ error: 'Failed to fetch executives list.' });
        }
    });

    // API for client to update their staff preferences
    // This endpoint should be protected by client authentication (once client login is implemented)
    // For now, let's assume client_id is passed in the body for simplicity,
    // but in a real app, it would come from the client's JWT.
    router.get('/api/general-food-recommendations', async (req, res) => {
        writeLog(`[${new Date().toISOString()}] /api/general-food-recommendations HIT`);
        try {
            // Fetch the most recent (or only) general recommendation
            // Assuming we'll mostly have one row that gets updated, or we take the latest if multiple exist.
            const [rows] = await executeSql(db,
                'SELECT recommendations_text FROM general_food_recommendations ORDER BY updated_at DESC LIMIT 1'
            );

            if (rows.length > 0) {
                res.json({ recommendations: rows[0].recommendations_text });
            } else {
                res.json({ recommendations: 'No general recommendations are currently set.' });
            }
        } catch (error) {
            writeLog('Error fetching general food recommendations:', error);
            res.status(500).json({ error: 'Failed to fetch general food recommendations.' });
        }
    });

    // API endpoint for ADMIN to SET/UPDATE general food recommendations
    router.get('/api/staff/clients/:clientId/personal-details', verifyStaffToken, async (req, res) => {
        const { clientId } = req.params;
        const staffId = req.user.userId;
        const staffRole = req.user.roles;

        writeLog(`[${new Date().toISOString()}] STAFF (${staffRole} ${staffId}) /api/staff/clients/${clientId}/personal-details HIT`);
        if (!await isStaffAuthorizedForClient(db, staffId, staffRole, clientId)) {
            return res.status(403).json({ error: 'Forbidden: You are not authorized to view this client.' });
        }
        // Reuse admin logic for fetching
        try {
            const [clients] = await executeSql(db, `
                SELECT
                    m.old_client_id as client_id,
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
                JOIN client_id_to_user_id_mapping m ON u.user_id = m.new_user_id
                JOIN client_consultations cc ON u.user_id = cc.user_id AND cc.is_latest = 1
                WHERE m.old_client_id = ?`,
                [clientId]
            );
            if (clients.length === 0) return res.status(404).json({ error: 'Client not found' });
            res.json(clients[0]);
        } catch (error) {
            writeLog(`Error fetching personal details for client ${clientId} by staff:`, error);
            res.status(500).json({ error: 'Failed to fetch client personal details.' });
        }
    });

    // Staff: Get latest medical history for a specific client
    router.get('/api/staff/clients/:clientId/medical-history/latest', verifyStaffToken, async (req, res) => {
        const { clientId } = req.params;
        const staffId = req.user.userId;
        const staffRole = req.user.roles;

        writeLog(`[${new Date().toISOString()}] STAFF (${staffRole} ${staffId}) /api/staff/clients/${clientId}/medical-history/latest HIT`);
        if (!await isStaffAuthorizedForClient(db, staffId, staffRole, clientId)) {
            return res.status(403).json({ error: 'Forbidden: You are not authorized to view this client.' });
        }
        try {
            const [latestHistoryMeta] = await executeSql(db, `
                SELECT cmh.history_id, cmh.family_medical_history, cmh.created_at, cmh.updated_at
                FROM client_medical_history cmh
                JOIN client_consultations cc ON cmh.client_consultation_id = cc.client_consultation_id
                WHERE cc.user_id = ?
                  AND cc.is_latest = 1
                ORDER BY cmh.updated_at DESC
                LIMIT 1`,
                [clientId]
            );
            if (latestHistoryMeta.length === 0) return res.json({ message: 'No medical history found for this client.' });
            const history = latestHistoryMeta[0];
            const [medications] = await executeSql(db, `SELECT medication_id, diagnosis, medicine_name, power, timing, since_when FROM client_medications WHERE history_id = ?`, [history.history_id]);
            res.json({ ...history, medications: medications });
        } catch (error) {
            writeLog(`Error fetching medical history for client ${clientId} by staff:`, error);
            res.status(500).json({ error: 'Failed to fetch medical history.' });
        }
    });

    // Staff: Get latest blood test results for a specific client
    router.get('/api/staff/clients/:clientId/blood-tests/latest', verifyStaffToken, async (req, res) => {
        const { clientId } = req.params;
        const staffId = req.user.userId;
        const staffRole = req.user.roles;

        writeLog(`[${new Date().toISOString()}] STAFF (${staffRole} ${staffId}) /api/staff/clients/${clientId}/blood-tests/latest HIT`);
        if (!await isStaffAuthorizedForClient(db, staffId, staffRole, clientId)) {
            return res.status(403).json({ error: 'Forbidden: You are not authorized to view this client.' });
        }
        try {
            const [latestReportMeta] = await executeSql(db, `
                SELECT cbtr.report_id, cbtr.report_date, cbtr.created_at
                FROM client_blood_test_reports cbtr
                JOIN client_consultations cc ON cbtr.client_consultation_id = cc.client_consultation_id
                WHERE cc.user_id = (SELECT new_user_id FROM client_id_to_user_id_mapping WHERE old_client_id = ?)
                  AND cc.is_latest = 1
                ORDER BY cbtr.created_at DESC
                LIMIT 1`,
                [clientId]
            );
            if (latestReportMeta.length === 0) return res.json({ message: 'No blood test reports found for this client.' });
            const report = latestReportMeta[0];
            const [results] = await executeSql(db, `SELECT test_code, value FROM client_blood_test_results WHERE report_id = ?`, [report.report_id]);
            res.json({ ...report, results: results });
        } catch (error) {
            writeLog(`Error fetching blood tests for client ${clientId} by staff:`, error);
            res.status(500).json({ error: 'Failed to fetch blood tests.' });
        }
    });

    // Staff: Get latest food plan for a specific client
    router.get('/api/staff/clients/:clientId/food-plan/latest', verifyStaffToken, async (req, res) => {
        const { clientId } = req.params;
        const staffId = req.user.userId;
        const staffRole = req.user.roles;

        writeLog(`[${new Date().toISOString()}] STAFF (${staffRole} ${staffId}) /api/staff/clients/${clientId}/food-plan/latest HIT`);
        if (!await isStaffAuthorizedForClient(db, staffId, staffRole, clientId)) {
            return res.status(403).json({ error: 'Forbidden: You are not authorized to view this client.' });
        }
        try {
            const [latestPlanMeta] = await executeSql(db, `
                SELECT cfp.plan_id, cfp.additional_personal_recommendations, cfp.created_at, cfp.updated_at
                FROM client_food_plans cfp
                JOIN client_consultations cc ON cfp.client_consultation_id = cc.client_consultation_id
                WHERE cc.user_id = (SELECT new_user_id FROM client_id_to_user_id_mapping WHERE old_client_id = ?)
                  AND cc.is_latest = 1
                ORDER BY cfp.updated_at DESC
                LIMIT 1`,
                [clientId]
            );
            if (latestPlanMeta.length === 0) return res.json({ message: 'No food plan found for this client.' });
            const plan = latestPlanMeta[0];
            const [hourlyDetails] = await executeSql(db, `SELECT time_slot, present_intake, proposed_structure, additional_points FROM client_food_plan_hourly_details WHERE plan_id = ? ORDER BY time_slot ASC`, [plan.plan_id]);
            res.json({ ...plan, hourly_details: hourlyDetails });
        } catch (error) {
            writeLog(`Error fetching food plan for client ${clientId} by staff:`, error);
            res.status(500).json({ error: 'Failed to fetch food plan.' });
        }
    });

    // Nutritionist: Save/Update food plan for a specific client
    router.post('/api/nutritionist/clients/:clientId/food-plan', verifyStaffToken, async (req, res) => {
        const { clientId } = req.params;
        const nutritionistId = req.user.userId;
        const { hourly_plan, additional_personal_recommendations } = req.body;

        if (!req.user.roles.includes('nutritionist')) {
            return res.status(403).json({ error: 'Forbidden: Only nutritionists can save food plans.' });
        }
        writeLog(`[${new Date().toISOString()}] NUTRITIONIST ${nutritionistId} /api/nutritionist/clients/${clientId}/food-plan POST HIT`);
        if (!await isStaffAuthorizedForClient(db, nutritionistId, 'nutritionist', clientId)) {
            return res.status(403).json({ error: 'Forbidden: You are not assigned to this client.' });
        }
        if (!hourly_plan || typeof hourly_plan !== 'object') {
            return res.status(400).json({ error: 'Hourly plan data is missing or invalid.' });
        }

        const connection = await db.getConnection();
        try {
            await connection.beginTransaction();

            // Find the latest consultation for the client
            const [consultations] = await executeSql(connection,
                `SELECT client_consultation_id FROM client_consultations
                 WHERE user_id = (SELECT new_user_id FROM client_id_to_user_id_mapping WHERE old_client_id = ?) AND is_latest = TRUE`,
                [clientId]
            );

            if (consultations.length === 0) {
                throw new Error('No active consultation found for this client to save the food plan against.');
            }
            const consultationId = consultations[0].client_consultation_id;

            // Delete any existing food plan for this consultation to avoid duplicates.
            await executeSql(connection,
                'DELETE FROM client_food_plans WHERE client_consultation_id = ?',
                [consultationId]
            );

            // Insert the new food plan record
            const [planResult] = await executeSql(connection,
                'INSERT INTO client_food_plans (client_consultation_id, additional_personal_recommendations, created_by_nutritionist_id) VALUES (?, ?, ?)',
                [consultationId, additional_personal_recommendations, nutritionistId]
            );
            const planId = planResult.insertId;

            // Prepare and insert hourly details
            const hourlyDetailsToInsert = Object.entries(hourly_plan)
                .map(([timeSlot, slotData]) => [
                    planId, timeSlot, slotData.present_intake || null,
                    slotData.proposed_structure || null, slotData.additional_points || null
                ])
                .filter(detail => detail[2] || detail[3] || detail[4]);

            if (hourlyDetailsToInsert.length > 0) {
                await connection.query('INSERT INTO client_food_plan_hourly_details (plan_id, time_slot, present_intake, proposed_structure, additional_points) VALUES ?', [hourlyDetailsToInsert]);
            }

            await connection.commit();
            res.json({ message: 'Client food plan updated successfully by nutritionist.', planId: planId });
        } catch (error) {
            if (connection) await connection.rollback();
            writeLog(`Error saving food plan for client ${clientId} by nutritionist (ROLLBACK EXECUTED):`, error);
            res.status(500).json({ error: 'Failed to save client food plan.' });
        } finally {
            if (connection) connection.release();
        }
    });


}
// --- Staff (Nutritionist/Executive) Access to Client Details ---
// Helper function to check if staff is authorized for a client
export async function isStaffAuthorizedForClient(db, staffId, staffRole, clientId) {
    const [clientRows] = await executeSql(db, `
        SELECT assigned_nutritionist_id, assigned_executive_id
        FROM users_v2
        WHERE user_id = ?`,
        [clientId]
    );
    if (clientRows.length === 0) {
        return false; // Client not found
    }
    const client = clientRows[0];
    if (staffRole.includes('nutritionist') && client.assigned_nutritionist_id === staffId) {
        return true;
    }
    if (staffRole.includes('executive') && client.assigned_executive_id === staffId) {
        return true;
    }
    return false;
}
