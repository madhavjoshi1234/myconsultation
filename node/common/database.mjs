import mysql from 'mysql2/promise';
import { writeLog } from "./utils.mjs";

export async function startDatabase({ host, db, user, password, encryptionKey }) {
  if (!host || !user || !password || !db) {
    writeLog('Missing database configuration in .env file.');
    process.exit(1);
  }
  let pool;
  try {
    pool = mysql.createPool({
      host: host || 'localhost', // Or your MySQL host
      user: user, // Your MySQL username
      password: password, // Your MySQL password from environment variable
      database: db, // Your database name
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });
    writeLog('MySQL Pool created successfully.');
  } catch (err) {
    writeLog('Failed to create MySQL Pool:', err);
    process.exit(1);
  }

  // Test the pool immediately upon creation
  try {
    const conn = await pool.getConnection();
    await conn.ping();
    conn.release();
    writeLog('Successfully connected to database.');
  } catch (err) {
    writeLog('Failed to connect to database:', err);
    process.exit(1);
  }
  return pool;
}

export function setupDbSetupRoute(router, db) {
  writeLog('Setting up DB setup route...');
  if (process.env.NODE_ENV === 'development') {
    writeLog('Running in development mode');
    router.post('/api/setup', async (req, res) => {
      writeLog('Received request to /api/setup');
      if (!req.body || !req.body.token || req.body.token !== process.env.HEALTH_CHECK_TOKEN) {
        writeLog('Bad request to /api/setup');
        res.status(400).json({ error: 'Bad Request' });
        return;
      }
      try {
        writeLog('Running setup from API...');
        await runSetup(db);
        writeLog('Setup from API completed successfully.');
        res.json({ status: 'OK', timestamp: new Date().toISOString(), logs: readLogs() });
      } catch (error) {
        writeLog('Error running setup from API:', error);
        res.status(500).json({ error: 'Failed to read logs' });
      }
    });
    router.post('/api/schema', async (req, res) => {
      writeLog('Received request to /api/schema');
      if (!req.body || !req.body.token || req.body.token !== process.env.HEALTH_CHECK_TOKEN) {
        writeLog('Bad request to /api/schema');
        res.status(400).json({ error: 'Bad Request' });
        return;
      }
      try {
        writeLog('Running setup from API...');
        let schema = await extractSchema(db);
        writeLog('Setup from API completed successfully.');
        res.json({ status: 'OK', timestamp: new Date().toISOString(), schema });
      } catch (error) {
        writeLog('Error running setup from API:', error);
        res.status(500).json({ error: 'Failed to read logs' });
      }
    });
  }
}

export async function executeSql(db, ...args) {
  if (args.length > 0 && typeof args[0] === 'string') {
    let sql = args[0];
    sql = sql.replaceAll(/[\n\t]/g, ' ');
    sql = sql.replace(/\s+/g, ' ');
    writeLog('SQL:\n', sql, '\n', 'args', args);
  }
  let result =   await db.execute(...args);
  writeLog('Result:\n', result);
  return result
}

export async function extractSchema(pool) {
  // use information_schema to extract table definitions and constraints
  const [tables] = await pool.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()");
  let schema = {};
  for (let table of tables) {
    const tableName = table.TABLE_NAME;
    const [columns] = await pool.execute(`
            SELECT *
            FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = ?
            ORDER BY ordinal_position
        `, [tableName]);

    const [constraints] = await pool.execute(`
            SELECT *
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
        `, [tableName]);

    schema[tableName] = {
      columns,
      constraints
    };
  }
  return schema;

}