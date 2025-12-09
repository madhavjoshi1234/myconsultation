const SQL_FILES_DIR = './sql';

import { SQL_FILES_ORDER } from '../sqlFiles.mjs';
import { readLogs, writeLog } from './utils.mjs';
import fs from 'fs';
import path from 'path';
import { startDatabase } from './database.mjs';
import { decrypt, getDefaultKey } from './decrypt.mjs';
import dotenv from 'dotenv';
import { pathToFileURL } from 'url';
dotenv.config();


const MIGRATIONS_LOG_FILE = path.join(SQL_FILES_DIR, 'migrations.log');

function readExecutedMigrations() {
  writeLog('Reading executed migrations...');
  if (fs.existsSync(MIGRATIONS_LOG_FILE)) {
    const migrations = fs.readFileSync(MIGRATIONS_LOG_FILE, 'utf8').split('\n').filter(Boolean);
    writeLog(`Executed migrations: ${migrations.join(', ')}`);
    return migrations;
  }
  writeLog('No migrations log file found.');
  return [];
}

function writeExecutedMigration(fileName) {
  writeLog(`Writing executed migration: ${fileName}`);
  fs.appendFileSync(MIGRATIONS_LOG_FILE, `${fileName}\n`);
}

let args = process.argv.slice(2);
async function main() {
  writeLog('Starting setup script...');
  const forceReset = args.includes('--force-reset');

  if (forceReset) {
    writeLog('--force-reset detected. Deleting migrations.log...');
    if (fs.existsSync(MIGRATIONS_LOG_FILE)) {
      fs.unlinkSync(MIGRATIONS_LOG_FILE);
      writeLog('migrations.log deleted.');
    } else {
      writeLog('migrations.log not found, no need to delete.');
    }
  }
  const ENC_KEY = process.env.ENC_KEY || getDefaultKey();

  writeLog('Starting database...');
  // Create pool
  const pool = await startDatabase({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    db: process.env.DB_NAME,
    encryptionKey: ENC_KEY,
  });
  writeLog('Database started.');

  let specificFile = args.filter(arg => arg !== '--force-reset')[0];
  // Execute SQL files in order
  writeLog('Running setup...');
  await runSetup(pool, specificFile);
  writeLog('Setup finished.');

  await pool.end();
  writeLog('Setup completed successfully.');
  process.exit(0);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}

async function runSetup(pool, specificFile) {
  writeLog('Running runSetup...');
  const executedFiles = readExecutedMigrations();
  let filesToExecute = SQL_FILES_ORDER.filter(file => !executedFiles.includes(file));

  if (specificFile) {
    filesToExecute = [specificFile];
    writeLog(`Specific file provided: ${specificFile}`);
  } else {
    let migrationFiles = fs.readdirSync(SQL_FILES_DIR)
      .filter(file => file.startsWith('migration-') && file.endsWith('.sql') && !executedFiles.includes(file))
      .sort((a, b) => {
        const numA = parseInt(a.match(/\d+/)[0]);
        const numB = parseInt(b.match(/\d+/)[0]);
        return numA - numB;
      });

    for (const mFile of migrationFiles) {
      if (!filesToExecute.includes(mFile)) {
        filesToExecute.push(mFile);
      }
    }
  }

  if (filesToExecute.length === 0) {
    writeLog('No SQL files to execute.');
    return true;
  }

  writeLog(`Files to execute: ${filesToExecute.join(', ')}`);

  for (const sqlFile of filesToExecute) {
    const fullPath = path.join(SQL_FILES_DIR, sqlFile);
    if (!fs.existsSync(fullPath)) {
      writeLog(`Warning: SQL file ${fullPath} not found. Skipping.`);
      continue;
    }
    writeLog(`Executing ${sqlFile}...`);
    try {
      const sqlContent = fs.readFileSync(fullPath, 'utf8');
      // 1. Remove comments
      const uncommentedSql = sqlContent.split('\n').filter(line => !line.trim().startsWith('--')).join('\n');

      // 2. Split into statements
      const statements = uncommentedSql
        .split(/;\s*[\r\n]+/)
        .map(s => s.trim())
        .filter(s => s.length > 0);

      for (const stmt of statements) {
        await pool.query(stmt);
      }
      writeExecutedMigration(sqlFile);
      writeLog(`${sqlFile} executed successfully.`);
    } catch (err) {
      writeLog(`Error executing ${sqlFile}:`, err);
      return false;
    }
  }
  writeLog('All SQL scripts executed successfully.');
  return true;
}

export async function checkAndSetup(db, tableName) {
  writeLog(`Checking if table '${tableName}' exists...`);
  // use information_schema to find if the table exists
  try {
    const [tables] = await db.query(
      `SELECT table_name FROM information_schema.tables \n        WHERE table_schema = ? AND table_name = ?`,
      [process.env.DB_NAME, tableName]);
    if (tables.length === 0) {
      writeLog(`Table '${tableName}' not found.`);
      let result = await runSetup(db);
      writeLog(`!!! CRITICAL: The "${tableName}" table does not exist in the database. Please run the setup script.`);
      return result;
    }
    writeLog(`Table '${tableName}' exists.`);
    return true;
  } catch (err) {
    writeLog('!!! CRITICAL: Error checking for "clients" table:', err);
    return false;
  }
}
