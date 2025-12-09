-- Migration to role codes for multi-role support

-- Modify the 'role' column to allow for a comma-separated list of roles
ALTER TABLE users MODIFY COLUMN role VARCHAR(255) NOT NULL;

-- Update existing roles to the new code format
UPDATE users SET role = 'N' WHERE role = 'nutritionist';
UPDATE users SET role = 'E' WHERE role = 'executive';
UPDATE users SET role = 'A' WHERE role = 'admin';

-- Example for assigning both roles to a user (commented out)
-- UPDATE users SET role = 'N,E' WHERE email = 'someuser@example.com';