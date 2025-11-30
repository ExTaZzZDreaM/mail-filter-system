CREATE TABLE staff (
                       id SERIAL PRIMARY KEY,
                       first_name VARCHAR(50) NOT NULL,
                       last_name VARCHAR(50) NOT NULL,
                       email VARCHAR(100) UNIQUE NOT NULL,
                       login VARCHAR(50) UNIQUE NOT NULL,
                       password VARCHAR(255) NOT NULL,
                       is_admin BOOLEAN DEFAULT FALSE,
                       status VARCHAR(20) DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive')),
                       created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);



INSERT INTO staff (first_name, last_name, email, login, password, is_admin, status)
VALUES
    ('John', 'Doe', 'john.doe@test.com', 'jdoe', 'password123', TRUE, 'Active'),
    ('Jane', 'Smith', 'jane.smith@test.com', 'jsmith', 'securepass456', FALSE, 'Active'),
    ('Mike', 'Johnson', 'mike.johnson@test.com', 'mjohnson', 'mypassword789', FALSE, 'Inactive');
