CREATE USER 'auth_user1'@'localhost' IDENTIFIED BY 'Auth123';

CREATE DATABASE auth_service_db;

GRANT ALL PRIVILEGES ON auth.* TO 'auth_user1'@'localhost';

USE auth_service_db;

