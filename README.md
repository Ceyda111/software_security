# Secure Student Notes Application

This project was developed for the SWE210 Software Security course.

The application is a simple secure web application created using Flask and SQLite. Users can register, login, and save secret notes securely.

## Security Features

- User Authentication
- Password Hashing using bcrypt
- Role-Based Access Control (RBAC)
- Data Encryption using Fernet
- Session Management
- SQL Injection Prevention with parameterized queries

## Technologies Used

- Python
- Flask
- SQLite
- bcrypt
- cryptography

## User Roles

### Admin
- Access admin panel
- View all users

### User
- Register and login
- Add and view secret notes

