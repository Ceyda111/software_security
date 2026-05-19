# Secure Student Notes Application

This project was developed for the SWE210 Software Security course.

The application is a simple secure web application created using Flask and SQLite. Users can register, login, and save secret notes securely. While admins can see user accounts and moniter user activity.

## Technologies Used

- Python
- HTML
- Flask
- SQLite
- bcrypt
- cryptography

- - - - 

# How To Run

1. Install Dependencies:
2. ```bash
   pip install -r requirements.txt
   ```
2. Initialis `user.db` and `key.key` files.
>[!IMPORTANT]
>A user.db with existing users and logs already exists (as an example), so you can either go to the next step, or delete them first before initialising.

3. ```bash
    python init_db.py
    ```
3. Run the main code, `app.py`
4. ```bash
   python app.py
   ```
4. Terminat should say that it's running on a site (https://...) copy and open in your browser.
   
>[!NOTE]
>Same notice should be on your terminal, but if you want to close the program simply press `Ctrl + c` to close the application.

# User Roles

### User
- Register and login
- Add and view personal secret notes

### Admin
- Access admin panel
- View all users
- View and monitor Audit Log

### To access the Admin panel:

`Username:` Admin

`Password:` Admin 123

# Security Features

- User Authentication
- Password Hashing using bcrypt
- Role-Based Access Control (RBAC)
- Data Encryption using Fernet
- Session Management
- SQL Injection Prevention with parameterized queries
