# Secret-App
# Authentication App with Express and Passport

This is a web application built with **Express.js** and **Passport.js** that demonstrates user authentication using **local authentication** (email and password) and **Google OAuth2**. The application also deals with session management and allows users to register, log in, submit secrets, and view them securely.

## Features

- **User Registration**: Users can register with an email and password. Passwords are securely hashed using **bcrypt**.
- **Local Authentication**: Users can log in using their email and password.
- **Google OAuth2 Authentication**: Users can log in using their Google account.
- **Session Management**: User sessions are managed using **express-session**.
- **Protected Routes**: Certain routes (e.g., `/secrets`, `/submit`) are accessible only to authenticated users.
- **Database Integration**: User data is stored in a **PostgreSQL** database.

## Technologies Used

- **Backend**: Node.js, Express.js
- **Authentication**: Passport.js, bcrypt
- **Database**: PostgreSQL
- **Frontend**: EJS (Embedded JavaScript templates)
- **Environment Variables**: dotenv

## Prerequisites

Before running the application, ensure you have the following installed:

- [Node.js](https://nodejs.org/) (v16 or higher)
- [PostgreSQL](https://www.postgresql.org/) (v12 or higher)
- [Git](https://git-scm.com/) (optional)

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name

2. **Install Dependencies:**
   ```bash
   npm install

3. **Set Up the Database:**
   
   Create a PostgreSQL database.
   Update the .env file with your database credentials:
   ```bash
    PG_USER=your_db_user
    PG_HOST=localhost
    PG_DATABASE=your_db_name
    PG_PASSWORD=your_db_password
    PG_PORT=5432
    SESSION_SECRET=your_session_secret
    GOOGLE_CLIENT_ID=your_google_client_id
    GOOGLE_CLIENT_SECRET=your_google_client_secret

