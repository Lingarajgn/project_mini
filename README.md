# Routine Hub

Routine Hub is a full-stack productivity and task management web application designed to help users organize daily routines, manage tasks, and improve productivity. The platform provides a clean dashboard for tracking tasks and routines while offering a scalable architecture for future AI/ML-powered productivity insights.

## Features

### User Authentication

* User Registration
* User Login
* JWT-based Authentication
* Secure Password Hashing
* Protected Routes

### Task Management

* Create Tasks
* View Tasks
* Update Tasks
* Delete Tasks
* Mark Tasks as Completed
* Priority-based Task Organization

### Routine Management

* Create Daily Routines
* View Routines
* Update Routines
* Delete Routines
* Schedule Activities with Time Slots

### Dashboard

* Total Tasks Overview
* Completed Tasks Count
* Pending Tasks Count
* Total Routines Overview
* Productivity Completion Rate

## Tech Stack

### Frontend

* HTML5
* CSS3
* JavaScript (Vanilla JS)

### Backend

* FastAPI
* Python
* SQLAlchemy
* Pydantic

### Database

* MySQL

### Authentication

* JWT (JSON Web Tokens)
* Passlib (Bcrypt)

## Project Structure

```text
routine-hub/
│
├── backend/
│   ├── app/
│   │   ├── auth/
│   │   ├── core/
│   │   ├── database/
│   │   ├── models/
│   │   ├── routers/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── utils/
│   │
│   ├── main.py
│   ├── requirements.txt
│   └── .env
│
├── frontend/
│   ├── pages/
│   ├── css/
│   ├── js/
│   └── assets/
│
└── README.md
```

## Installation

### Clone Repository

```bash
git clone https://github.com/Lingarajgn/project_mini.git
cd project_mini
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

Windows:

```bash
venv\Scripts\activate
```

Linux/Mac:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Environment Variables

Create a `.env` file inside the backend directory.

```env
DATABASE_URL=mysql+pymysql://username:password@localhost/routinehub
SECRET_KEY=your_secret_key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

## Database Setup

1. Install MySQL.
2. Create a database:

```sql
CREATE DATABASE routinehub;
```

3. Update your `.env` file with database credentials.
4. Run migrations or create tables through SQLAlchemy.

## Running the Backend

```bash
uvicorn main:app --reload
```

Backend API:

```text
http://127.0.0.1:8000
```

Swagger Documentation:

```text
http://127.0.0.1:8000/docs
```

## Running the Frontend

Open the frontend folder and launch the HTML files using:

* VS Code Live Server
* Any local web server

Example:

```bash
http://127.0.0.1:5500
```

## API Endpoints

### Authentication

```http
POST /register
POST /login
```

### Tasks

```http
GET    /tasks
POST   /tasks
GET    /tasks/{id}
PUT    /tasks/{id}
DELETE /tasks/{id}
PATCH  /tasks/{id}/complete
```

### Routines

```http
GET    /routines
POST   /routines
GET    /routines/{id}
PUT    /routines/{id}
DELETE /routines/{id}
```

### Dashboard

```http
GET /dashboard
```

## Future Enhancements

* Habit Tracker
* Calendar Integration
* Pomodoro Timer
* Productivity Analytics
* AI Productivity Assistant
* ML-Based Productivity Prediction
* Burnout Detection
* Personalized Routine Recommendations
* Weekly Productivity Reports
* Achievement and Streak System

## Security Features

* Password Hashing with Bcrypt
* JWT Authentication
* Protected API Routes
* Input Validation
* User-Specific Data Access Control

## Author

**Lingaraj**

Routine Hub was developed as a full-stack productivity management project using FastAPI, MySQL, and Vanilla JavaScript, with future plans for Machine Learning-powered productivity analysis.

## License

This project is intended for educational and portfolio purposes.
