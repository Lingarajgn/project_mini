# Routine Hub database migration notes

## 1. Create the schema
Run the backend once so SQLAlchemy can create the tables from the models:

```bash
cd backend
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

The startup hook in `main.py` calls `Base.metadata.create_all(bind=engine)`, which will create the `users`, `tasks`, and `routines` tables.

## 2. For real migrations (recommended)
If you want versioned migrations, install Alembic and initialize it:

```bash
pip install alembic
alembic init alembic
```

Then generate and apply migrations:

```bash
alembic revision --autogenerate -m "add routine hub models"
alembic upgrade head
```

## 3. Relationship summary
- One `User` can have many `Task` records.
- One `User` can have many `Routine` records.
- `Task.user_id` and `Routine.user_id` are foreign keys to `users.id`.
- `cascade="all, delete-orphan"` means deleting a user also removes their tasks and routines.
