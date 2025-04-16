alembic revision --autogenerate -m "Initial migration" && alembic upgrade head && uvicorn app.main:app --reload
