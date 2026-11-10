# Centralized Travel Analytics and Decision Support System

A FastAPI + PostgreSQL + Power BI system that consolidates ticket, hotel and ancillary booking exports from kaggle into one governed warehouse with interactive dashboards. Built as my final project for the Professional Master's in Information Technology, Miva Open University.

> All data used is synthetic (29,929 structured records).

## Features
- Secured upload portal: JWT authentication, TOTP two-factor login, audit logging
- Pandas ETL: auto-detects ticket/hotel/ancillary files, cleans data, rejects duplicates, loads in atomic 5,000-row batches
- PostgreSQL schema: unified bookings table, 16 indexes, 2 reporting views
- Power BI model with 21 DAX measures and 3 report pages

## Files
- `main.py`: FastAPI portal and ETL pipeline
- `database_schema.sql`: PostgreSQL schema and views


## Setup
1. Install PostgreSQL and create a database named `travel_analytics`.
2. Run `database_schema.sql` against it.
3. `pip install -r requirements.txt`
4. Set the environment variable `JWT_SECRET_KEY` to a long random string, and fill in your database details in `DB_CONFIG` in `main.py`.
5. Start the app: `uvicorn main:app --reload`

## Known limitations
Built as a demonstration. For production: stronger password hashing (bcrypt/Argon2), restricted CORS, vaulted secrets, and removal of the debug endpoint.

## Author
Tunde Akinseye
