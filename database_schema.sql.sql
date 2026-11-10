-- ============================================================
-- ULTIMATE SCALABLE TRAVEL ANALYTICS DATABASE
-- Handles: Trillions in value, unlimited text, millions of rows
-- ============================================================

-- Drop everything and start fresh
DROP VIEW IF EXISTS vw_unified_bookings CASCADE;
DROP VIEW IF EXISTS vw_dashboard_summary CASCADE;
DROP TABLE IF EXISTS unified_bookings CASCADE;
DROP TABLE IF EXISTS uploads CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Users table
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(500) NOT NULL,
    department VARCHAR(200) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Uploads tracking
CREATE TABLE uploads (
    upload_id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    file_name VARCHAR(500) NOT NULL,
    source_type VARCHAR(50) NOT NULL CHECK (source_type IN ('ticket', 'hotel', 'ancillary')),
    record_count BIGINT,
    file_size_bytes BIGINT,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'success',
    error_message TEXT
);

-- UNIFIED TABLE: Optimized for millions of rows
CREATE TABLE unified_bookings (
    -- Primary key using BIGSERIAL for scalability (up to 9 quintillion rows)
    booking_id BIGSERIAL PRIMARY KEY,
    
    -- Foreign key to upload batch
    upload_id BIGINT REFERENCES uploads(upload_id),
    
    -- Source discriminator
    source_type VARCHAR(50) NOT NULL CHECK (source_type IN ('ticket', 'hotel', 'ancillary')),
    
    -- Dates with auto-generated year/month/quarter for fast filtering
    booking_date DATE,
    booking_year INTEGER GENERATED ALWAYS AS (EXTRACT(YEAR FROM booking_date)) STORED,
    booking_month INTEGER GENERATED ALWAYS AS (EXTRACT(MONTH FROM booking_date)) STORED,
    booking_quarter INTEGER GENERATED ALWAYS AS (EXTRACT(QUARTER FROM booking_date)) STORED,
    
    -- Document/Transaction IDs
    doc_no VARCHAR(100),
    
    -- Client Information (VARCHAR(500) for long names)
    client_name VARCHAR(500),
    client_type VARCHAR(500),
    department VARCHAR(200),
    
    -- Passenger/Guest
    passenger_name VARCHAR(500),
    
    -- Currency & Quantity
    currency VARCHAR(20) DEFAULT 'NGN',
    quantity BIGINT DEFAULT 1,
    
    -- Financial Fields: DECIMAL(20,4) = up to 99,999,999,999,999.9999 (99 TRILLION)
    total_revenue DECIMAL(20,4),
    cost DECIMAL(20,4),
    profit DECIMAL(20,4),
    service_fee DECIMAL(20,4),
    commission DECIMAL(20,4),
    tax_amount DECIMAL(20,4),
    
    -- Supplier & Agent
    supplier_name VARCHAR(500),
    agent_name VARCHAR(500),
    
    -- Remarks (TEXT = unlimited length)
    remarks TEXT,
    
    -- TICKET-SPECIFIC FIELDS
    ticket_number VARCHAR(100),
    pnr_number VARCHAR(50),
    airline VARCHAR(300),
    airline_code VARCHAR(20),
    route VARCHAR(300),
    destination VARCHAR(300),
    destination_code VARCHAR(50),
    sector_code VARCHAR(50),
    route_type VARCHAR(50),
    travel_date DATE,
    departure_date DATE,
    return_date DATE,
    class_type VARCHAR(100),
    return_class VARCHAR(100),
    tour_code VARCHAR(100),
    fare_basis VARCHAR(100),
    booking_source VARCHAR(200),
    published_fare DECIMAL(20,4),
    original_fare DECIMAL(20,4),
    lowest_fare_offered DECIMAL(20,4),
    fare_lost_amount DECIMAL(20,4),
    departure_time VARCHAR(50),
    arrival_time VARCHAR(50),
    extra_earning DECIMAL(20,4),
    iata_insurance_payable DECIMAL(20,4),
    iata_insurance_collected DECIMAL(20,4),
    discount_given DECIMAL(20,4),
    billing_tax DECIMAL(20,4),
    cc_charges_collected DECIMAL(20,4),
    sharing_amount DECIMAL(20,4),
    debited_amount DECIMAL(20,4),
    glpo_commission DECIMAL(20,4),
    adm_acm VARCHAR(100),
    carbon_emission_value VARCHAR(200),
    reference VARCHAR(500),
    narration TEXT,
    frequent_flyer_no VARCHAR(200),
    corporate_airline_deals VARCHAR(500),
    
    -- HOTEL-SPECIFIC FIELDS
    hotel_name VARCHAR(500),
    hotel_city VARCHAR(200),
    hotel_country VARCHAR(200),
    start_date DATE,
    end_date DATE,
    no_of_nights BIGINT,
    no_of_rooms BIGINT,
    voucher_no VARCHAR(100),
    
    -- ANCILLARY-SPECIFIC FIELDS
    service_name VARCHAR(500),
    from_date DATE,
    to_date DATE,
    lpo_no VARCHAR(100),
    particulars TEXT,
    
    -- Metadata & Audit
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_valid BOOLEAN DEFAULT TRUE,
    validation_errors TEXT
);

-- INDEXES FOR PERFORMANCE (Critical for millions of rows)
CREATE INDEX idx_bookings_source_type ON unified_bookings(source_type);
CREATE INDEX idx_bookings_booking_date ON unified_bookings(booking_date);
CREATE INDEX idx_bookings_client_name ON unified_bookings(client_name);
CREATE INDEX idx_bookings_department ON unified_bookings(department);
CREATE INDEX idx_bookings_year ON unified_bookings(booking_year);
CREATE INDEX idx_bookings_month ON unified_bookings(booking_month);
CREATE INDEX idx_bookings_quarter ON unified_bookings(booking_quarter);
CREATE INDEX idx_bookings_source_date ON unified_bookings(source_type, booking_date);
CREATE INDEX idx_bookings_client_date ON unified_bookings(client_name, booking_date);
CREATE INDEX idx_bookings_dept_date ON unified_bookings(department, booking_date);
CREATE INDEX idx_bookings_route ON unified_bookings(route);
CREATE INDEX idx_bookings_destination ON unified_bookings(destination);
CREATE INDEX idx_bookings_airline ON unified_bookings(airline);
CREATE INDEX idx_bookings_revenue ON unified_bookings(total_revenue) WHERE total_revenue > 0;
CREATE INDEX idx_bookings_profit ON unified_bookings(profit);
CREATE INDEX idx_bookings_upload ON unified_bookings(upload_id);

-- OPTIMIZED VIEW FOR POWER BI
CREATE VIEW vw_unified_bookings AS
SELECT 
    booking_id,
    source_type,
    booking_date,
    booking_year AS year,
    booking_month AS month,
    CASE booking_month
        WHEN 1 THEN 'January' WHEN 2 THEN 'February' WHEN 3 THEN 'March'
        WHEN 4 THEN 'April' WHEN 5 THEN 'May' WHEN 6 THEN 'June'
        WHEN 7 THEN 'July' WHEN 8 THEN 'August' WHEN 9 THEN 'September'
        WHEN 10 THEN 'October' WHEN 11 THEN 'November' WHEN 12 THEN 'December'
    END AS month_name,
    booking_quarter AS quarter,
    CONCAT('Q', booking_quarter) AS quarter_label,
    doc_no,
    client_name,
    client_type,
    department,
    passenger_name,
    currency,
    quantity,
    total_revenue,
    cost,
    profit,
    service_fee,
    commission,
    tax_amount,
    supplier_name,
    agent_name,
    remarks,
    ticket_number,
    pnr_number,
    airline,
    airline_code,
    route,
    destination,
    destination_code,
    sector_code,
    route_type,
    travel_date,
    departure_date,
    return_date,
    class_type,
    return_class,
    tour_code,
    fare_basis,
    booking_source,
    published_fare,
    original_fare,
    lowest_fare_offered,
    fare_lost_amount,
    departure_time,
    arrival_time,
    extra_earning,
    iata_insurance_payable,
    iata_insurance_collected,
    discount_given,
    billing_tax,
    cc_charges_collected,
    sharing_amount,
    debited_amount,
    glpo_commission,
    adm_acm,
    carbon_emission_value,
    reference,
    narration,
    frequent_flyer_no,
    corporate_airline_deals,
    hotel_name,
    hotel_city,
    hotel_country,
    start_date,
    end_date,
    no_of_nights,
    no_of_rooms,
    voucher_no,
    service_name,
    from_date,
    to_date,
    lpo_no,
    particulars,
    created_at
FROM unified_bookings;

-- AGGREGATE VIEW FOR FAST DASHBOARD SUMMARIES
CREATE VIEW vw_dashboard_summary AS
SELECT 
    source_type,
    booking_year,
    booking_month,
    booking_quarter,
    department,
    client_name,
    COUNT(*) AS transaction_count,
    SUM(quantity) AS total_quantity,
    SUM(total_revenue) AS total_revenue,
    SUM(cost) AS total_cost,
    SUM(profit) AS total_profit,
    SUM(commission) AS total_commission,
    AVG(total_revenue) AS avg_revenue,
    AVG(profit) AS avg_profit
FROM unified_bookings
GROUP BY source_type, booking_year, booking_month, booking_quarter, department, client_name;



-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
