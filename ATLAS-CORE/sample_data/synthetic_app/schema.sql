-- SYNTHETIC schema
CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) NOT NULL, password_hash TEXT NOT NULL, full_name TEXT);
CREATE TABLE orders (id SERIAL PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id), total NUMERIC(10,2), status TEXT);
CREATE TABLE order_items (id SERIAL PRIMARY KEY, order_id INT NOT NULL, sku TEXT, qty INT,
  FOREIGN KEY (order_id) REFERENCES orders(id));
