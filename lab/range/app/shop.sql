-- The shop's one table, made in the database the spec plants on db.
CREATE TABLE items (
  id INT PRIMARY KEY,
  name VARCHAR(80) NOT NULL,
  price DECIMAL(8, 2) NOT NULL
);
INSERT INTO items VALUES
  (1, 'Blue mug', 9.50),
  (2, 'Fire poker', 24.00),
  (3, 'Nexus sticker', 1.25);
