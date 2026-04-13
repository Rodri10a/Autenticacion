CREATE DATABASE devlearn_hub;

\c devlearn_hub

CREATE TABLE topics (
  id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  votes INTEGER DEFAULT 0
);

CREATE TABLE links (
  id SERIAL PRIMARY KEY,
  topic_id INTEGER REFERENCES topics(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  url TEXT NOT NULL,
  votes INTEGER DEFAULT 0
);

INSERT INTO topics (title, description, votes) VALUES
  ('JavaScript', 'Lenguaje de programacion de la web', 7),
  ('Node.js', 'JavaScript del lado del servidor', 4),
  ('Python', 'Lenguaje versatil para backend y data science', 1);

INSERT INTO links (topic_id, title, url, votes) VALUES
  (1, 'MDN Web Docs', 'https://developer.mozilla.org', 3),
  (1, 'JavaScript.info', 'https://javascript.info', 5),
  (2, 'Documentacion oficial', 'https://nodejs.org/docs', 2);
