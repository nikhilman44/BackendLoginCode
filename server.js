// server.js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./database');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5001;
const SECRET_KEY = 'testy_kitchen_key'; 

app.use(cors());
app.use(bodyParser.json());

// Register endpoint
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  const hashedPassword = bcrypt.hashSync(password, 8);
  
  const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
  db.run(query, [username, hashedPassword], function(err) {
    if (err) {
      return res.status(500).send('User already exists');
    }
    const token = jwt.sign({ id: this.lastID }, SECRET_KEY, { expiresIn: '30h' });
    res.status(201).send({ auth: true, token });
  });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  const query = `SELECT * FROM users WHERE username = ?`;
  db.get(query, [username], (err, user) => {
    if (err || !user) {
      return res.status(404).send('User not found');
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send('Invalid password');
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '30h' });
    res.status(200).send({ auth: true, token });
  });
});

// Protected route example
app.get('/me', async (req, res) => {
    const query = `SELECT * FROM users`;
    const myData = await db.get(query)
    res.send(myData);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
