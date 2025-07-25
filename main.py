// index.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// —— CONFIG ——
const { MONGO_URI, JWT_SECRET, PORT = 3000 } = process.env;

// —— DB SETUP ——
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// —— SCHEMAS ——
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  hash:     { type: String, required: true }
});
const productSchema = new mongoose.Schema({
  name:     String,
  sku:      { type: String, unique: true },
  quantity: Number,
  price:    Number
});

const User    = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);

// —— MIDDLEWARE ——
const auth = async (req, res, next) => {
  const authHdr = req.headers.authorization;
  if (!authHdr) return res.status(401).json({ error: 'Missing token' });
  const token = authHdr.split(' ')[1];
  try {
    const { username } = jwt.verify(token, JWT_SECRET);
    req.user = await User.findOne({ username });
    if (!req.user) throw new Error();
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// —— ROUTES ——

/** POST /register
 *  { username, password }
 */
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 10;
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    await User.create({ username, hash });
    res.status(201).json({ msg: 'User created' });
  } catch (e) {
    res.status(400).json({ error: 'Username taken' });
  }
});

/** POST /login
 *  { username, password }
 */
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: 'Bad credentials' });

  const ok = await bcrypt.compare(password, user.hash);
  if (!ok) return res.status(401).json({ error: 'Bad credentials' });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30m' });
  res.json({ access_token: token });
});

/** POST /products
 *  { name, sku, quantity, price }
 */
app.post('/products', auth, async (req, res) => {
  try {
    const prod = await Product.create(req.body);
    res.status(201).json({ id: prod._id });
  } catch (e) {
    res.status(400).json({ error: 'Invalid product data' });
  }
});

/** PUT /products/:id/quantity
 *  { quantity }
 */
app.put('/products/:id/quantity', auth, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  const prod = await Product.findByIdAndUpdate(id, { quantity }, { new: true });
  if (!prod) return res.status(404).json({ error: 'Not found' });
  res.json({ id: prod._id, quantity: prod.quantity });
});

/** GET /products?skip=0&limit=10 */
app.get('/products', auth, async (req, res) => {
  const skip = parseInt(req.query.skip) || 0;
  const limit = parseInt(req.query.limit) || 10;
  const prods = await Product.find().skip(skip).limit(limit);
  res.json(prods.map(p => ({
    id: p._id, name: p.name, sku: p.sku,
    quantity: p.quantity, price: p.price
  })));
});

// —— START ——
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
