import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const router = express.Router();

/* =======================
   ENV VALIDATION
======================= */
if (!process.env.JWT_SECRET) {
  console.warn('⚠️ JWT_SECRET is missing in environment variables. Auth routes may fail.');
  // process.exit(1); // optional: comment out so server still runs
}

/* =======================
   USER MODEL
======================= */
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['buyer', 'seller'], default: 'buyer' }
}, { timestamps: true });

userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.comparePassword = function (password) {
  return bcrypt.compare(password, this.password);
};

const User = mongoose.models.User || mongoose.model('User', userSchema);

/* =======================
   SHOP MODEL
======================= */
const shopSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  logo: { type: String, default: null },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

const Shop = mongoose.models.Shop || mongoose.model('Shop', shopSchema);

/* =======================
   PRODUCT MODEL
======================= */
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  price: { type: Number, required: true },
  image: { type: String, default: null },
  badges: { type: [String], default: [] },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  shop: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', default: null }
}, { timestamps: true });

const Product = mongoose.models.Product || mongoose.model('Product', productSchema);

/* =======================
   AUTH MIDDLEWARE
======================= */
const authRequired = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ message: 'Invalid token' });

    req.user = user;
    next();
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: 'Token invalid or expired' });
  }
};

/* =======================
   AUTH ROUTES
======================= */
router.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ message: 'All fields required' });

  try {
    if (await User.findOne({ email }))
      return res.status(400).json({ message: 'Email already exists' });

    const user = await User.create({ name, email, password, role });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: { name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Registration failed' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password)))
      return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: { name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Login failed' });
  }
});

/* =======================
   SHOPS
======================= */
router.post('/shops', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'seller')
      return res.status(403).json({ message: 'Seller only' });

    const shop = await Shop.create({
      ...req.body,
      owner: req.user._id
    });

    res.json(shop);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Shop creation failed' });
  }
});

router.get('/shops', async (_, res) => {
  try {
    const shops = await Shop.find().populate('owner', 'name email');
    res.json(shops);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch shops' });
  }
});

/* =======================
   PRODUCTS
======================= */
router.post('/products', authRequired, async (req, res) => {
  try {
    if (!req.user)
      return res.status(401).json({ message: 'Unauthorized' });

    const { name, price } = req.body;
    if (!name || !price)
      return res.status(400).json({ message: 'Product name and price are required' });

    const product = await Product.create({
      ...req.body,
      seller: req.user._id
    });

    res.json(product);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Product creation failed' });
  }
});

router.get('/products', async (_, res) => {
  try {
    const products = await Product.find()
      .populate('seller', 'name')
      .populate('shop', 'name logo');
    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch products' });
  }
});

export default router;
