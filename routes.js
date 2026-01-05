import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const router = express.Router();

/* =======================
   ENV VALIDATION
======================= */
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET is missing in environment variables');
  process.exit(1);
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
   AD MODEL
======================= */
const adSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  shop: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop' },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amountPaid: Number,
  durationDays: Number
}, { timestamps: true });

const Ad = mongoose.models.Ad || mongoose.model('Ad', adSchema);

/* =======================
   PAYMENT MODEL
======================= */
const paymentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['ad', 'product'], required: true },
  targetId: mongoose.Schema.Types.ObjectId,
  amount: Number,
  method: { type: String, default: 'manual' },
  status: { type: String, default: 'completed' }
}, { timestamps: true });

const Payment = mongoose.models.Payment || mongoose.model('Payment', paymentSchema);

/* =======================
   AUTH MIDDLEWARES
======================= */

// REQUIRED AUTH
const authRequired = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ message: 'Invalid token' });

    req.user = user;
    next();
  } catch {
    res.status(401).json({ message: 'Token invalid or expired' });
  }
};

/* =======================
   AUTH ROUTES
======================= */

// REGISTER
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

// LOGIN
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
  if (req.user.role !== 'seller')
    return res.status(403).json({ message: 'Seller only' });

  const shop = await Shop.create({
    ...req.body,
    owner: req.user._id
  });

  res.json(shop);
});

router.get('/shops', async (_, res) => {
  res.json(await Shop.find().populate('owner', 'name email'));
});

/* =======================
   PRODUCTS
======================= */
router.post('/products', authRequired, async (req, res) => {
  const product = await Product.create({
    ...req.body,
    seller: req.user._id
  });
  res.json(product);
});

router.get('/products', async (_, res) => {
  res.json(
    await Product.find()
      .populate('seller', 'name')
      .populate('shop', 'name logo')
  );
});

export default router;
