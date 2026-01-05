import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const router = express.Router();

// -------------------- USER MODEL --------------------
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['buyer', 'seller'], default: 'buyer' }
}, { timestamps: true });

// Pre-save password hash
userSchema.pre('save', async function() {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
});

// Compare password
userSchema.methods.comparePassword = function(password) {
  return bcrypt.compare(password, this.password);
};

const User = mongoose.models.User || mongoose.model('User', userSchema);

// -------------------- SHOP MODEL --------------------
const shopSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  logo: { type: String, default: null }, // Base64 logo
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

const Shop = mongoose.models.Shop || mongoose.model('Shop', shopSchema);

// -------------------- PRODUCT MODEL --------------------
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  image: { type: String, default: null }, // Main product image
  badges: { type: [String], default: [] }, // Array of badge icons (Base64 or URLs)
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // optional for simple sellers
  shop: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', default: null }
}, { timestamps: true });

const Product = mongoose.models.Product || mongoose.model('Product', productSchema);

// -------------------- AD MODEL --------------------
const adSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', default: null },
  shop: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', default: null },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amountPaid: { type: Number, required: true },
  durationDays: { type: Number, required: true }
}, { timestamps: true });

const Ad = mongoose.models.Ad || mongoose.model('Ad', adSchema);

// -------------------- PAYMENT MODEL --------------------
const paymentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['ad', 'product'], required: true },
  targetId: { type: mongoose.Schema.Types.ObjectId, required: true },
  amount: { type: Number, required: true },
  method: { type: String, default: 'manual' },
  status: { type: String, enum: ['pending','completed','failed'], default: 'completed' }
}, { timestamps: true });

const Payment = mongoose.models.Payment || mongoose.model('Payment', paymentSchema);

// -------------------- AUTH MIDDLEWARE --------------------
export const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return next(); // allow unauthenticated users

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return next(); // allow if user not found

    req.user = user;
    next();
  } catch (err) {
    next(); // ignore token errors
  }
};

// -------------------- AUTH ROUTES --------------------
// REGISTER
router.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: 'Please provide all required fields' });

  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });

    const user = await User.create({ name, email, password, role });
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ token, user: { name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Please provide email and password' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// -------------------- SHOPS --------------------
router.post('/shops', authMiddleware, async (req, res) => {
  if (!req.user || req.user.role !== 'seller') return res.status(403).json({ message: 'Not a seller or unauthorized' });

  try {
    const { name, description, logo } = req.body;
    const shop = await Shop.create({ name, description, logo: logo || null, owner: req.user._id });
    res.json(shop);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

router.get('/shops', async (req, res) => {
  const shops = await Shop.find().populate('owner', 'name email');
  res.json(shops);
});

// -------------------- PRODUCTS --------------------
router.post('/products', authMiddleware, async (req, res) => {
  try {
    const { name, description, price, image, badges, shopId } = req.body;

    const sellerId = req.user?._id || null; // optional if not logged in
    const product = await Product.create({
      name,
      description,
      price,
      image: image || null,
      badges: badges || [], // array of badge images/icons
      seller: sellerId,
      shop: shopId || null
    });

    res.json(product);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

router.get('/products', async (req, res) => {
  const products = await Product.find()
    .populate('seller', 'name email')
    .populate('shop', 'name logo'); // return shop logo too
  res.json(products);
});

// -------------------- ADS --------------------
router.post('/ads', authMiddleware, async (req, res) => {
  if (!req.user || req.user.role !== 'seller') return res.status(403).json({ message: 'Not a seller' });

  try {
    const { productId, shopId, amountPaid, durationDays } = req.body;
    const ad = await Ad.create({
      product: productId || null,
      shop: shopId || null,
      seller: req.user._id,
      amountPaid,
      durationDays
    });

    await Payment.create({
      user: req.user._id,
      type: 'ad',
      targetId: ad._id,
      amount: amountPaid,
      status: 'completed'
    });

    res.json(ad);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// -------------------- PAYMENTS --------------------
router.post('/payments', authMiddleware, async (req, res) => {
  try {
    const { type, targetId, amount, method } = req.body;
    const userId = req.user?._id || null; // optional for simple sellers
    if (!userId) return res.status(400).json({ message: 'User ID required for payment' });

    const payment = await Payment.create({
      user: userId,
      type, targetId, amount, method, status: 'completed'
    });

    res.json(payment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

export default router;
