import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import routes from './routes.js';

dotenv.config();
const app = express();

// -------------------- MIDDLEWARES --------------------
// Enable CORS
app.use(cors());

// Increase JSON & URL-encoded payload limits (for large images)
app.use(express.json({ limit: '10mb' }));       // for JSON requests
app.use(express.urlencoded({ extended: true, limit: '10mb' })); // for form data

// Simple logger middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// -------------------- ROUTES --------------------
app.use('/api', routes);

// -------------------- MONGODB CONNECTION --------------------
const PORT = process.env.PORT || 5000;

mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ MongoDB connected');
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  })
  .catch(err => console.error('❌ MongoDB connection error:', err));
