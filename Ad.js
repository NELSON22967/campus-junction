import mongoose from 'mongoose';

const adSchema = new mongoose.Schema({
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    shop: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop' },
    seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amountPaid: { type: Number, required: true },
    durationDays: { type: Number, default: 7 },
    startDate: { type: Date, default: Date.now }
}, { timestamps: true });

export default mongoose.model('Ad', adSchema);
