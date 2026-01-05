import mongoose from 'mongoose';

const paymentSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['product', 'ad'], required: true },
    targetId: { type: mongoose.Schema.Types.ObjectId, required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'completed'], default: 'pending' },
    method: { type: String, enum: ['card', 'mobileMoney', 'paypal'], default: 'card' }
}, { timestamps: true });

export default mongoose.models.Payment || mongoose.model('Payment', paymentSchema);
