import mongoose from 'mongoose';

const shopSchema = new mongoose.Schema({
    name: { type: String, required: true },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    description: { type: String },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

export default mongoose.models.Shop || mongoose.model('Shop', shopSchema);
