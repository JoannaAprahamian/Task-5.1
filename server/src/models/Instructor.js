import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true, select: false }, // bcrypt hash
    department: { type: String },
    role: { type: String, default: 'instructor' },

    // Private fields: hidden from every query unless explicitly requested
    apiKey: { type: String, select: false },
    privateEmail: { type: String, select: false },
    privatePhone: { type: String, select: false }
  },
  { timestamps: true }
);

// Hash the password on save. Skipped if the password wasn't changed,
// so an existing hash is never hashed twice.
instructorSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
});

export const Instructor = mongoose.model('Instructor', instructorSchema);