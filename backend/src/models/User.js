// User model — stores credentials and account status
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    // Identity health: normal | at_risk | compromised
    identityStatus: {
      type: String,
      enum: ['normal', 'at_risk', 'compromised'],
      default: 'normal',
    },
    // Auto-healing flags
    sessionTerminated: { type: Boolean, default: false },
    forcePasswordReset: { type: Boolean, default: false },
    isBlocked: { type: Boolean, default: false },

    // Known trusted devices (user-agent strings)
    knownDevices: [{ type: String }],
  },
  { timestamps: true }
);

// Hash password before saving
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare plaintext password to hash
UserSchema.methods.comparePassword = async function (plaintext) {
  return bcrypt.compare(plaintext, this.password);
};

module.exports = mongoose.model('User', UserSchema);
