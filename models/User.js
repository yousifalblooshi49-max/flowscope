'use strict';

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username:        { type: String, required: true, unique: true, trim: true },
  email:           { type: String, default: null, trim: true },
  passwordHash:    { type: String, required: true },
  isAdmin:         { type: Boolean, default: false },
  hasSubscription: { type: Boolean, default: false },
  plan:            { type: String, default: null },
  trialUsed:       { type: Boolean, default: false },
  trialStartedAt:  { type: Date, default: null },
  trialEndsAt:     { type: Date, default: null },
  createdAt:       { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
