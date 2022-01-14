import mongoose, { Schema } from 'mongoose';

const schema = new Schema({
    account: { type: Schema.Types.ObjectId, ref: 'Account' },
    token: String,
    expires: Date,
    created: { type: Date, default: Date.now },
    createdByIp: String,
    revoked: Date,
    revokedByIp: String,
    replacedByToken: String
});

schema.virtual('isExpired').get(function (this: mongoose.VirtualTypeOptions) {
    return Date.now() >= this.expires;
});

schema.virtual('isActive').get(function (this: mongoose.VirtualTypeOptions) {
    return !this.revoked && !this.isExpired;
});

export const refreshTokenModel = mongoose.model('RefreshToken', schema)