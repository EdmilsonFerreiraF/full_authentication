import { Schema } from "mongoose";

export type RefreshTokenModel = {
    account: Schema.Types.ObjectId,
    token: string,
    expires: Date,
    created: Date,
    createdByIp: string,
    revoked: Date,
    revokedByIp: string,
    replacedByToken: string,
}