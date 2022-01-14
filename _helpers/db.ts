import mongoose from 'mongoose'
import dotenv from 'dotenv'

import { accountModel } from '../accounts/account.model'
import { refreshTokenModel } from '../accounts/refresh-token.model'

dotenv.config()

const connectionOptions = { useCreateIndex: true, useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false };

mongoose.connect(process.env.MONGODB_URI || process.env.CONNECTION_STRING as string, connectionOptions);
mongoose.Promise = global.Promise;

export function isValidId(id: string): boolean {
    return mongoose.Types.ObjectId.isValid(id);
}

export  { accountModel }
export { refreshTokenModel }