import jwt from 'express-jwt';
import { Request, Response, NextFunction } from 'express'
import dotenv from 'dotenv'

import { accountModel, refreshTokenModel } from '../_helpers/db';
import { Role, toRole } from '../entities/Role'
import { RefreshTokenModel } from '../entities/RefreshTokenModel';
import { IUser } from 'entities/User';

dotenv.config()

export function authorize(roles: Role[] = []) {
    // roles param can be a single role string (e.g. Role.User or 'User') 
    // or an array of roles (e.g. [Role.Admin, Role.User] or ['Admin', 'User'])
    if (typeof roles === 'string') {
        roles = [roles];
    }
    
    return [
        // authenticate JWT token and attach user to request object (req.user)
        jwt({ secret: process.env.secret as string, algorithms: ['HS256'] }),

        // authorize based on user role
        async (req: Request, res: Response, next: NextFunction) => {
            const user: IUser = req.user as IUser

            const account = await accountModel.findById(user?.id);
            const refreshTokens = await refreshTokenModel.find({ account: account?.id });

            console.log('account', account)
            console.log('roles[0]', roles[0])
            console.log('account?.role', account?.role)
            console.log('roles.length', roles.length)
            console.log('roles.length', roles.length)
            console.log('toRole(account?.role as string)', toRole(account?.role as string))
            console.log('roles.includes(toRole(account.role))', roles.includes(toRole(account?.role as string)))
            if (!account || (roles.length && !roles.includes(toRole(account.role as string)))) {
                // account no longer exists or role not authorized
                return res.status(401).json({ message: 'Unauthorized' });
            }

            // authentication and authorization successful
            user.role = toRole(account.role)
            user.ownsToken = (token: string) => !!refreshTokens.find((x: RefreshTokenModel) => x.token === token);
            next();
        }
    ];
}