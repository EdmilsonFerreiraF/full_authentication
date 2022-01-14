import jwt from 'express-jwt';
import { Request, Response, NextFunction } from 'express'
import dotenv from 'dotenv'

import { accountModel, refreshTokenModel } from '../_helpers/db';
import { Role, toRole } from '../entities/Role'
import { RefreshTokenModel } from '../entities/RefreshTokenModel';

dotenv.config()

export function authorize(roles: Role[] | Role = []) {
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
            const user = req.body.user

            const account = await accountModel.findById(user?.id);
            const refreshTokens = await refreshTokenModel.find({ account: account?.id });

            if (!account || (roles.length && !roles.includes(toRole(account.role)))) {
                // account no longer exists or role not authorized
                return res.status(401).json({ message: 'Unauthorized' });
            }

            // authentication and authorization successful
            user.role = account.role
            user.ownsToken = (token: string) => !!refreshTokens.find((x: RefreshTokenModel) => x.token === token);
            next();
        }
    ];
}