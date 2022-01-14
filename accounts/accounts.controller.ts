import express, { Request, Response, NextFunction } from 'express'
import Joi from 'joi'

import { 
    serviceAuthenticate,
    serviceRefreshToken,
    serviceRevokeToken,
    serviceRegister,
    serviceVerifyEmail,
    serviceForgotPassword,
    serviceValidateResetToken,
    serviceResetPassword,
    serviceGetAll,
    serviceGetById,
    serviceCreate,
    serviceUpdate,
    serviceDelete
 } from './account.service'
import { RefreshTokenModel } from '../entities/RefreshTokenModel'
import { Role } from '../entities/Role'
import { validateRequest } from '../_middleware/validate-request'
import { authorize } from '../_middleware/authorize'
import { IUser } from 'entities/User'

export const router = express.Router()

// routes
router.post('/authenticate', authenticateSchema, authenticate);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', authorize(), revokeTokenSchema, revokeToken);
router.post('/register', registerSchema, register);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post('/validate-reset-token', validateResetTokenSchema, validateResetToken);
router.post('/reset-password', resetPasswordSchema, resetPassword);

const adminRole = [
    Role.ADMIN
]

router.get('/', authorize(adminRole), getAll);
router.get('/:id', authorize(), getById);
router.post('/', authorize(adminRole), createSchema, create);
router.put('/:id', authorize(), updateSchema, update);
router.delete('/:id', authorize(), _delete);

function authenticateSchema(req: Request, _: any, next: NextFunction) {
    const schema = Joi.object({
        email: Joi.string().required(),
        password: Joi.string().required()
    });

    validateRequest(req, next, schema);
}

function authenticate(req: Request, res: Response, next: NextFunction) {
    const { email, password } = req.body;
    const ipAddress = req.ip;

    serviceAuthenticate({ email, password, ipAddress })
        .then(({ refreshToken, ...account }: any) => {
            setTokenCookie(res, refreshToken);
            res.json(account);
        })
        .catch(next);
}

function refreshToken(req: Request, res: Response, next: NextFunction) {
    const token = req.cookies.refreshToken;
    const ipAddress = req.ip;

    serviceRefreshToken({ token, ipAddress })
        .then(({ refreshToken, ...account }: any) => {
            setTokenCookie(res, refreshToken);
            res.json(account);
        })
        .catch(next);
}

function revokeTokenSchema(req: Request, _: any, next: NextFunction) {
    const schema = Joi.object({
        token: Joi.string().empty('')
    });

    validateRequest(req, next, schema);
}

function revokeToken(req: Request, res: Response, next: NextFunction) {
    // accept token from request body or cookie
    const token = req.body.token || req.cookies.refreshToken;
    const ipAddress = req.ip;

    if (!token) return res.status(400).json({ message: 'Token is required' });

    const user: IUser = req.user as IUser
    // users can revoke their own tokens and admins can revoke any tokens

    if (!user?.ownsToken(token) && user?.role !== Role.ADMIN) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    serviceRevokeToken({ token, ipAddress })
        .then(() => res.json({ message: 'Token revoked' }))
        .catch(next);
}

function registerSchema(req: Request, _: any, next: NextFunction) {
    const schema = Joi.object({
        title: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        acceptTerms: Joi.boolean().valid(true).required()
    });

    validateRequest(req, next, schema);
}

function register(req: Request, res: Response, next: NextFunction) {
    serviceRegister(req.body, req.get('origin') as string)
        .then(() => res.json({ message: 'Registration successful, please check your email for verification instructions' }))
        .catch(next);
}

function verifyEmailSchema(req: Request, _: any, next: NextFunction) {
    const schema = Joi.object({
        token: Joi.string().required()
    });

    validateRequest(req, next, schema);
}

function verifyEmail(req: Request, res: Response, next: NextFunction) {
    serviceVerifyEmail(req.body)
        .then(() => res.json({ message: 'Verification successful, you can now login' }))
        .catch(next);
}

function forgotPasswordSchema(req: Request, _: any, next: NextFunction) {
    const schema = Joi.object({
        email: Joi.string().email().required()
    });

    validateRequest(req, next, schema);
}

function forgotPassword(req: Request, res: Response, next: NextFunction) {
    serviceForgotPassword(req.body, req.get('origin') as string)
        .then(() => res.json({ message: 'Please check your email for password reset instructions' }))
        .catch(next);
}

function validateResetTokenSchema(req: Request, _: any, next: NextFunction) {
    const schema = Joi.object({
        token: Joi.string().required()
    });

    validateRequest(req, next, schema);
}

function validateResetToken(req: Request, res: Response, next: NextFunction) {
    serviceValidateResetToken(req.body)
        .then(() => res.json({ message: 'Token is valid' }))
        .catch(next);
}

function resetPasswordSchema(req: Request, _: any, next: NextFunction) {
    const schema = Joi.object({
        token: Joi.string().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required()
    });

    validateRequest(req, next, schema);
}

function resetPassword(req: Request, res: Response, next: NextFunction) {
    serviceResetPassword(req.body)
        .then(() => res.json({ message: 'Password reset successful, you can now login' }))
        .catch(next);
}

function getAll(_: Request, res: Response, next: NextFunction) {
    serviceGetAll()
        .then((accounts: any) => res.json(accounts))
        .catch(next);
}

function getById(req: Request, res: Response, next: NextFunction) {
    // users can get their own account and admins can get any account
    const user: IUser = req.user as IUser

    if (req.params.id !== user?.id && user?.role !== Role.ADMIN) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    serviceGetById(req.params.id)
        .then((account: any) => account ? res.json(account) : res.sendStatus(404))
        .catch(next);
}

function createSchema(req: Request, _: any, next: NextFunction) {
    const schema = Joi.object({
        title: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        role: Joi.string().valid(Role.ADMIN, Role.USER).required()
    });

    validateRequest(req, next, schema);
}

function create(req: Request, res: Response, next: NextFunction) {
    serviceCreate(req.body)
        .then((account: any) => res.json(account))
        .catch(next);
}

function updateSchema(req: Request, _: any, next: NextFunction) {
    const schemaRules: any = {
        title: Joi.string().empty(''),
        firstName: Joi.string().empty(''),
        lastName: Joi.string().empty(''),
        email: Joi.string().email().empty(''),
        password: Joi.string().min(6).empty(''),
        confirmPassword: Joi.string().valid(Joi.ref('password')).empty('')
    };

    const user = req.body.user

    // only admins can update role
    if (user.role === Role.ADMIN) {
        schemaRules.role = Joi.string().valid(Role.ADMIN, Role.USER).empty('');
    }

    const schema = Joi.object(schemaRules).with('password', 'confirmPassword');

    validateRequest(req, next, schema);
}

function update(req: Request, res: Response, next: NextFunction) {
    const user = req.body.user

    // users can update their own account and admins can update any account
    if (req.params.id !== user?.id && user?.role !== Role.ADMIN) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    serviceUpdate(req.params.id, req.body)
        .then((account: any) => res.json(account))
        .catch(next);
}

function _delete(req: Request, res: Response, next: NextFunction) {
    const user = req.body.user

    // users can delete their own account and admins can delete any account
    if (req.params.id !== user?.id && user?.role !== Role.ADMIN) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    serviceDelete(req.params.id)
        .then(() => res.json({ message: 'Account deleted successfully' }))
        .catch(next);
}

// helper functions

function setTokenCookie(res: Response, token: RefreshTokenModel) {
    // create cookie with refresh token that expires in 7 days
    const cookieOptions = {
        httpOnly: true,
        expires: new Date(Date.now() + 7*24*60*60*1000)
    };

    res.cookie('refreshToken', token, cookieOptions);
}