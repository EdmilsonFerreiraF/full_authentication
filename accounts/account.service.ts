import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import crypto from "crypto"
import { Request } from 'express'
import dotenv from 'dotenv'

import { accountModel } from './account.model'
import { refreshTokenModel } from './refresh-token.model'
import { sendEmail } from '../_helpers/send-email'
import { isValidId } from '../_helpers/db'
import { Account } from '../entities/Account'
import { RefreshTokenModel } from '../entities/RefreshTokenModel'
import { toRole } from '../entities/Role'
import { IMailerOptions } from '../entities/Mailer'

dotenv.config()

export async function serviceAuthenticate({ email, password, ipAddress }: {email: string, password: string, ipAddress: string}) {
    const account: Account | null = await accountModel.findOne({ email });

    if (!account || !account.isVerified || !bcrypt.compareSync(password, account.passwordHash as string)) {
        throw 'Email or password is incorrect';
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = serviceGenerateJwtToken(account);
    const refreshToken: any = serviceGenerateRefreshToken(account, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...serviceBasicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

export async function serviceRefreshToken({ token, ipAddress }: { token: RefreshTokenModel, ipAddress: string }){
    const refreshToken = await serviceGetRefreshToken(token);

    const { account } = refreshToken;

    // replace old refresh token with a new one and save
    const newRefreshToken: any = serviceGenerateRefreshToken(account, ipAddress);

    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;

    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken = serviceGenerateJwtToken(account);

    // return basic details and tokens
    return {
        ...serviceBasicDetails(account),
        jwtToken,
        refreshToken: newRefreshToken.token
    };
}

export async function serviceRevokeToken({ token, ipAddress }: { token: RefreshTokenModel, ipAddress: string }) {
    const refreshToken = await serviceGetRefreshToken(token);

    // revoke token and save
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;

    await refreshToken.save();
}

export async function serviceRegister(params: any, origin: string) {
    // validate
    if (await accountModel.findOne({ email: params.email })) {
        // send already registered error in email to prevent account enumeration
        return await serviceSendAlreadyRegisteredEmail(params.email, origin);
    }

    // create account object
    const account = new accountModel(params);

    // first registered account is an admin
    const isFirstAccount = (await accountModel.countDocuments({})) === 0;

    account.role = isFirstAccount ? toRole("ADMIN") : toRole("USER");
    account.verificationToken = serviceRandomTokenString();

    // hash password
    account.passwordHash = serviceHash(params.password);

    // save account
    await account.save();

    // send email
    await serviceSendVerificationEmail(account, origin);
}

export async function serviceVerifyEmail({ token }: { token: RefreshTokenModel }) {
    const account = await accountModel.findOne({ verificationToken: token as any });

    if (!account) throw 'Verification failed';

    account.verified = Date.now();
    account.verificationToken = undefined;

    await account.save();
}

export async function serviceForgotPassword({ email }: {email: string}, origin: string){
    const account = await accountModel.findOne({ email });

    // always return ok response to prevent email enumeration
    if (!account) return;

    // create reset token that expires after 24 hours
    account.resetToken = {
        token: serviceRandomTokenString(),
        expires: new Date(Date.now() + 24*60*60*1000)
    };
    await account.save();

    // send email
    await serviceSendPasswordResetEmail(account, origin);
}

export async function serviceValidateResetToken({ token }: { token: RefreshTokenModel }) {
    const account = await accountModel.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!account) throw 'Invalid token';
}

export async function serviceResetPassword({ token, password }: { token: RefreshTokenModel, password: string }) {
    const account = await accountModel.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!account) throw 'Invalid token';

    // update password and remove reset token
    account.passwordHash = serviceHash(password);
    account.passwordReset = Date.now();
    account.resetToken = undefined;

    await account.save();
}

export async function serviceGetAll() {
    const accounts = await accountModel.find();

    return accounts.map((x: Account) => serviceBasicDetails(x));
}

export async function serviceGetById(id: string) {
    const account = await serviceGetAccount(id);

    return serviceBasicDetails(account);
}

export async function serviceCreate(params: any) {
    // validate
    if (await accountModel.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const account = new accountModel(params);
    account.verified = Date.now();

    // hash password
    account.passwordHash = serviceHash(params.password);

    // save account
    await account.save();

    return serviceBasicDetails(account);
}

export async function serviceUpdate(id: string, params: any) {
    const account = await serviceGetAccount(id);

    // validate (if email was changed)
    if (params.email && account.email !== params.email && await accountModel.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = serviceHash(params.password);
    }

    // copy params to account and save
    Object.assign(account, params);
    
    account.updated = Date.now();
    await account.save();

    return serviceBasicDetails(account);
}

export async function serviceDelete(id: string) {
    const account = await serviceGetAccount(id);

    await account.remove();
}

// helper functions

export async function serviceGetAccount(id: string) {
    if (!isValidId(id)) throw 'Account not found';

    const account = await accountModel.findById(id);

    if (!account) throw 'Account not found';
    return account;
}

export async function serviceGetRefreshToken(token: RefreshTokenModel) {
    const refreshToken = await refreshTokenModel.findOne({ token }).populate('account');

    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

export function serviceHash(password: string) {
    return bcrypt.hashSync(password, 10);
}

export function serviceGenerateJwtToken(account: Account) {
    // create a jwt token containing the account id that expires in 15 minutes
    return jwt.sign({ sub: account.id, id: account.id }, process.env.secret as string, { expiresIn: '15m' });
}

export function serviceGenerateRefreshToken(account: Account, ipAddress: Request["ip"]) {
    // create a refresh token that expires in 7 days
    return new refreshTokenModel({
        account,
        token: serviceRandomTokenString(),
        expires: new Date(Date.now() + 7*24*60*60*1000),
        createdByIp: ipAddress
    });
}

export function serviceRandomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

export function serviceBasicDetails(account: Account) {
    const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;

    return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}

export async function serviceSendVerificationEmail(account: Account, origin: string) {
    let message;

    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
        message = `<p>Please click the below link to verify your email address:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }

    const mailOptions: IMailerOptions = {
        to: account.email as string,
        subject: 'Sign-up Verification API - Verify Email',
        html: `<h4>Verify Email</h4>
               <p>Thanks for registering!</p>
               ${message}`
    }

    await sendEmail(mailOptions);
}

export async function serviceSendAlreadyRegisteredEmail(email: string, origin: string) {
    let message;

    if (origin) {
        message = `<p>If you don't know your password please visit the <a href="${origin}/account/forgot-password">forgot password</a> page.</p>`;
    } else {
        message = `<p>If you don't know your password you can reset it via the <code>/account/forgot-password</code> api route.</p>`;
    }

    const mailOptions: IMailerOptions = {
        to: email,
        subject: 'Sign-up Verification API - Email Already Registered',
        html: `<h4>Email Already Registered</h4>
               <p>Your email <strong>${email}</strong> is already registered.</p>
               ${message}`
    }

    await sendEmail(mailOptions);
}

export async function serviceSendPasswordResetEmail(account: Account, origin: string) {
    let message;

    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${account.resetToken?.token}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
                   <p><code>${account.resetToken?.token}</code></p>`;
    }

    const mailOptions: IMailerOptions = {
        to: account.email as string,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    }

    await sendEmail(mailOptions);
}