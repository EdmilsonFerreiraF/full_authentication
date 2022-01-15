import { RefreshTokenModel } from "./RefreshTokenModel";
import { Request } from 'express'

export type Account = {
    id: string,
    email: string,
    passwordHash: string,
    title: string,
    firstName: string,
    lastName: string,
    acceptTerms: boolean,
    role: string,
    verificationToken?: string,
    verified: number,
    isVerified: boolean,
    resetToken?: {
        token: string,
        expires: Date,
    },
    passwordReset: number,
    created: number,
    updated: number,
}

export interface IServiceAuthenticateDTO {
    email: string,
    password: string,
    ipAddress: string
}

export interface IServiceRefreshTokenDTO {
    token: RefreshTokenModel,
    ipAddress: string
}

export interface IServiceRevokeTokenDTO {
    token: RefreshTokenModel,
    ipAddress: string
}

export interface IServiceRegisterDTO {
    params: any, origin: string
}

export interface IServiceVerifyEmailDTO {
    token: RefreshTokenModel
}

export interface IServiceForgotPasswordDTO {
    email: string, origin: string
}

export interface IServiceValidateResetTokenDTO {
    token: RefreshTokenModel
}

export interface IServiceResetPasswordDTO {
    token: RefreshTokenModel,
    password: string
}

export interface IServiceGetByIdDTO {
    id: string
}

export interface IServiceCreateDTO {
    params: any
}

export interface IServiceUpdateDTO {
    id: string, params: any
}

export interface IServiceDeleteDTO {
    id: string
}

export interface IServiceGetAccountDTO {
    id: string
}

export interface IServiceGetRefreshTokenDTO {
    token: RefreshTokenModel
}

export interface IServiceHashDTO {
    password: string
}

export interface IServiceGenerateJwtTokenDTO {
    account: Account
}

export interface IServiceGenerateRefreshTokenDTO {
    account: Account,
    ipAddress: Request["ip"]
}

export interface IServiceBasicDetailsDTO {
    account: Account
}

export interface IServiceSendVerificationEmailDTO {
    account: Account,
    origin: string
}

export interface IServiceSendAlreadyRegisteredEmailDTO {
    email: string,
    origin: string
}

export interface IServiceSendPasswordResetEmailDTO {
    account: Account,
    origin: string
}
