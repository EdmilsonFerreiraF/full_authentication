import nodemailer, { TransportOptions } from 'nodemailer'
import dotenv from 'dotenv'

import { IMailerOptions } from '../entities/Mailer'

dotenv.config()

export async function sendEmail(mailOptions: IMailerOptions): Promise<void> {
    const transporter = nodemailer.createTransport({
        host: process.env.host as string,
        port: process.env.port as string,
        auth: {
            user: process.env.user as string,
            pass: process.env.pass as string,
        },
        tls: {
            rejectUnauthorized: false
        }
    } as TransportOptions);

    await transporter.sendMail(mailOptions);
}