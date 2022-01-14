import { Request, Response } from "express";

export const errorHandler = (err: any, _: Request, res: Response) => {
    switch (true) {
        case typeof err === 'string':
            // custom application error
            const is404 = err.toLowerCase().endsWith('not found');
            const statusCode = is404 ? 404 : 400;
            
            console.log(err)
            return res.status(statusCode).json({ message: err });
        case err.name === 'ValidationError':
            // mongoose validation error
            console.log(err)
            return res.status(400).json({ message: err.message });
        case err.name === 'UnauthorizedError':
            // jwt authentication error
            console.log(err)
            return res.status(401).json({ message: 'Unauthorized' });
        default:
            console.log(err)
            return res.status(500).json({ message: err.message });
    }
}