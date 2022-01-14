import 'rootpath'
import express from 'express'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import cors from 'cors'

import { router as accountRouter} from './accounts/accounts.controller'
import { router as swaggerRouter } from './_helpers/swagger'
import { errorHandler } from './_middleware/error-handler'

const app = express()

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// allow cors requests from any origin and with credentials
app.use(cors({ origin: (_, callback) => callback(null, true), credentials: true }));

// api routes
app.use('/accounts', accountRouter);

// swagger docs route
app.use('/api-docs', swaggerRouter);

// global error handler
app.use(errorHandler);

// start server
const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 4000;

app.listen(port, () => {
    console.log('Server listening on port ' + port);
});
