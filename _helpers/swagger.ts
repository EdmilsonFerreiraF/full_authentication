import express from 'express'
import swaggerUi from 'swagger-ui-express'
import YAML from 'yamljs'

const swaggerDocument = YAML.load('./swagger.yaml');

export const router = express.Router();

router.use('/', swaggerUi.serve, swaggerUi.setup(swaggerDocument));