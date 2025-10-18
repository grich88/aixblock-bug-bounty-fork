import cors from '@fastify/cors'
import formBody from '@fastify/formbody'
import fastifyMultipart, { MultipartFile } from '@fastify/multipart'
import fastify, { FastifyBaseLogger, FastifyInstance } from 'fastify'
import fastifyFavicon from 'fastify-favicon'
import { fastifyRawBody } from 'fastify-raw-body'
import qs from 'qs'
import { AppSystemProp, exceptionHandler } from 'workflow-server-shared'
import { apId, ApMultipartFile } from 'workflow-shared'
import { setupApp } from './app'
import { healthModule } from './health/health.module'
import { errorHandler } from './helper/error-handler'
import { system } from './helper/system/system'
import { setupWorker } from './worker'


export const setupServer = async (): Promise<FastifyInstance> => {
    const app = await setupBaseApp()

    if (system.isApp()) {
        await setupApp(app)
    }
    if (system.isWorker()) {
        await setupWorker(app)
    }
    return app
}

async function setupBaseApp(): Promise<FastifyInstance> {
    const MAX_FILE_SIZE_MB = system.getNumberOrThrow(AppSystemProp.MAX_FILE_SIZE_MB)
    const fileSizeLimit =  Math.max(25 * 1024 * 1024, (MAX_FILE_SIZE_MB + 4) * 1024 * 1024)
    const app = fastify({
        logger: system.globalLogger() as FastifyBaseLogger,
        ignoreTrailingSlash: true,
        pluginTimeout: 30000,
        // Default 100MB, also set in nginx.conf
        bodyLimit: fileSizeLimit,
        genReqId: () => {
            return `req_${apId()}`
        },
        ajv: {
            customOptions: {
                removeAdditional: 'all',
                useDefaults: true,
                keywords: ['discriminator'],
                coerceTypes: 'array',
                formats: {},
            },
        },
    }) 
    await app.register(fastifyFavicon)
    await app.register(fastifyMultipart, {
        attachFieldsToBody: 'keyValues',
        async onFile(part: MultipartFile) {
            const apFile: ApMultipartFile = {
                filename: part.filename,
                data: await part.toBuffer(),
                type: 'file',
            };
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (part as any).value = apFile
        },
    })
    exceptionHandler.initializeSentry(system.get(AppSystemProp.SENTRY_DSN))


    await app.register(fastifyRawBody, {
        field: 'rawBody',
        global: false,
        encoding: 'utf8',
        runFirst: true,
        routes: [],
    })

    await app.register(formBody, { parser: (str) => qs.parse(str) })
    app.setErrorHandler(errorHandler)
    // Security fix: CORS configuration to prevent wildcard origin with credentials
    await app.register(cors, {
        origin: (origin, callback) => {
            // Allow specific AIxBlock domains only
            const allowedOrigins = [
                'https://workflow.aixblock.io',
                'https://app.aixblock.io',
                'https://api.aixblock.io',
                'https://workflow-live.aixblock.io'
            ]
            
            // Allow requests with no origin (mobile apps, Postman, etc.)
            if (!origin) return callback(null, true)
            
            if (allowedOrigins.includes(origin)) {
                callback(null, true)
            } else {
                callback(new Error('Not allowed by CORS'), false)
            }
        },
        credentials: true,
        exposedHeaders: ['*'],
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    })
    // SurveyMonkey
    app.addContentTypeParser(
        'application/vnd.surveymonkey.response.v1+json',
        { parseAs: 'string' },
        app.getDefaultJsonParser('ignore', 'ignore'),
    )
    await app.register(healthModule)

    return app
}

