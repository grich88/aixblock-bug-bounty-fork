import { ALL_PRINCIPAL_TYPES } from 'workflow-shared'
import { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox'
import { FastifyRequest } from 'fastify'
import { flagService } from './flag.service'
import { flagHooks } from './flags.hooks'

export const flagModule: FastifyPluginAsyncTypebox = async (app) => {
    await app.register(flagController, { prefix: '/v1/flags' })
}

export const flagController: FastifyPluginAsyncTypebox = async (app) => {
    app.get(
        '/',
        {
            config: {
                allowedPrincipals: ALL_PRINCIPAL_TYPES,
            },
            logLevel: 'silent',
        },
        async (request: FastifyRequest) => {
            // Security fix: Require authentication
            if (!request.principal) {
                return app.httpErrors.unauthorized('Authentication required')
            }

            // Security fix: Require admin role for sensitive configuration
            if (request.principal.type !== 'ADMIN') {
                return app.httpErrors.forbidden('Admin access required')
            }

            const flags = await flagService.getAll()
            const flagsMap: Record<string, string | boolean | number | Record<string, unknown>> = flags.reduce(
                (map, flag) => ({ ...map, [flag.id as string]: flag.value }),
                {},
            )
            
            // Security fix: Filter sensitive configuration data
            const safeFlags = filterSensitiveFlags(flagsMap)
            
            return flagHooks.get().modify({
                flags: safeFlags,
                request,
            })
        },
    )
    
}

// Security fix: Filter sensitive configuration data
function filterSensitiveFlags(flags: Record<string, string | boolean | number | Record<string, unknown>>): Record<string, string | boolean | number | Record<string, unknown>> {
    const sensitiveKeys = [
        'AUTH0_DOMAIN',
        'AUTH0_APP_CLIENT_ID', 
        'SAML_AUTH_ACS_URL',
        'WEBHOOK_URL_PREFIX',
        'THIRD_PARTY_AUTH_PROVIDER_REDIRECT_URL',
        'SUPPORTED_APP_WEBHOOKS'
    ]
    
    const safeFlags = { ...flags }
    
    // Remove sensitive keys
    sensitiveKeys.forEach(key => {
        delete safeFlags[key]
    })
    
    return safeFlags
}
