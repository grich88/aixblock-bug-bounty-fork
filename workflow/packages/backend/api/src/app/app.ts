import swagger from '@fastify/swagger'
import { createAdapter } from '@socket.io/redis-adapter'
import { FastifyInstance, FastifyRequest, HTTPMethods } from 'fastify'
import fastifySocketIO from 'fastify-socket.io'
import { Socket } from 'socket.io'
import { ApplicationEventName, AuthenticationEvent, ConnectionEvent, FlowCreatedEvent, FlowDeletedEvent, FlowRunEvent, FolderEvent, GitRepoWithoutSensitiveData, ProjectMember, ProjectReleaseEvent, ProjectRoleEvent, SigningKeyEvent, SignUpEvent } from 'workflow-axb-shared'
import { BlockMetadata } from 'workflow-blocks-framework'
import { AppSystemProp, exceptionHandler, rejectedPromiseHandler } from 'workflow-server-shared'
import { ApEdition, ApEnvironment, AppConnectionWithoutSensitiveData, Flow, FlowRun, FlowTemplate, Folder, isNil, ProjectRelease, ProjectWithLimits, spreadIfDefined, UserInvitation } from 'workflow-shared'
import { aiProviderModule } from './ai/ai-provider.module'
import { setPlatformOAuthService } from './app-connection/app-connection-service/oauth2'
import { appConnectionModule } from './app-connection/app-connection.module'
import { appEventRoutingModule } from './app-event-routing/app-event-routing.module'
import { authenticationModule } from './authentication/authentication.module'
import { accessTokenManager } from './authentication/lib/access-token-manager'
import { blockModule } from './blocks/base-block-module'
import { blockMetadataServiceHooks } from './blocks/block-metadata-service/hooks'
import { communityBlocksModule } from './blocks/community-block-module'
import { changelogModule } from './changelog/changelog.module'
import { copilotModule } from './copilot/copilot.module'
import { rateLimitModule } from './core/security/rate-limit'
import { securityHandlerChain } from './core/security/security-handler-chain'
import { getRedisConnection } from './database/redis-connection'
import { alertsModule } from './ee/alerts/alerts-module'
import { analyticsModule } from './ee/analytics/analytics.module'
import { apiKeyModule } from './ee/api-keys/api-key-module'
import { platformOAuth2Service } from './ee/app-connections/platform-oauth2-service'
import { appCredentialModule } from './ee/app-credentials/app-credentials.module'
import { auditEventModule } from './ee/audit-logs/audit-event-module'
import { auditLogService } from './ee/audit-logs/audit-event-service'
import { enterpriseLocalAuthnModule } from './ee/authentication/enterprise-local-authn/enterprise-local-authn-module'
import { federatedAuthModule } from './ee/authentication/federated-authn/federated-authn-module'
import { otpModule } from './ee/authentication/otp/otp-module'
import { rbacMiddleware } from './ee/authentication/project-role/rbac-middleware'
import { authnSsoSamlModule } from './ee/authentication/saml-authn/authn-sso-saml-module'
import { adminPieceModule } from './ee/blocks/admin-block-module'
import { enterpriseBlockMetadataServiceHooks } from './ee/blocks/filters/enterprise-block-metadata-service-hooks'
import { platformPieceModule } from './ee/blocks/platform-block-module'
import { connectionKeyModule } from './ee/connection-keys/connection-key.module'
import { customDomainModule } from './ee/custom-domains/custom-domain.module'
import { domainHelper } from './ee/custom-domains/domain-helper'
import { enterpriseFlagsHooks } from './ee/flags/enterprise-flags.hooks'
import { platformRunHooks } from './ee/flow-run/cloud-flow-run-hooks'
import { platformFlowTemplateModule } from './ee/flow-template/platform-flow-template.module'
import { globalConnectionModule } from './ee/global-connections/global-connection-module'
import { emailService } from './ee/helper/email/email-service'
import { licenseKeysModule } from './ee/license-keys/license-keys-module'
import { licenseKeysService } from './ee/license-keys/license-keys-service'
import { managedAuthnModule } from './ee/managed-authn/managed-authn-module'
import { oauthAppModule } from './ee/oauth-apps/oauth-app.module'
import { platformBillingModule } from './ee/platform-billing/platform-billing.module'
import { adminPlatformModule } from './ee/platform/admin-platform.controller'
import { projectMemberModule } from './ee/project-members/project-member.module'
import { gitRepoModule } from './ee/project-release/git-sync/git-sync.module'
import { projectReleaseModule } from './ee/project-release/project-release.module'
import { projectRoleModule } from './ee/project-role/project-role.module'
import { projectEnterpriseHooks } from './ee/projects/ee-project-hooks'
import { platformProjectModule } from './ee/projects/platform-project-module'
import { signingKeyModule } from './ee/signing-key/signing-key-module'
import { todoCommentModule } from './ee/todos/comment/todos-comment.module'
import { userModule } from './ee/users/user.module'
import { fileModule } from './file/file.module'
import { flagModule } from './flags/flag.module'
import { flagHooks } from './flags/flags.hooks'
import { communityFlowTemplateModule } from './flow-templates/community-flow-template.module'
import { flowRunHooks } from './flows/flow-run/flow-run-hooks'
import { flowRunModule } from './flows/flow-run/flow-run-module'
import { flowModule } from './flows/flow.module'
import { aixblockAssignTasksModule } from './flows/flow/aixblock-assign-tasks/aixblock-assign-tasks.module'
import { aixblockTasksModule } from './flows/flow/aixblock-tasks/aixblock-tasks.module'
import { aixblockWebFormsModule } from './flows/flow/aixblock-web-forms/aixblock-web-forms.module'
import { aixblockModule } from './flows/flow/aixblock/aixblock.module'
import { humanInputModule } from './flows/flow/human-input/human-input.module'
import { folderModule } from './flows/folder/folder.module'
import { issuesModule } from './flows/issues/issues-module'
import { triggerEventModule } from './flows/trigger-events/trigger-event.module'
import { eventsHooks } from './helper/application-events'
import { openapiModule } from './helper/openapi/openapi.module'
import { systemJobsSchedule } from './helper/system-jobs'
import { SystemJobName } from './helper/system-jobs/common'
import { systemJobHandlers } from './helper/system-jobs/job-handlers'
import { validateEnvPropsOnStartup } from './helper/system-validator'
import { QueueMode, system } from './helper/system/system'
import { marketplaceModule } from './marketplace/marketplace.module'
import { mcpModule } from './mcp/mcp-module'
import { platformModule } from './platform/platform.module'
import { platformService } from './platform/platform.service'
import { projectHooks } from './project/project-hooks'
import { projectModule } from './project/project-module'
import { projectService } from './project/project-service'
import { storeEntryModule } from './store-entry/store-entry.module'
import { tablesModule } from './tables/tables.module'
import { tagsModule } from './tags/tags-module'
import { todoModule } from './todos/todo.module'
import { invitationModule } from './user-invitations/user-invitation.module'
import { platformUserModule } from './user/platform/platform-user-module'
import { webhookModule } from './webhooks/webhook-module'
import { websocketService } from './websockets/websockets.service'
import { flowConsumer } from './workers/consumer'
import { engineResponseWatcher } from './workers/engine-response-watcher'
import { workerModule } from './workers/worker-module'
export const setupApp = async (app: FastifyInstance): Promise<FastifyInstance> => {

    await app.register(swagger, {
        hideUntagged: true,
        openapi: {
            servers: [
                {
                    url: 'https://workflow.aixblock.io/api',
                    description: 'Production Server',
                },
            ],
            components: {
                securitySchemes: {
                    apiKey: {
                        type: 'http',
                        description: 'Use your api key generated from the admin console',
                        scheme: 'bearer',
                    },
                },
                schemas: {
                    [ApplicationEventName.FLOW_CREATED]: FlowCreatedEvent,
                    [ApplicationEventName.FLOW_DELETED]: FlowDeletedEvent,
                    [ApplicationEventName.CONNECTION_UPSERTED]: ConnectionEvent,
                    [ApplicationEventName.CONNECTION_DELETED]: ConnectionEvent,
                    [ApplicationEventName.FOLDER_CREATED]: FolderEvent,
                    [ApplicationEventName.FOLDER_UPDATED]: FolderEvent,
                    [ApplicationEventName.FOLDER_DELETED]: FolderEvent,
                    [ApplicationEventName.FLOW_RUN_STARTED]: FlowRunEvent,
                    [ApplicationEventName.FLOW_RUN_FINISHED]: FlowRunEvent,
                    [ApplicationEventName.USER_SIGNED_UP]: SignUpEvent,
                    [ApplicationEventName.USER_SIGNED_IN]: AuthenticationEvent,
                    [ApplicationEventName.USER_PASSWORD_RESET]: AuthenticationEvent,
                    [ApplicationEventName.USER_EMAIL_VERIFIED]: AuthenticationEvent,
                    [ApplicationEventName.SIGNING_KEY_CREATED]: SigningKeyEvent,
                    [ApplicationEventName.PROJECT_ROLE_CREATED]: ProjectRoleEvent,
                    [ApplicationEventName.PROJECT_RELEASE_CREATED]: ProjectReleaseEvent,
                    'flow-template': FlowTemplate,
                    'folder': Folder,
                    'user-invitation': UserInvitation,
                    'project-member': ProjectMember,
                    project: ProjectWithLimits,
                    flow: Flow,
                    'flow-run': FlowRun,
                    'app-connection': AppConnectionWithoutSensitiveData,
                    piece: BlockMetadata,
                    'git-repo': GitRepoWithoutSensitiveData,
                    'project-release': ProjectRelease,
                    'global-connection': AppConnectionWithoutSensitiveData,
                },
            },
            info: {
                title: 'Documentation',
                version: '0.0.0',
            },
            externalDocs: {
                url: 'https://workflow.aixblock.io/docs',
                description: 'Find more info here',
            },
        },
    })


    await app.register(rateLimitModule)

    await app.register(fastifySocketIO, {
        cors: {
            origin: [
                'https://app.aixblock.io',
                'https://workflow.aixblock.io',
                'https://workflow-live.aixblock.io'
            ],
            credentials: true
        },
        ...spreadIfDefined('adapter', await getAdapter()),
        transports: ['websocket'],
    })

    app.io.use((socket: Socket, next: (err?: Error) => void) => {
        accessTokenManager
            .verifyPrincipal(socket.handshake.auth.token)
            .then(() => {
                next()
            })
            .catch(() => {
                next(new Error('Authentication error'))
            })
    })

    app.io.on('connection', (socket: Socket) => {
        rejectedPromiseHandler(websocketService.init(socket, app.log), app.log)
    })

    app.addHook('onResponse', async (request, reply) => {
        // eslint-disable-next-line
        reply.header('x-request-id', request.id)
    })
    app.addHook('onRequest', async (request, reply) => {
        const route = app.hasRoute({
            method: request.method as HTTPMethods,
            url: request.url,
        })
        if (!route) {
            return reply.code(404).send({
                statusCode: 404,
                error: 'Not Found',
                message: 'Route not found',
            })
        }
    })

    app.addHook('preHandler', securityHandlerChain)
    app.addHook('preHandler', rbacMiddleware)
    await systemJobsSchedule(app.log).init()
    await app.register(fileModule)
    await app.register(flagModule)
    await app.register(storeEntryModule)
    await app.register(folderModule)
    await app.register(flowModule)
    await app.register(blockModule)
    await app.register(flowRunModule)
    await app.register(webhookModule)
    await app.register(appConnectionModule)
    await app.register(openapiModule)
    await app.register(triggerEventModule)
    await app.register(appEventRoutingModule)
    await app.register(authenticationModule)
    await app.register(copilotModule),
    await app.register(platformModule)
    await app.register(humanInputModule)
    await app.register(aixblockWebFormsModule)
    await app.register(aixblockTasksModule);
    await app.register(aixblockAssignTasksModule);
    await app.register(aixblockModule);
    await app.register(tagsModule)
    await app.register(mcpModule)
    await projectService.setup()
    await licenseKeysService(app.log).setup()
    await app.register(platformUserModule)
    await app.register(issuesModule)
    await app.register(alertsModule)
    await app.register(invitationModule)
    await app.register(workerModule)
    await app.register(aiProviderModule)
    await app.register(licenseKeysModule)
    await app.register(tablesModule)
    await app.register(userModule)
    await app.register(todoModule)
    await app.register(adminPlatformModule)
    await app.register(changelogModule)
    await app.register(marketplaceModule)

    app.get(
        '/redirect',
        async (
            request: FastifyRequest<{ Querystring: { code: string } }>,
            reply,
        ) => {
            const params = {
                code: request.query.code,
            }
            if (!params.code) {
                return reply.send('The code is missing in url')
            }
            else {
                return reply
                    .type('text/html')
                    .send(
                        `<script>if(window.opener){window.opener.postMessage({ 'code': '${encodeURIComponent(
                            params.code,
                        )}' },'*')}</script> <html>Redirect succuesfully, this window should close now</html>`,
                    )
            }
        },
    )

    await validateEnvPropsOnStartup(app.log)

    const edition = system.getEdition()
    app.log.info({
        edition,
    }, 'AIxBlock workflow')
    switch (edition) {
        case ApEdition.CLOUD:
            await app.register(appCredentialModule)
            await app.register(connectionKeyModule)
            await app.register(platformProjectModule)
            await app.register(platformBillingModule)
            await app.register(projectMemberModule)
            await app.register(adminPieceModule)
            await app.register(customDomainModule)
            await app.register(signingKeyModule)
            await app.register(authnSsoSamlModule)
            await app.register(managedAuthnModule)
            await app.register(oauthAppModule)
            await app.register(platformPieceModule)
            await app.register(otpModule)
            await app.register(enterpriseLocalAuthnModule)
            await app.register(federatedAuthModule)
            await app.register(apiKeyModule)
            await app.register(platformFlowTemplateModule)
            await app.register(gitRepoModule)
            await app.register(auditEventModule)
            await app.register(analyticsModule)
            await app.register(projectRoleModule)
            await app.register(projectReleaseModule)
            await app.register(todoCommentModule)
            await app.register(globalConnectionModule)
            setPlatformOAuthService(platformOAuth2Service(app.log))
            projectHooks.set(projectEnterpriseHooks)
            eventsHooks.set(auditLogService)
            flowRunHooks.set(platformRunHooks)
            flagHooks.set(enterpriseFlagsHooks)
            blockMetadataServiceHooks.set(enterpriseBlockMetadataServiceHooks)
            systemJobHandlers.registerJobHandler(SystemJobName.ISSUES_REMINDER, emailService(app.log).sendReminderJobHandler)
            exceptionHandler.initializeSentry(system.get(AppSystemProp.SENTRY_DSN))
            break
        case ApEdition.ENTERPRISE:
            await app.register(customDomainModule)
            await app.register(platformProjectModule)
            await app.register(projectMemberModule)
            await app.register(signingKeyModule)
            await app.register(authnSsoSamlModule)
            await app.register(managedAuthnModule)
            await app.register(oauthAppModule)
            await app.register(platformPieceModule)
            await app.register(otpModule)
            await app.register(enterpriseLocalAuthnModule)
            await app.register(federatedAuthModule)
            await app.register(apiKeyModule)
            await app.register(platformFlowTemplateModule)
            await app.register(gitRepoModule)
            await app.register(auditEventModule)
            await app.register(analyticsModule)
            await app.register(projectRoleModule)
            await app.register(projectReleaseModule)
            await app.register(todoCommentModule)
            await app.register(globalConnectionModule)
            systemJobHandlers.registerJobHandler(SystemJobName.ISSUES_REMINDER, emailService(app.log).sendReminderJobHandler)
            setPlatformOAuthService(platformOAuth2Service(app.log))
            projectHooks.set(projectEnterpriseHooks)
            eventsHooks.set(auditLogService)
            flowRunHooks.set(platformRunHooks)
            blockMetadataServiceHooks.set(enterpriseBlockMetadataServiceHooks)
            flagHooks.set(enterpriseFlagsHooks)
            break
        case ApEdition.COMMUNITY:
            await app.register(projectModule)
            await app.register(communityBlocksModule)
            await app.register(communityFlowTemplateModule)
            break
    }

    app.addHook('onClose', async () => {
        app.log.info('Shutting down')
        await flowConsumer(app.log).close()
        await systemJobsSchedule(app.log).close()
        await engineResponseWatcher(app.log).shutdown()
    })

    return app
}



async function getAdapter() {
    const queue = system.getOrThrow<QueueMode>(AppSystemProp.QUEUE_MODE)
    switch (queue) {
        case QueueMode.MEMORY: {
            return undefined
        }
        case QueueMode.REDIS: {
            const sub = getRedisConnection().duplicate()
            const pub = getRedisConnection().duplicate()
            return createAdapter(pub, sub)
        }
    }
}


export async function appPostBoot(app: FastifyInstance): Promise<void> {

    app.log.info(`
The application started on ${await domainHelper.getPublicApiUrl({ path: '' })}, as specified by the AP_FRONTEND_URL variables.`)

    const environment = system.get(AppSystemProp.ENVIRONMENT)
    const blocksSource = system.getOrThrow(AppSystemProp.BLOCKS_SOURCE)
    const blocks = process.env.AP_DEV_BLOCKS

    app.log.warn(
        `[WARNING]: Pieces will be loaded from source type ${blocksSource}`,
    )
    if (environment === ApEnvironment.DEVELOPMENT) {
        app.log.warn(
            `[WARNING]: The application is running in ${environment} mode.`,
        )
        app.log.warn(
            `[WARNING]: This is only shows blocks specified in AP_DEV_BLOCKS ${blocks} environment variable.`,
        )
    }
    const oldestPlatform = await platformService.getOldestPlatform()
    const key = system.get<string>(AppSystemProp.LICENSE_KEY)
    if (!isNil(oldestPlatform) && !isNil(key)) {
        await platformService.update({
            id: oldestPlatform.id,
            licenseKey: key,
        })
    }
}
