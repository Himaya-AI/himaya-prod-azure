@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Base name for all resources (no dashes)')
param baseName string = 'himaya'

@description('Environment name')
param environmentName string = 'prod'

@description('PostgreSQL admin username')
param postgresAdminUser string = 'himayaadmin'

@description('PostgreSQL admin password')
@secure()
param postgresAdminPassword string

@description('Redis SKU')
param redisSku string = 'Standard'

@description('Redis family')
param redisFamily string = 'C'

@description('Redis capacity (0 = 250MB, 1 = 1GB)')
param redisCapacity int = 1

@description('Container Apps CPU cores')
param containerCpu string = '1.0'

@description('Container Apps memory (Gi)')
param containerMemory string = '2.0'

@description('Domain name for the app')
param customDomain string = 'app.himaya.ai'

@description('DeepSeek endpoint FQDN (remains on AWS)')
param deepseekEndpoint string = ''

@description('Reputation microservice base URL (AWS ALB, us-east-1)')
param reputationServiceUrl string = 'http://helios-reputation-alb-1053507845.us-east-1.elb.amazonaws.com'

@description('Graph (Neo4j trust) microservice base URL (AWS ALB, us-east-1) — routes are prefixed with /graph')
param graphServiceUrl string = 'http://graph-lb-926798979.us-east-1.elb.amazonaws.com'

@description('Content classifier (Kimi K2.5) microservice base URL (AWS ALB, us-east-1)')
param classifierServiceUrl string = 'http://classify-lb-556047835.us-east-1.elb.amazonaws.com'

@description('Anthropic API key — enables Claude LLM classification + fallback')
@secure()
param anthropicApiKey string = ''

@description('Microsoft 365 OAuth application (client) ID')
param m365ClientId string = ''

@description('Microsoft 365 OAuth client secret')
@secure()
param m365ClientSecret string = ''

@description('Microsoft 365 directory (tenant) ID, or "common"')
param m365TenantId string = 'common'

@description('Google Workspace OAuth client ID')
param googleClientId string = ''

@description('Google Workspace OAuth client secret')
@secure()
param googleClientSecret string = ''

@description('SaaS Security M365 OAuth application (client) ID')
param saasM365ClientId string = ''

@description('SaaS Security M365 OAuth client secret')
@secure()
param saasM365ClientSecret string = ''

@description('Image tags to deploy')
param frontendImage string = ''
param backendImage string = ''

var resourcePrefix = '${baseName}-${environmentName}'
var frontendAppName = '${resourcePrefix}-frontend'
var backendAppName = '${resourcePrefix}-backend'
var acrName = '${baseName}${environmentName}acr'
var logAnalyticsName = '${resourcePrefix}-logs'
var containerAppEnvName = '${resourcePrefix}-env'
var postgresName = '${resourcePrefix}-db'
var redisName = '${resourcePrefix}-redis'
var storageName = '${baseName}${environmentName}sa'
var serviceBusName = '${resourcePrefix}-bus'
var frontDoorName = '${resourcePrefix}-fd'
var identityName = '${resourcePrefix}-identity'

// Container Registry
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    adminUserEnabled: false
  }
}

// Log Analytics
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
  }
}

// Managed Identity for Container Apps
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
}

// ACR pull role assignment for the managed identity
var acrPullRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
resource acrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(identity.id, acr.id, acrPullRoleDefinitionId)
  scope: acr
  properties: {
    roleDefinitionId: acrPullRoleDefinitionId
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Account Blob Data Contributor role for managed identity
var storageBlobContributorRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
resource storageBlobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(identity.id, storage.id, storageBlobContributorRoleId)
  scope: storage
  properties: {
    roleDefinitionId: storageBlobContributorRoleId
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Service Bus Data Owner role for managed identity
// Built-in role: Azure Service Bus Data Owner
var serviceBusDataOwnerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '090c5cfd-751d-490a-894a-3ce6f1109419')
resource serviceBusDataRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(identity.id, serviceBus.id, serviceBusDataOwnerRoleId)
  scope: serviceBus
  properties: {
    roleDefinitionId: serviceBusDataOwnerRoleId
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Container Apps Environment
resource containerAppEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: containerAppEnvName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// Backend Container App
resource backendApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: backendAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: identity.id
        }
      ]
      secrets: [
        { name: 'anthropic-api-key', value: anthropicApiKey }
        { name: 'm365-client-secret', value: m365ClientSecret }
        { name: 'google-client-secret', value: googleClientSecret }
        { name: 'saas-m365-client-secret', value: saasM365ClientSecret }
      ]
    }
    template: {
      containers: [
        {
          name: backendAppName
          image: !empty(backendImage) ? backendImage : 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'
          resources: {
            cpu: json(containerCpu)
            memory: '${containerMemory}Gi'
          }
          env: [
            { name: 'DATABASE_URL', value: 'postgresql+asyncpg://${postgresAdminUser}:${postgresAdminPassword}@${postgres.properties.fullyQualifiedDomainName}:5432/himaya?sslmode=require' }
            { name: 'REDIS_URL', value: 'rediss://:${redisDatabase.listKeys().primaryKey}@${redis.properties.hostName}:10000' }
            { name: 'AZURE_STORAGE_ACCOUNT', value: storage.name }
            { name: 'AZURE_SERVICE_BUS_NAMESPACE', value: serviceBus.name }
            { name: 'DEEPSEEK_ENDPOINT', value: deepseekEndpoint }
            { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
            { name: 'AZURE_REGION', value: location }
            // ── Threat-detection microservices (remain on AWS ALBs, us-east-1) ──
            { name: 'REPUTATION_SERVICE_URL', value: reputationServiceUrl }
            { name: 'GRAPH_SERVICE_URL', value: graphServiceUrl }
            { name: 'CLASSIFIER_SERVICE_URL', value: classifierServiceUrl }
            { name: 'ANTHROPIC_API_KEY', secretRef: 'anthropic-api-key' }
            // ── App base URL (CORS, invite links, OAuth post-callback redirects) ──
            { name: 'FRONTEND_URL', value: 'https://${customDomain}' }
            // ── Microsoft 365 OAuth (onboarding) ──
            { name: 'M365_CLIENT_ID', value: m365ClientId }
            { name: 'M365_CLIENT_SECRET', secretRef: 'm365-client-secret' }
            { name: 'M365_TENANT_ID', value: m365TenantId }
            { name: 'M365_REDIRECT_URI', value: 'https://${customDomain}/api/onboarding/callback/m365' }
            // ── Google Workspace OAuth (onboarding) ──
            { name: 'GOOGLE_CLIENT_ID', value: googleClientId }
            { name: 'GOOGLE_CLIENT_SECRET', secretRef: 'google-client-secret' }
            { name: 'GOOGLE_REDIRECT_URI', value: 'https://${customDomain}/api/onboarding/callback/google' }
            // ── SaaS Security M365 OAuth ──
            { name: 'SAAS_M365_CLIENT_ID', value: saasM365ClientId }
            { name: 'SAAS_M365_CLIENT_SECRET', secretRef: 'saas-m365-client-secret' }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
        rules: [
          {
            name: 'http-rule'
            custom: {
              type: 'http'
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

// Frontend Container App
resource frontendApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: frontendAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 3000
        transport: 'auto'
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: frontendAppName
          image: !empty(frontendImage) ? frontendImage : 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'
          resources: {
            cpu: json(containerCpu)
            memory: '${containerMemory}Gi'
          }
          env: [
            { name: 'NEXT_PUBLIC_API_URL', value: 'https://${customDomain}' }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
      }
    }
  }
}

// PostgreSQL Flexible Server
resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' = {
  name: postgresName
  location: location
  sku: {
    name: 'Standard_B2s'
    tier: 'Burstable'
  }
  properties: {
    administratorLogin: postgresAdminUser
    administratorLoginPassword: postgresAdminPassword
    version: '15'
    storage: {
      storageSizeGB: 32
    }
    highAvailability: {
      mode: 'Disabled'
    }
  }
}

// Azure Managed Redis (replaces retiring Azure Cache for Redis)
resource redis 'Microsoft.Cache/redisEnterprise@2024-09-01-preview' = {
  name: redisName
  location: location
  sku: {
    name: 'Balanced_B1'
  }
  properties: {}
}

resource redisDatabase 'Microsoft.Cache/redisEnterprise/databases@2024-09-01-preview' = {
  name: 'default'
  parent: redis
  properties: {
    clientProtocol: 'Encrypted'
    port: 10000
    // EnterpriseCluster = single proxied endpoint, NO MOVED redirects.
    // Celery/kombu (redis-py in standalone mode) cannot follow OSSCluster
    // MOVED redirects, which crash-loops the worker on `LLEN celery`.
    clusteringPolicy: 'EnterpriseCluster'
    evictionPolicy: 'VolatileLRU'
    persistence: {
      aofEnabled: false
      rdbEnabled: false
    }
  }
}

// Storage Account
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  name: 'default'
  parent: storage
}

resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: 'himaya-evidence'
  parent: blobService
}

resource reportsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: 'himaya-reports'
  parent: blobService
}

resource modelsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: 'himaya-models'
  parent: blobService
}

resource frontendContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: 'himaya-frontend-prod'
  parent: blobService
}

// Service Bus Namespace
resource serviceBus 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: serviceBusName
  location: location
  sku: {
    name: 'Standard'
    tier: 'Standard'
  }
}

resource emailQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  name: 'himaya-email-events'
  parent: serviceBus
  properties: {
    requiresDuplicateDetection: false
    requiresSession: false
    maxDeliveryCount: 10
    deadLetteringOnMessageExpiration: true
  }
}

resource alertQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  name: 'himaya-alerts'
  parent: serviceBus
}

resource complianceQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  name: 'himaya-compliance'
  parent: serviceBus
}

resource sandboxJobsQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  name: 'himaya-sandbox-jobs'
  parent: serviceBus
}

resource sandboxResultsQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  name: 'himaya-sandbox-results'
  parent: serviceBus
}

// Azure Front Door
resource frontDoorProfile 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: frontDoorName
  location: 'global'
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
}

// Front Door Endpoint
resource frontDoorEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' = {
  name: 'himaya-prod'
  parent: frontDoorProfile
  location: 'global'
  properties: {
    enabledState: 'Enabled'
  }
}

// Origin Group — Frontend
resource frontendOriginGroup 'Microsoft.Cdn/profiles/originGroups@2024-02-01' = {
  name: 'frontend-og'
  parent: frontDoorProfile
  properties: {
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
    }
    healthProbeSettings: {
      probePath: '/'
      probeRequestType: 'HEAD'
      probeProtocol: 'Https'
      probeIntervalInSeconds: 30
    }
  }
}

resource frontendOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2024-02-01' = {
  name: 'frontend-origin'
  parent: frontendOriginGroup
  properties: {
    hostName: frontendApp.properties.configuration.ingress.fqdn
    httpPort: 80
    httpsPort: 443
    originHostHeader: frontendApp.properties.configuration.ingress.fqdn
    priority: 1
    weight: 1000
  }
}

// Origin Group — Backend
resource backendOriginGroup 'Microsoft.Cdn/profiles/originGroups@2024-02-01' = {
  name: 'backend-og'
  parent: frontDoorProfile
  properties: {
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
    }
    healthProbeSettings: {
      probePath: '/health'
      probeRequestType: 'HEAD'
      probeProtocol: 'Https'
      probeIntervalInSeconds: 30
    }
  }
}

resource backendOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2024-02-01' = {
  name: 'backend-origin'
  parent: backendOriginGroup
  properties: {
    hostName: backendApp.properties.configuration.ingress.fqdn
    httpPort: 80
    httpsPort: 443
    originHostHeader: backendApp.properties.configuration.ingress.fqdn
    priority: 1
    weight: 1000
  }
}

// Routes
resource apiRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-02-01' = {
  name: 'api-route'
  parent: frontDoorEndpoint
  dependsOn: [backendOrigin]
  properties: {
    originGroup: { id: backendOriginGroup.id }
    supportedProtocols: ['Https']
    patternsToMatch: ['/api/*', '/health', '/docs', '/openapi.json']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
  }
}

resource frontendRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-02-01' = {
  name: 'frontend-route'
  parent: frontDoorEndpoint
  dependsOn: [frontendOrigin]
  properties: {
    originGroup: { id: frontendOriginGroup.id }
    supportedProtocols: ['Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
  }
}

output acrLoginServer string = acr.properties.loginServer
output backendFqdn string = backendApp.properties.configuration.ingress.fqdn
output frontendFqdn string = frontendApp.properties.configuration.ingress.fqdn
output postgresFqdn string = postgres.properties.fullyQualifiedDomainName
output redisFqdn string = '${redis.properties.hostName}:10000'
output storageAccountName string = storage.name
output serviceBusNamespace string = serviceBus.name
output managedIdentityClientId string = identity.properties.clientId
output managedIdentityPrincipalId string = identity.properties.principalId
