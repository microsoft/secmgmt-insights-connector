section SecMgmtInsights;

// Global variables

authorize_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
client_id = Text.FromBinary(Extension.Contents("client_id"));
graph_endpoint = "https://graph.microsoft.com";
logout_uri = "https://login.microsoftonline.com/logout.srf";
redirect_uri = "https://oauth.powerbi.com/views/oauthredirect.html";
token_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
version = "2.2-preview-1";

// Data Source Kind description

SecMgmtInsights = [
    Authentication = [
        OAuth = [
            FinishLogin = FinishLogin,
            Logout = Logout,
            Refresh = Refresh,
            StartLogin = StartLogin
        ]
    ],
    Label = Extension.LoadString("DataSourceLabel"),
    TestConnection = (dataSourcePath) => {"SecMgmtInsights.Contents"}
];

// Data Source UI publishing description

SecMgmtInsights.Publish = [
    Beta = true,
    Category = "Other",
    ButtonText = { Extension.LoadString("ButtonTitle"), Extension.LoadString("ButtonHelp") },
    LearnMoreUrl = "https://github.com/microsoft/secmgmt-insights-connector",
    SourceImage = SecMgmtInsights.Icons,
    SourceTypeImage = SecMgmtInsights.Icons
];

SecMgmtInsights.Icons = [
    Icon16 = { Extension.Contents("SecMgmtInsights16.png"), Extension.Contents("SecMgmtInsights20.png"), Extension.Contents("SecMgmtInsights24.png"), Extension.Contents("SecMgmtInsights32.png") },
    Icon32 = { Extension.Contents("SecMgmtInsights32.png"), Extension.Contents("SecMgmtInsights40.png"), Extension.Contents("SecMgmtInsights48.png"), Extension.Contents("SecMgmtInsights64.png") }
];

// Data Source type

SecMgmtInsightsType = type function (
    optional tenants as (type list meta [
        Documentation.FieldCaption = "List of tenants",
        Documentation.FieldDescription = "List of tenant identifiers if left blank the list of tenants will be obtained using contracts feature of Microsoft Graph"
    ])) 
    as table meta [
        Documentation.Name = "Security and Management Insights",
        Documentation.LongDescription = "Security and Management Insights",
        Documentation.Icon = Extension.Contents("SecMgmtInsights32.png")
    ];

// Authentication

FinishLogin = (context, callbackUri, state) =>
    let
        parts = Uri.Parts(callbackUri)[Query],
        result = if (Record.HasFields(parts, {"error", "error_description"})) then 
                    error Error.Record(parts[error], parts[error_description], parts)
                 else
                    TokenMethod(token_uri, "authorization_code", "code", parts[code])
    in
        result;

Logout = (token) => logout_uri;

Refresh = (resourceUrl, refresh_token) => TokenMethod(token_uri, "refresh_token", "refresh_token", refresh_token);

StartLogin = (resourceUrl, state, display) =>
    let
        authorizeUrl = authorize_uri & "?" & Uri.BuildQueryString([
            client_id = client_id,  
            redirect_uri = redirect_uri,
            state = state,
            scope = "offline_access https://graph.microsoft.com/.default",
            response_type = "code",
            response_mode = "query",
            login = "login",
            acr_values = "urn:microsoft:policies:mfa"
        ])
    in
        [
            LoginUri = authorizeUrl,
            CallbackUri = redirect_uri,
            WindowHeight = 860,
            WindowWidth = 1024,
            Context = null
        ];

TokenMethod = (tokenUri, grantType, tokenField, parameter, optional scope as text) =>
    let
        queryString = [
            client_id = client_id,
            scope = if (scope <> null) then scope else "offline_access https://graph.microsoft.com/.default",
            grant_type = grantType,
            redirect_uri = redirect_uri
        ],
        queryWithCode = Record.AddField(queryString, tokenField, parameter),

        tokenResponse = Web.Contents(tokenUri, [
            Content = Text.ToBinary(Uri.BuildQueryString(queryWithCode)),
            Headers = [
                #"Content-type" = "application/x-www-form-urlencoded",
                #"Accept" = "application/json"
            ],
            ManualStatusHandling = {400, 401, 403} 
        ]),
        body = Json.Document(tokenResponse),
        result = if (Record.HasFields(body, {"error", "error_description"})) then 
                    error Error.Record(body[error], body[error_description], body)
                 else
                    body
    in 
        result;

Token.GetAccessToken = (optional tenantId as text, optional scope as text) =>
    let 
        authResult = if (tenantId <> null) then 
            TokenMethod("https://login.microsoftonline.com/" & tenantId & "/oauth2/v2.0/token", "refresh_token", "refresh_token", Extension.CurrentCredential()[refresh_token], scope)
        else
            TokenMethod(token_uri, "refresh_token", "refresh_token", Extension.CurrentCredential()[refresh_token], scope)
    in 
        authResult[access_token];

// Azure Active Directory

SecMgmtInsights.ConditionalAccessPolicies = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("conditionalAccessPolicy", schemaOnly, tenants, "beta", true, "/beta/identity/conditionalAccess/policies", query, schema, metadata)
    in 
        result;

SecMgmtInsights.Contracts = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("contract", schemaOnly, {}, "v1.0", true, "/v1.0/contracts", query, schema, metadata)
    in
        result;

SecMgmtInsights.CredentialUserRegistrationDetails = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("credentialUserRegistrationDetails", schemaOnly, tenants, "beta", true, "/beta/reports/credentialUserRegistrationDetails", query, schema, metadata)
    in
        result;

SecMgmtInsights.Devices = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("device", schemaOnly, tenants, "v1.0", true, "/v1.0/devices", query, schema, metadata)
    in
        result;

SecMgmtInsights.LicenseDetails = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("licenseDetails", schemaOnly, tenants, "v1.0", true, "/v1.0/users?$select=id", query, null, metadata, "tenantId = text, userId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "userId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/v1.0/users/" & [userId] & "/licenseDetails"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in
        result;

SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("identitySecurityDefaultsEnforcementPolicy", schemaOnly, tenants, "v1.0", false, "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", query, schema, metadata)
    in 
        result;

SecMgmtInsights.SignIns = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("signIn", schemaOnly, tenants, "beta", true, "/beta/auditLogs/signIns", query, schema, metadata)
    in 
        result;

 SecMgmtInsights.SubscribedSkus = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        removedTopParameter = if (query <> null and Text.Contains(query, "top")) then null else query,
        result = Request.GetData("subscribedSku", schemaOnly, tenants, "v1.0", true, "/v1.0/subscribedSkus", removedTopParameter, schema, metadata)
    in
        result;

SecMgmtInsights.Users = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) => 
    let
        result = Request.GetData("user", schemaOnly, tenants, "beta", true, "/beta/users", query, schema, metadata)
    in 
        result;

// Device Management

SecMgmtInsights.AndroidManagedStoreAccountEnterpriseSettings = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) => 
    let
        result = Request.GetData("androidManagedStoreAccountEnterpriseSettings", schemaOnly, tenants, "beta", false, "/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings", query, schema, metadata)
    in 
        result;

SecMgmtInsights.AppleMDMPushCertificate = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) => 
    let
        result = Request.GetData("dataSharingConsent", schemaOnly, tenants, "beta", false, "/beta/deviceManagement/appleMDMPushCertificate", query, schema, metadata)
    in 
        result;

SecMgmtInsights.DetectedApps = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("detectedApp", schemaOnly, tenants, "beta", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/detectedApps"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in
        result;

SecMgmtInsights.DetectedMalwareState = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("windowsDeviceMalwareState", schemaOnly, tenants, "beta", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState/detectedMalwareState"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.DeviceCompliancePolicies = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("deviceCompliancePolicy", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/deviceCompliancePolicies?$select=id,displayName,createdDateTime,description,lastModifiedDateTime,roleScopeTagIds,version", query, schema, metadata)
    in
        result;

SecMgmtInsights.DeviceCompliancePolicySettingStates = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("deviceCompliancePolicySettingState", schemaOnly, tenants, "beta", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text, policyId = text", (input as table) => 
            let
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates?$select=id"),
                policies = Rest.Feed(requests, true),
                renamePolicyIdColumn = Table.RenameColumns(policies, {"id", "policyId"}, MissingField.Ignore),
                stateRequests = Table.AddColumn(renamePolicyIdColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates/" & [policyId] & "/settingStates"),
                output = Rest.Feed(stateRequests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.DeviceCompliancePolicyStates = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let        
        result = Request.GetData("deviceCompliancePolicyState", schemaOnly, tenants, "v1.0", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.DeviceCompliancePolicySettingStateSummaries = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let        
        result = Request.GetData("deviceCompliancePolicySettingStateSummary", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries", query, schema, metadata)
    in
        result;

SecMgmtInsights.DeviceComplianceSettingStates = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let        
        result = Request.GetData("deviceComplianceSettingState", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries?$select=id", query, null, metadata, "tenantId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "secMgmtSearchValue"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries/" & [secMgmtSearchValue] & "/deviceComplianceSettingStates"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.DeviceConfigurationProfiles = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("deviceConfiguration", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/deviceConfigurations?$select=id,displayName,createdDateTime,description,lastModifiedDateTime,roleScopeTagIds,supportsScopeTags,deviceManagementApplicabilityRuleOsEdition,deviceManagementApplicabilityRuleOsVersion,deviceManagementApplicabilityRuleDeviceMode,version", query, schema, metadata)
    in
        result;

SecMgmtInsights.DeviceConfigurationProfileSettingStates = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("deviceConfigurationSettingState", schemaOnly, tenants, "beta", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text, policyId = text", (input as table) => 
            let
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates?$select=id"),
                policies = Rest.Feed(requests, true),
                renamePolicyIdColumn = Table.RenameColumns(policies, {"id", "policyId"}, MissingField.Ignore),
                stateRequests = Table.AddColumn(renamePolicyIdColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates/" & [policyId] & "/settingStates"),
                output = Rest.Feed(stateRequests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.DeviceConfigurationProfileStates = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let        
        result = Request.GetData("deviceConfigurationState", schemaOnly, tenants, "v1.0", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.DeviceManagement = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        removedTopParameter = if (query <> null and Text.Contains(query, "top")) then null else query,
        result = Request.GetData("deviceManagement", schemaOnly, tenants, "beta", false, "/beta/deviceManagement", removedTopParameter, schema, metadata)
    in
        result;

SecMgmtInsights.Intents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("deviceManagementIntent", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/intents", query, schema, metadata)
    in
        result;

SecMgmtInsights.ManagedDeviceOverview = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        removedTopParameter = if (query <> null and Text.Contains(query, "top")) then null else query,
        result = Request.GetData("managedDeviceOverview", schemaOnly, tenants, "beta", false, "/beta/deviceManagement/managedDeviceOverview", removedTopParameter, schema, metadata)
    in
        result;

SecMgmtInsights.ManagedDevices = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("managedDevice", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/managedDevices", query, schema, metadata)
    in
        result;

SecMgmtInsights.MobileAppDeviceStatuses = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("mobileAppInstallStatus", schemaOnly, tenants, "beta", true, "/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true", query, null, metadata, "tenantId = text, mobileAppId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "mobileAppId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/deviceStatuses"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.MobileAppUserStatuses = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("userAppInstallStatus", schemaOnly, tenants, "beta", true, "/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true", query, null, metadata, "tenantId = text, mobileAppId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "mobileAppId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/userStatuses"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.MobileApps = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("mobileApp", schemaOnly, tenants, "beta", true, "/beta/deviceAppManagement/mobileApps?$select=id,displayName,lastModifiedDateTime,roleScopeTagIds", query, schema, metadata)
    in 
        result;

SecMgmtInsights.RemoteActionAudits = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("remoteActionAudit", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/remoteActionAudits", query, schema, metadata)
    in 
        result;

SecMgmtInsights.SecurityBaselineSettingStates = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("securityBaselineSettingState", schemaOnly, tenants, "beta", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text, templateId = text", (input as table) => 
            let
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates?$select=id"),
                policies = Rest.Feed(requests, true),
                renamePolicyIdColumn = Table.RenameColumns(policies, {"id", "templateId"}, MissingField.Ignore),
                stateRequests = Table.AddColumn(renamePolicyIdColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates/" & [templateId] & "/settingStates"),
                output = Rest.Feed(stateRequests, true)
            in 
                output)
    in 
        result;

SecMgmtInsights.SecurityBaselineStates = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let     
        result = Request.GetData("securityBaselineState", schemaOnly, tenants, "beta", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates"),
                output = Rest.Feed(requests, true)
            in 
                output)
    in 
        result; 

SecMgmtInsights.SoftwareUpdateStatusSummary = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("softwareUpdateStatusSummary", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/softwareUpdateStatusSummary", query, schema, metadata)
    in 
        result;

SecMgmtInsights.SubscriptionState = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("deviceManagementSubscriptionState", schemaOnly, tenants, "beta", false, "/beta/deviceManagement/subscriptionState", query, schema, metadata)
    in
        result;

SecMgmtInsights.UserExperienceAnalyticsDevicePerformance = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("userExperienceAnalyticsDevicePerformance", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/userExperienceAnalyticsDevicePerformance", query, schema, metadata)
    in
        result;

SecMgmtInsights.UserExperienceAnalyticsDeviceStartupProcessPerformance = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("userExperienceAnalyticsDeviceStartupProcessPerformance", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/userExperienceAnalyticsDeviceStartupProcessPerformance", query, schema, metadata)
    in
        result;

SecMgmtInsights.WindowsAutopilotDeviceIdentities = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("windowsAutopilotDeviceIdentity", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/windowsAutopilotDeviceIdentities", query, schema, metadata)
    in 
        result;

SecMgmtInsights.WindowsAutopilotProfiles = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("windowsAutopilotDeploymentProfile", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/windowsAutopilotDeploymentProfiles", query, schema, metadata)
    in 
        result;

SecMgmtInsights.WindowsAutopilotSettings = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("windowsAutopilotSettings", schemaOnly, tenants, "beta", false, "/beta/deviceManagement/windowsAutopilotSettings", query, schema, metadata)
    in 
        result;

SecMgmtInsights.WindowsMalwareInformation = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("windowsMalwareInformation", schemaOnly, tenants, "beta", true, "/beta/deviceManagement/windowsMalwareInformation", query, schema, metadata)
    in
        result;

SecMgmtInsights.WindowsProtectionState = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("windowsProtectionState", schemaOnly, tenants, "beta", true, "/v1.0/deviceManagement/managedDevices?$select=id", query, null, metadata, "tenantId = text, deviceId = text", (input as table) => 
            let 
                renamedColumns = Table.RenameColumns(input, {"id", "deviceId"}, MissingField.Ignore),
                requests = Table.AddColumn(renamedColumns, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState"),
                output = Rest.Feed(requests, true, schema)
            in 
                output)
     in  
         result; 

// Entities

EntityTable = #table({"Entity", "Action"}, {
    { "ActivitySubscriptions", SecMgmtInsights.ActivitySubscriptions },
    { "Alerts", SecMgmtInsights.Alerts },
    { "AndroidManagedStoreAccountEnterpriseSettings", SecMgmtInsights.AndroidManagedStoreAccountEnterpriseSettings },
    { "AppleMDMPushCertificate", SecMgmtInsights.AppleMDMPushCertificate },
    { "AzureActiveDirectoryEvents", SecMgmtInsights.AzureActiveDirectoryEvents },
    { "ComplianceCaseEvents", SecMgmtInsights.ComplianceCaseEvents },
    { "ConditionalAccessPolicies", SecMgmtInsights.ConditionalAccessPolicies },
    { "Contracts", SecMgmtInsights.Contracts },
    { "Controls", SecMgmtInsights.Controls },
    { "CredentialUserRegistrationDetails", SecMgmtInsights.CredentialUserRegistrationDetails },
    { "DetectedApps", SecMgmtInsights.DetectedApps },
    { "DetectedMalwareState", SecMgmtInsights.DetectedMalwareState },
    { "DeviceActions", SecMgmtInsights.DeviceActions },
    { "DeviceCompliancePolicies", SecMgmtInsights.DeviceCompliancePolicies },
    // TODO - Determiner if the following function should be retried because of the new policy based (instead of device) approach due to efficency.
    { "DeviceCompliancePolicySettingStates", SecMgmtInsights.DeviceCompliancePolicySettingStates }, 
    { "DeviceCompliancePolicySettingStateSummaries", SecMgmtInsights.DeviceCompliancePolicySettingStateSummaries },
    { "DeviceCompliancePolicyStates", SecMgmtInsights.DeviceCompliancePolicyStates },
    { "DeviceComplianceSettingStates", SecMgmtInsights.DeviceComplianceSettingStates },
    { "DeviceConfigurationProfiles", SecMgmtInsights.DeviceConfigurationProfiles },
    { "DeviceConfigurationProfileSettingStates", SecMgmtInsights.DeviceConfigurationProfileSettingStates }, 
    { "DeviceConfigurationProfileStates", SecMgmtInsights.DeviceConfigurationProfileStates },
    { "DeviceManagement", SecMgmtInsights.DeviceManagement },
    { "Devices", SecMgmtInsights.Devices },
    { "DlpEvents", SecMgmtInsights.DlpEvents },
    { "ExchangeEvents", SecMgmtInsights.ExchangeEvents},
    { "GeneralEvents", SecMgmtInsights.GeneralEvents },
    { "HygieneTenantEvents", SecMgmtInsights.HygieneTenantEvents },
    { "IdentitySecurityDefaultsEnforcementPolicy", SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy },
    { "Intents", SecMgmtInsights.Intents },
    { "LicenseDetails", SecMgmtInsights.LicenseDetails },
    { "MailboxUsageDetail", SecMgmtInsights.MailboxUsageDetail }, 
    { "ManagedDeviceOverview", SecMgmtInsights.ManagedDeviceOverview },
    { "ManagedDevices", SecMgmtInsights.ManagedDevices },
    { "MobileAppDeviceStatuses", SecMgmtInsights.MobileAppDeviceStatuses },
    { "MobileAppUserStatuses", SecMgmtInsights.MobileAppUserStatuses },
    { "MobileApps", SecMgmtInsights.MobileApps },
    { "Office365ActivationsUserDetail", SecMgmtInsights.Office365ActivationsUserDetail },
    { "Office365ActiveUserDetails", SecMgmtInsights.Office365ActiveUserDetails },
    { "Office365ServicesUserCounts", SecMgmtInsights.Office365ServicesUserCounts },
    { "OneDriveUsageAccountDetail", SecMgmtInsights.OneDriveUsageAccountDetail },
    { "QuarantineReleaseMessage", SecMgmtInsights.QuarantineReleaseMessage },
    { "RemoteActionAudits", SecMgmtInsights.RemoteActionAudits },
    { "RiskDetections", SecMgmtInsights.RiskDetections },
    { "SafeAttachmentEvents", SecMgmtInsights.SafeAttachmentEvents }, 
    { "SafeLinksEvents", SecMgmtInsights.SafeLinksEvents },
    { "SecureScore", SecMgmtInsights.SecureScore },
    { "SecureScoreControlProfiles", SecMgmtInsights.SecureScoreControlProfiles },
    { "SecurityBaselineSettingStates", SecMgmtInsights.SecurityBaselineSettingStates },
    { "SecurityBaselineStates", SecMgmtInsights.SecurityBaselineStates },
    { "SecurityComplianceAlerts", SecMgmtInsights.SecurityComplianceAlerts },
    { "ServiceCurrentStatus", SecMgmtInsights.ServiceCurrentStatus },
    { "ServiceHistoricalStatus", SecMgmtInsights.ServiceHistoricalStatus },
    { "ServiceMessages", SecMgmtInsights.ServiceMessages },
    { "SharePointEvents", SecMgmtInsights.SharePointEvents },
    { "SharePointSiteUsageDetail", SecMgmtInsights.SharePointSiteUsageDetail },
    { "SignIns", SecMgmtInsights.SignIns },
    { "SoftwareUpdateStatusSummary", SecMgmtInsights.SoftwareUpdateStatusSummary },
    { "SubmissionEvents", SecMgmtInsights.SubmissionEvents },
    { "SubscribedSkus", SecMgmtInsights.SubscribedSkus },
    { "SubscriptionState", SecMgmtInsights.SubscriptionState },
    { "TeamsUserActivityUserDetail", SecMgmtInsights.TeamsUserActivityUserDetail },
    { "UserExperienceAnalyticsDevicePerformance", SecMgmtInsights.UserExperienceAnalyticsDevicePerformance },
    { "UserExperienceAnalyticsDeviceStartupProcessPerformance", SecMgmtInsights.UserExperienceAnalyticsDeviceStartupProcessPerformance },
    { "Users", SecMgmtInsights.Users },
    { "WindowsAutopilotDeviceIdentities", SecMgmtInsights.WindowsAutopilotDeviceIdentities }, 
    { "WindowsAutopilotProfiles", SecMgmtInsights.WindowsAutopilotProfiles }, 
    { "WindowsAutopilotSettings", SecMgmtInsights.WindowsAutopilotSettings },
    { "WindowsMalwareInformation", SecMgmtInsights.WindowsMalwareInformation },
    { "WindowsProtectionState", SecMgmtInsights.WindowsProtectionState },
    { "YammerActivityUserDetail", SecMgmtInsights.YammerActivityUserDetail }
});

GetActionForEntity = (entity as text) =>
    try 
        EntityTable{[Entity = entity]}[Action]
     otherwise
         let
             message = Text.Format("Could not find entity: '#{0}'", {entity})
         in
             Diagnostics.Trace(TraceLevel.Error, message, () => error message, true);

// Extensions

Diagnostics = Extension.LoadFunction("Diagnostics.pqm");

Diagnostics.LogValue = Diagnostics[LogValue];
Diagnostics.LogFailure = Diagnostics[LogFailure];
Diagnostics.WrapHandlers = Diagnostics[WrapHandlers];

Extension.LoadFunction = (name as text) =>
    let
        binary = Extension.Contents(name),
        asText = Text.FromBinary(binary)
    in
        Expression.Evaluate(asText, #shared);

Schema = Extension.LoadFunction("Schema.pqm");

Schema.GetKnownType = Schema[GetKnownType];

Table.ChangeType = Extension.LoadFunction("Table.ChangeType.pqm");
Table.GenerateByPage = Extension.LoadFunction("Table.GenerateByPage.pqm");
Table.ToNavigationTable = Extension.LoadFunction("Table.ToNavigationTable.pqm");

// GitHub

SecMgmtInsights.Controls = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then type table[tenantId = text, expectedValue = text, id = text, info = text, resource = text, #"type" = text] else 
            let 
                data = GitHub.GetContent("https://raw.githubusercontent.com/microsoft/secmgmt-insights-connector/master/controls/recommended.json"),
                controls = Table.FromList(data[controls], Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                expandRecord = Table.ExpandRecordColumn(controls, "Column1", {"expectedValue", "id", "info", "resource", "tenantFilter", "type"}, {"expectedValue", "id", "info", "resource", "tenantFilter", "type"}),

                GetControls = (tenantId as text) => 
                    let 
                        source = Table.SelectRows(expandRecord, each (List.Contains([tenantFilter], tenantId) = false))
                    in 
                        source,

               source = Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),
               appliedControls = Table.AddColumn(source, "Custom", each GetControls([tenantId])),
               expandcustom = Table.ExpandTableColumn(appliedControls, "Custom", {"expectedValue", "id", "info", "resource", "type"}, {"expectedValue", "id", "info", "resource", "type"})
            in 
                expandcustom
    in 
        output;

SecMgmtInsights.DeviceActions = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        GetActions = (input as table, expectedValue as text, id as text, resource as text, tenantId as text) => 
            let
                value = if(Table.HasColumns(input, "policyId")) then 
                        Table.SelectColumns(input, {"tenantId", "deviceId", "policyId", "setting", "state", "currentValue", "errorCode", "errorDescription" })
                    else 
                          let
                            appended = Table.AddColumn(input, "Column1", each [policyId = null, setting = null, state = null, currentValue = null, errorCode = null, errorDescription = null]),
                            expanded = Table.ExpandRecordColumn(appended, "Column1", {"policyId", "setting", "state", "currentValue", "errorCode", "errorDescription"})
                        in 
                            expanded,

                filterRows = Table.SelectRows(value, each ([setting] = id and [state] <> "compliant" and [tenantId] = tenantId))
            in 
                filterRows,

      GetPortalLink = (resource as text, tenantId as text) =>
            let 
                source = if resource = "deviceCompliancePolicy" then "https://endpoint.microsoft.com/" & tenantId & "/#blade/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu/policies" else "https://endpoint.microsoft.com/" & tenantId & "/#blade/Microsoft_Intune_DeviceSettings/DevicesMenu/configurationProfiles"
            in 
                source,

        output = if(schemaOnly) then 
                type table[tenantId = text, deviceId = text, #"type" = text, policyId = text, id = text, resource = text, expectedValue = text, currentValue = text, errorCode = number, errorDescription = text, state = text, info = text, portal = text]
            else 
                let 
                    controls = SecMgmtInsights.Controls(tenants, false),
                    deviceComplianceControls =  Table.SelectRows(controls, each [resource] = "deviceCompliancePolicy"),
                    deviceConfigurationControls = Table.SelectRows(controls, each [resource] = "deviceConfigurationPolicy"),

                    deviceCompliancePolicySettingStates = SecMgmtInsights.DeviceCompliancePolicySettingStates(tenants, false),
                    deviceConfigurationProfileSettingStates = SecMgmtInsights.DeviceConfigurationProfileSettingStates(tenants, false),

                    deviceComplianceActions = Table.AddColumn(deviceComplianceControls, "action", each GetActions(deviceCompliancePolicySettingStates, [expectedValue], [id], [resource], [tenantId])),
                    deviceConfigurationActions = Table.AddColumn(deviceConfigurationControls, "action", each GetActions(deviceConfigurationProfileSettingStates, [expectedValue], [id], [resource], [tenantId])),

                    combined = Table.Combine({deviceComplianceActions, deviceConfigurationActions}),
                    expanded = Table.ExpandTableColumn(combined, "action", {"deviceId", "policyId", "state", "currentValue", "errorCode", "errorDescription"}),
                    filtered = Table.SelectRows(expanded, each [deviceId] <> null and [policyId] <> null), 
                    
                    linkAdded = Table.AddColumn(filtered, "portal", each GetPortalLink([resource], [tenantId]))
                in 
                    linkAdded
    in 
        output;

// Helper

Request.GetData = (resource as text, schemaOnly as logical, tenants as list, version as text, isPaged as logical, relativeUrl as text, optional query, optional schema as type, optional metadata, optional additionalSchema as text, optional func as function) =>
    let
        result = if(schemaOnly) then 
                Schema.GetKnownType(metadata{[Version = version]}[Value], resource, if(additionalSchema <> null) then additionalSchema else "tenantId = text")
            else 
                let
                    requests = Graph.BuildRequests(tenants, relativeUrl, query),
                    data = Rest.Feed(requests, isPaged, schema),
                    output = if(func <> null) then func(data) else data
                in 
                    output
    in 
        result;

// Identity Protection 

SecMgmtInsights.RiskDetections = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("riskDetection", schemaOnly, tenants, "beta", true, "/beta/identityProtection/riskDetections", query, schema, metadata)
    in 
        result;

// Intelligent Security Graph

SecMgmtInsights.Alerts = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("alert", schemaOnly, tenants, "v1.0", true, "/v1.0/security/alerts", query, schema, metadata)
    in 
        result;

SecMgmtInsights.SecureScore = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("secureScore", schemaOnly, tenants, "v1.0", true, "/v1.0/security/secureScores", query, schema, metadata)
    in 
        result;

SecMgmtInsights.SecureScoreControlProfiles = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("secureScoreControlProfile", schemaOnly, tenants, "v1.0", true, "/v1.0/security/secureScoreControlProfiles", query, schema, metadata)
    in
        result;

// Navigation 
        
[DataSource.Kind="SecMgmtInsights", Publish="SecMgmtInsights.Publish"]
shared SecMgmtInsights.Contents =  Value.ReplaceType(SecMgmtInsights.NavigationTable, SecMgmtInsightsType);

SecMgmtInsights.NavigationTable = (optional tenants as list) as table =>
    let
        GetMetadata = (version as text) =>
            let
                data = Web.Contents(Uri.Combine(graph_endpoint, version & "/$metadata")), 
                buffered = Binary.Buffer(data), 
                metadata = Xml.Tables(buffered){0}[DataServices]{0}[#"http://docs.oasis-open.org/odata/ns/edm"]{0}[Schema]
            in 
                metadata,

        listOfTenants = if(tenants <> null and not List.IsEmpty(tenants)) then 
                tenants
            else if(tenants = null or List.IsEmpty(tenants)) then 
                Graph.GetTenant()[tenantId]
            else 
                Rest.GetPages(graph_endpoint & "/v1.0/contracts?$select=customerId", Token.GetAccessToken())[customerId],

        metadata = #table({"Version", "Value"}, {
            { "beta", GetMetadata("beta") },
            { "v1.0", GetMetadata("v1.0") }
        }),

        // Use our schema table as the source of top level items in the navigation tree
        entities = Table.SelectColumns(EntityTable, {"Entity"}),
        rename = Table.RenameColumns(entities, {{"Entity", "Name"}}),
        // Add Data as a calculated column
        withData = Table.AddColumn(rename, "Data", each SecMgmtInsights.View([Name], metadata, listOfTenants), type table),
        // Add ItemKind and ItemName as fixed text values
        withItemKind = Table.AddColumn(withData, "ItemKind", each "Table", type text),
        withItemName = Table.AddColumn(withItemKind, "ItemName", each "Table", type text),
        // Indicate that the node should not be expandable
        withIsLeaf = Table.AddColumn(withItemName, "IsLeaf", each true, type logical),
        // Generate the nav table
        navTable = Table.ToNavigationTable(withIsLeaf, {"Name"}, "Name", "Data", "ItemKind", "ItemName", "IsLeaf")
    in
        navTable;

SecMgmtInsights.View = (entity as text, metadata as table, tenants as list) as table =>
    let
        // Implementation of Table.View handlers.
        //
        // We wrap the record with Diagnostics.WrapHandlers() to get some automatic
        // tracing if a handler returns an error.
        //
        View = (state as record) => Table.View(null, Diagnostics.WrapHandlers([

            // Returns the table type returned by GetRows()
            GetType = () => CalculateSchema(state),

            // Called last - retrieves the data from the calculated URL
            GetRows = () => 
                let
                    finalSchema = CalculateSchema(state),
                    finalUrl = CalculateUrl(state),
                    // TODO - Need to change var finalUrl to query because the URL is calculated in another function downstream
                    result = GetActionForEntity(entity)(tenants, false, finalUrl, finalSchema),
                    appliedType = Table.ChangeType(result, finalSchema)
                in
                    appliedType,

            // GetRowCount - called when all we want is the total row count.
            // Most OData services support $count, but it only works if
            // no other query parameters are sent (i.e. $top, or $filter).
            // Our implementation will first check for other query state -
            // if there are any state fields set by other handlers, we
            // return "..." unimplemented, because we won't be able to fold
            // the request to the server.
            GetRowCount = () as number =>
                if (Record.FieldCount(Record.RemoveFields(state, {"Url", "Entity", "Schema"}, MissingField.Ignore)) > 0) then
                    ...
                else
                    let
                        newState = state & [ RowCountOnly = true ],
                        finalUrl = CalculateUrl(newState),
                        value = Rest.Scalar(finalUrl),
                        converted = Number.FromText(value)
                    in
                        converted,

            // OnTake - handles the Table.FirstN transform, limiting
            // the maximum number of rows returned in the result set.
            // The count value should be >= 0.
            OnTake = (count as number) =>
                let
                    value = if(count >= 1000) then 999 else count,
                    newState = state & [ Top = value ]
                in
                    @View(newState),

            // OnSkip - handles the Table.Skip transform.
            // The count value should be >= 0.
            OnSkip = (count as number) =>
                let
                    newState = state & [ Skip = count ]
                in
                    @View(newState),

            // OnSelectColumns - handles column selection
            OnSelectColumns = (columns as list) =>
                let
                    // get the current schema
                    currentSchema = CalculateSchema(state),
                    // get the columns from the current schema (which is an M Type value)
                    rowRecordType = Type.RecordFields(Type.TableRow(currentSchema)),
                    existingColumns = Record.FieldNames(rowRecordType),
                    // calculate the new schema
                    columnsToRemove = List.Difference(existingColumns, columns),
                    updatedColumns = Record.RemoveFields(rowRecordType, columnsToRemove),
                    newSchema = type table (Type.ForRecord(updatedColumns, false))
                in
                    @View(state & 
                        [ 
                            SelectColumns = columns,
                            Schema = newSchema
                        ]
                    ),

            // OnSort - receives a list of records containing two fields: 
            //    [Name]  - the name of the column to sort on
            //    [Order] - equal to Order.Ascending or Order.Descending
            // If there are multiple records, the sort order must be maintained.
            //
            // OData allows you to sort on columns that do not appear in the result
            // set, so we do not have to validate that the sorted columns are in our 
            // existing schema.
            OnSort = (order as list) =>
                let
                    // This will convert the list of records to a list of text,
                    // where each entry is "<columnName> <asc|desc>"
                    sorting = List.Transform(order, (o) => 
                        let
                            column = o[Name],
                            order = o[Order],
                            orderText = if (order = Order.Ascending) then "asc" else "desc"
                        in
                            column & " " & orderText
                    ),
                    orderBy = Text.Combine(sorting, ", ")
                in
                    @View(state & [ OrderBy = orderBy ]),

            //
            // Helper functions
            //
            // Retrieves the cached schema. If this is the first call
            // to CalculateSchema, the table type is calculated based on
            // entity name that was passed into the function.
            CalculateSchema = (state) as type =>
                if (state[Schema]? = null) then
                    GetActionForEntity(entity)(tenants, true, null, null, metadata)
                else
                    state[Schema],

            // Calculates the final URL based on the current state.
            CalculateUrl = (state) as text => 
                let
                    entity = "",

                    // Check for $count. If all we want is a row count,
                    // then we add /$count to the path value (following the entity name).
                    urlWithRowCount =
                        if (state[RowCountOnly]? = true) then
                            entity & "/$count"
                        else
                            entity,

                    // Uri.BuildQueryString requires that all field values
                    // are text literals.
                    defaultQueryString = [],

                    // Check for Top defined in our state
                    qsWithTop =
                        if (state[Top]? <> null) then
                            defaultQueryString & [ #"$top" = Number.ToText(state[Top]) ]
                        else
                            defaultQueryString,

                    // Check for Skip defined in our state
                    qsWithSkip = 
                        if (state[Skip]? <> null) then
                            qsWithTop & [ #"$skip" = Number.ToText(state[Skip]) ]
                        else
                            qsWithTop,

                    // Check for explicitly selected columns
                    qsWithSelect =
                        if (state[SelectColumns]? <> null) then
                            qsWithSkip & [ #"$select" = Text.Combine(List.RemoveItems(state[SelectColumns], {"tenantId"}), ",") ]
                        else
                            qsWithSkip,

                    qsWithOrderBy = 
                        if (state[OrderBy]? <> null) then
                            qsWithSelect & [ #"$orderby" = state[OrderBy] ]
                        else
                            qsWithSelect,

                    encodedQueryString = Uri.BuildQueryString(qsWithOrderBy),
                    finalUrl = urlWithRowCount & "?" & encodedQueryString
                in
                    finalUrl
        ]))
    in
        View([Entity = entity]);

// Network

GitHub.GetContent = (url as text) =>
    let
        response = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "application/json",
                    #"Accept-encoding" = "gzip"
                ], 
                ManualCredentials = true,
                ManualStatusHandling = {401, 403}
            ]),
        buffered = Binary.Buffer(response),
        result = Json.Document(buffered)
    in 
        result;

Graph.BuildRequests = (tenants as list, relativeUrl as text, optional query as text) =>
    let 
        request = if(query = null or query = "") then 
            Uri.Combine(graph_endpoint, relativeUrl)
        else if(Text.Contains(relativeUrl, "?")) then 
            Uri.Combine(graph_endpoint, relativeUrl) & "&" & Text.AfterDelimiter(query, "?")
        else 
            Uri.Combine(graph_endpoint, relativeUrl) & query,

        data = #table({"tenantId", "secMgmtInsightsScope", "secMgmtInsightsRequest"}, {{tenants, "https://graph.microsoft.com/.default", request}}),
        expandedList = Table.ExpandListColumn(data, "tenantId")
    in 
        expandedList;

Graph.GetTenant = () =>
    let
        data = Rest.GetPages(graph_endpoint & "/v1.0/organization", Extension.CurrentCredential()[access_token]),
        renamedColumns = Table.RenameColumns(data, {"id", "tenantId"}, MissingField.Ignore)
    in
        renamedColumns;

Rest.Feed = (requests as table, isPaged as logical, optional schema as type) => 
    let
        GetData = (input as record) =>
            let
                requestContainsTopQuery = Text.Contains(input[secMgmtInsightsRequest], "top="),

                data = try if(isPaged and not requestContainsTopQuery) then 
                        Rest.GetPages(input[secMgmtInsightsRequest], Token.GetAccessToken(input[tenantId], input[secMgmtInsightsScope]), schema)
                    else
                        Rest.GetContents(input[secMgmtInsightsRequest], Token.GetAccessToken(input[tenantId], input[secMgmtInsightsScope]), isPaged and requestContainsTopQuery, schema),

                response = if(data[HasError] or Table.IsEmpty(data[Value])) then 
                        let
                            listOfFields = List.RemoveMatchingItems(Record.FieldNames(input), { "secMgmtInsightsRequest" }),
                            tableFromRecord = Table.FromRecords({input}, listOfFields),
                            value = Table.ToRecords(tableFromRecord)
                        in
                            value
                else 
                    let 
                        base = Table.AddColumn(data[Value], "secMgmtInsightsBase", each input),
                        listOfFields = List.RemoveMatchingItems(Record.FieldNames(input), { "secMgmtInsightsRequest", "secMgmtSearchValue" }),
                        expanded = Table.ExpandRecordColumn(base, "secMgmtInsightsBase", listOfFields), 
                        value = Table.ToRecords(expanded)
                    in
                        value
            in 
                response,

        data = Table.AddColumn(requests, "Column1", each GetData(_)),
        buffered = Table.Buffer(data), 

        mergedLists = List.Combine(buffered[Column1]),
        tableFromList = Table.FromList(mergedLists, Splitter.SplitByNothing(), {"Column1"}),
        
        listOfColumns =  List.Union(List.Transform(mergedLists, each Record.FieldNames(_))),
        expandedRecord = Table.ExpandRecordColumn(tableFromList, "Column1", listOfColumns)
    in 
        expandedRecord;

Rest.GetContents = (url as text, token as text, isPaged as logical, optional schema as type) =>
    let 
        response = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "application/json;odata.metadata=minimal;odata.streaming=false;IEEE754Compatible=false",
                    #"Accept-encoding" = "gzip, deflate",
                    #"Authorization" = "Bearer " & token,
                    #"User-Agent" = "secmgmt-insights-connector" 
                ],
                ManualCredentials = true,
                ManualStatusHandling = {400, 401, 403}
            ]),
        buffered = Binary.Buffer(response),
        body = Json.Document(buffered), 
        nextLink = Rest.GetNextLink(body),

        data = if (isPaged and schema = null) then 
                Diagnostics.LogFailure(
                    "Error converting response body. Are the records uniform?",
                    () => Table.FromRecords(body[value])
                )
            else if(isPaged and schema <> null) then 
                let
                    asTable = Table.FromList(body[value], Splitter.SplitByNothing(), {"Column1"}),
                    fields = Record.FieldNames(Type.RecordFields(Type.TableRow(schema))),
                    expanded = Table.ExpandRecordColumn(asTable, "Column1", fields),
                    // TODO HACK
                    test = Table.RemoveColumns(expanded, {"tenantId"}, MissingField.Ignore)
                in
                    test
            else
                let
                    abstract = if(Type.Is(Value.Type(body), List.Type)) then body else {body}, 
                    contents = Table.FromList(abstract, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                  
                    firstRow = contents{0}?,
                    listOfColumns =  List.Union(List.Transform(abstract, each Record.FieldNames(_))),

                    value = if(firstRow = null) then Table.FromRows({}) else Table.ExpandRecordColumn(contents, "Column1", listOfColumns)
                in
                    value
    in 
        data meta [NextLink = nextLink];

Rest.GetNextLink = (response) as nullable text => Record.FieldOrDefault(response, "@odata.nextLink");

 Rest.GetPages = (url as text, token as text, optional schema as type) => Table.GenerateByPage((previous) => 
    let
        // if previous is null, then this is our first page of data
        nextLink = if (previous = null) then url else Value.Metadata(previous)[NextLink]?,
        // if NextLink was set to null by the previous call, we know we have no more data
        page = if (nextLink <> null) then Rest.GetContents(nextLink, token, true, schema) else null
    in
        page);

Rest.Scalar = (url as text) =>
    let
        token = Token.GetAccessToken(null, "https://graph.microsoft.com/.default"),

        response = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "text/plain",
                    #"Authorization" = "Bearer " & token,
                    #"User-Agent" = "secmgmt-insights-connector" 
                ],
                ManualCredentials = true,
                ManualStatusHandling = {400, 401, 403}
            ]),
        buffered = Binary.Buffer(response),
        value = Text.FromBinary(buffered)
    in 
        value;

ServiceCommunications.BuildRequests = (tenants as list, relativeUrl as text, optional queryString as text) =>
    let 
        source = #table({"tenantId", "secMgmtInsightsScope"}, {{tenants, "https://manage.office.com/.default"}}),
        expandedList = Table.ExpandListColumn(source, "tenantId"),
        data = Table.AddColumn(expandedList, "secMgmtInsightsRequest", each 
             if(queryString = null or queryString = "") then 
                "https://manage.office.com/api/v1.0/" & [tenantId] & relativeUrl 
            else if(Text.Contains(relativeUrl, "?")) then 
                "https://manage.office.com/api/v1.0/" & [tenantId] & relativeUrl & "&" & Text.AfterDelimiter(queryString, "?")
            else 
                "https://manage.office.com/api/v1.0/" & [tenantId] & relativeUrl & queryString)
    in 
        data;

// Office 365 Management Activity

 ManagementActivity.GetEvents = (tenants as list, contentType as text) =>
     let
        requests = ServiceCommunications.BuildRequests(tenants, "/activity/feed/subscriptions/content?contentType=" & contentType),
        availableContent = Rest.Feed(requests, false),
        renamedColumns = Table.RenameColumns(availableContent, {"contentUri", "secMgmtInsightsRequest"}, MissingField.Ignore),
        data = Rest.Feed(renamedColumns, false)
    in
        data;

SecMgmtInsights.ActivitySubscriptions = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, contentType = text, status = text, webhook = any]  
            else 
                let
                    requests = ServiceCommunications.BuildRequests(tenants, "/activity/feed/subscriptions/list"),
                    data = Rest.Feed(requests, false)
                in 
                    data
    in
        output;

SecMgmtInsights.AzureActiveDirectoryEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, ResultStatus = text, UserKey = text, Version = text, Workload = text, ClientIP = text, ObjectId = text, UserId = text, AzureActiveDirectoryEventType = text, ExtendedProperties = any, ModifiedProperties = any, Actor = any, ActorContextId = text, ActorIpAddress = text, InterSystemsId = text, IntraSystemId = text, SupportTicketId = text, Target = any, TargetContextId = text, ApplicationId = text]  
            else 
                ManagementActivity.GetEvents(tenants, "audit.azureactivedirectory")
    in
        output;

SecMgmtInsights.ComplianceCaseEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, UserKey = text, UserType = text, Version = number, Workload = text, ObjectId = text, UserId = text, Case = text, ExchangeLocations = any, ExtendedProperties = any, ObjectType = text, Parameters = any, PublicFolderLocations = any, Query = any, SharepointLocations = any]  
            else 
                let 
                    events = ManagementActivity.GetEvents(tenants, "audit.general"),
                    filtered = Table.SelectRows(events, each try [Operation] = "CaseAdded" or [Operation] = "CaseViewed" otherwise null)
                in
                    filtered
    in
        output;

SecMgmtInsights.DlpEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, UserKey = text, UserType = text, Version = text, Workload = text, ObjectId = text, UserId = text, IncidentId = text, PolicyDetails = any, SensitiveInfoDetectionIsIncluded = logical, ExchangeMetaData = any, SharePointMetaData = any, ExceptionInfo = text]  
            else 
                ManagementActivity.GetEvents(tenants, "dlp.all")
    in
        output;

SecMgmtInsights.ExchangeEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, ResultStatus = logical, UserKey = text, UserType = text, Version = text, Workload = text, ClientIP = any, ObjectId = text, UserId = text, AppId = text, ClientAppId = text, ExternalAccess = logical, OrganizationName = text, OriginatingServer = text, Parameters = any, SessionId = text]  
            else 
                let 
                    events = ManagementActivity.GetEvents(tenants, "audit.exchange"),
                    filtered = Table.SelectRows(events, each try [Operation] <> "DlpRuleMatch" otherwise null)
                in 
                    filtered
    in
        output;

SecMgmtInsights.HygieneTenantEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, ResultStatus = text, UserKey = text, UserType = text, Version = text, Workload = text, UserId = text, Audit = text, Event = text, EventId = text, EventValue = text, Reason = text]  
            else 
                let 
                    events = ManagementActivity.GetEvents(tenants, "audit.general"),
                    filtered = Table.SelectRows(events, each try [Operation] = "HygieneTenantEvents" otherwise null)
                in
                    filtered
    in
        output;

SecMgmtInsights.GeneralEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, ResultStatus = text,Version = text, Workload = text, UserId = text]  
            else 
                ManagementActivity.GetEvents(tenants, "audit.general")
    in
        output;

SecMgmtInsights.QuarantineReleaseMessage = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, ResultStatus = text, UserKey = text, UserType = text, Version = number, Worload = text, UserId = text, NetworkMessageId = text, ReleaseTo = text, RequestSource = text, RequestType = text]  
            else 
                let 
                    events = ManagementActivity.GetEvents(tenants, "audit.general"),
                    filtered = Table.SelectRows(events, each try [Operation] = "QuarantineReleaseMessage" otherwise null)
                in
                    filtered
    in
        output;

SecMgmtInsights.SafeAttachmentEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, UserKey = text, UserType = text, Version = text, Workload = text, ObjectId = text, UserId = text, AttachmentData = any, DetectionMethod = text, DetectionType = text, EventDeepLink = text, InternetMessageId = text, MessageTime = datetime, NetworkMessageId = text, P1Sender = text, P2Sender = text, Policy = text, PolicyAction = text, Recipients = any, SenderIp = text, Subject = text, Verdict = text]  
            else 
                let 
                    events = ManagementActivity.GetEvents(tenants, "audit.general"),
                    filtered = Table.SelectRows(events, each try [Operation] = "TIMailData" otherwise null)
                in
                    filtered
    in
        output;

SecMgmtInsights.SafeLinksEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, UserKey = text, UserType = text, Version = text, Workload = text, AppName = text, AppVersion = text, EventDeepLink = text, OS = text, SourceId = text, TimeOfClick = datetime, Url = text, UrlClickAction = text]
            else 
                let 
                    events = ManagementActivity.GetEvents(tenants, "audit.general"),
                    filtered = Table.SelectRows(events, each try [Operation] = "TIUrlClickData" otherwise null)
                in
                    filtered
    in
        output;

SecMgmtInsights.SecurityComplianceAlerts = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, ResultStatus = text, UserKey = text, UserType = text, Version = text, Workload = text, ObjectId = text, UserId = text, AlertId = text, AlertLinks = any, AlertType = text, Category = text, Comments = text, Data = any, Name = text, PolicyId = text, Severity = text, Source = text, Status = text] 
            else
                let
                    events = ManagementActivity.GetEvents(tenants, "audit.general"),
                    filtered = Table.SelectRows(events, each try [UserKey] = "SecurityComplianceAlerts" otherwise null)
                in 
                    filtered
    in 
        output;

SecMgmtInsights.SharePointEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, UserKey = text, UserType = text, Version = text, Workload = text, ClientIP = text, ObjectId = text, UserId = text, CorrelationId = text, EventSource = text, ItemType = text, ListId = text, ListItemUniqueId = text, Site = text, UserAgent = text, WebId = text, SourceFileExtension = text, SiteUrl = text, SourceFileName = text, SourceRelativeUrl = text]  
            else 
                ManagementActivity.GetEvents(tenants, "audit.sharepoint")
    in
        output;

SecMgmtInsights.SubmissionEvents = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, CreationTime = datetimezone, Id = text, Operation = text, OrganizationId = text, RecordType = text, UserKey = text, UserType = text, Version = text, Workload = text, ObjectId = text, UserId = text, BCLValue = text, ExtendedProperties = any, FilteringDate = datetime, KesMailId = text, Language = text, MessageDate = datetime, P1Sender = text, P1SenderDomain = text, P2Sender = text, P2SenderDomain = text, Recipients = any, RescanResult = any, SenderIP = text, Subject = text, SubmissionId = text, SubmissionState = text, SubmissionType = text]
            else 
                let 
                    events = ManagementActivity.GetEvents(tenants, "audit.general"),
                    filtered = Table.SelectRows(events, each try [Operation] = "AdminSubmission" or [Operation] = "UserSubmission" otherwise null)
                in
                    filtered
    in
        output;

// Office 365 Service Communication

SecMgmtInsights.ServiceCurrentStatus = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, Id = text, Workload = text, StatusDate = datetime, WorkloadDisplayName = text, Status = text, IncidentIds = any, FeatureGroupStatusCollection = any]  
            else 
                let
                    requests = ServiceCommunications.BuildRequests(tenants, "/ServiceComms/CurrentStatus"),
                    data = Rest.Feed(requests, true)
                in 
                    data
    in
        output;

SecMgmtInsights.ServiceHistoricalStatus = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, Id = text, Workload = text, StatusDate = datetime, WorkloadDisplayName = text, Status = text, IncidentIds = any, FeatureGroupStatusCollection = any]
            else 
                let
                    requests = ServiceCommunications.BuildRequests(tenants, "/ServiceComms/HistoricalStatus"),
                    data = Rest.Feed(requests, true)
                in 
                    data
    in
        output;

SecMgmtInsights.ServiceMessages = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        output = if(schemaOnly) then
                type table [tenantId = text, Id = text, Name = text, Title = text, StartTime = datetimezone, EndTime = datetimezone, Status = text, Messages = any, LastUpdatedTime = datetimezone, Workload = text, WorkloadDisplayName = text, Feature = text, FeatureDisplayName = text]
            else 
                let
                    requests = ServiceCommunications.BuildRequests(tenants, "/ServiceComms/Messages"),
                    data = Rest.Feed(requests, true)
                in 
                    data
    in
        output;

// Reporting

SecMgmtInsights.MailboxUsageDetail = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let 
        result = Request.GetData("mailboxUsageDetail", schemaOnly, tenants, "beta", true, "/beta/reports/getMailboxUsageDetail(period='D30')?$format=application/json", query, schema, metadata)
    in 
        result;

SecMgmtInsights.Office365ActivationsUserDetail = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("office365ActivationsUserDetail", schemaOnly, tenants, "beta", true, "/beta/reports/getOffice365ActivationsUserDetail?$format=application/json", query, schema, metadata)
    in 
        result;

SecMgmtInsights.Office365ActiveUserDetails = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("office365ActiveUserDetail", schemaOnly, tenants, "beta", true, "/beta/reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json", query, schema, metadata)
    in 
        result;

SecMgmtInsights.Office365ServicesUserCounts = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("office365ServicesUserCounts", schemaOnly, tenants, "beta", true, "/beta/reports/getOffice365ServicesUserCounts(period='D30')?$format=application/json", query, schema, metadata)
    in 
        result;

SecMgmtInsights.OneDriveUsageAccountDetail = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("oneDriveUsageAccountDetail", schemaOnly, tenants, "beta", true, "/beta/reports/getOneDriveUsageAccountDetail(period='D30')?$format=application/json", query, schema, metadata)
    in 
        result;

SecMgmtInsights.SharePointSiteUsageDetail = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("sharePointSiteUsageDetail", schemaOnly, tenants, "beta", true, "/beta/reports/getSharePointSiteUsageDetail(period='D30')?$format=application/json", query, schema, metadata)
    in 
        result;

SecMgmtInsights.TeamsUserActivityUserDetail = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("teamsUserActivityUserDetail", schemaOnly, tenants, "beta", true, "/beta/reports/getTeamsUserActivityUserDetail(period='D30')?$format=application/json", query, schema, metadata)
    in 
        result;

SecMgmtInsights.YammerActivityUserDetail = (tenants as list, schemaOnly as logical, optional query as text, optional schema as type, optional metadata as table) =>
    let
        result = Request.GetData("yammerActivityUserDetail", schemaOnly, tenants, "beta", true, "/beta/reports/getYammerActivityUserDetail(period='D30')?$format=application/json", query, schema, metadata)
    in 
        result;