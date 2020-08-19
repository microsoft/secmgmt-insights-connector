section SecMgmtInsights;

// Global variables

authorize_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
client_id = Text.FromBinary(Extension.Contents("client_id"));
graph_endpoint = "https://graph.microsoft.com";
logout_uri = "https://login.microsoftonline.com/logout.srf";
redirect_uri = "https://oauth.powerbi.com/views/oauthredirect.html";
token_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
version = "2.0-preview-1";

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
    model as (type text meta [
        Documentation.FieldCaption = "Operating Model",
        Documentation.FieldDescription = "Model for how the connector will operate",
        Documentation.AllowedValues = { "Customer", "Partner" },
        Documentation.DefaultValue = { "Partner" }
    ])) 
    as table meta [
        Documentation.Name = "SecMgmtInsights",
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

SecMgmtInsights.ConditionalAccessPolicies = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/identity/conditionalAccess/policies", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.Contracts = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests({}, "/v1.0/contracts", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.CredentialUserRegistrationDetails = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/reports/credentialUserRegistrationDetails", queryString),
        // TODO - If the tenant does not have an entiltment, then this request will fail with a HTTP 403
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.Devices = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/v1.0/devices", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", queryString),
        data = Rest.Feed(requests, false, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SignIns = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/auditLogs/signIns", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

 SecMgmtInsights.SubscribedSkus = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/v1.0/subscribedSkus", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.Users = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/v1.0/users", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

// Device Management

SecMgmtInsights.DetectedApps = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId]  & "/detectedApps"),
        data = Rest.Feed(requests, true, true, schemaOnly, "deviceId = text")
    in
        data;

SecMgmtInsights.DetectedMalwareState = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState/detectedMalwareState"),
        data = Rest.Feed(requests, true, true, schemaOnly, "deviceId = text")
    in 
        data;

SecMgmtInsights.DeviceCompliancePolicySettingStates = (tenants as list, schemaOnly as logical, optional queryString as text) => 
    let
        firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
        source = Rest.Feed(firstRequests, true, false, false),
        
        output = if(Table.IsEmpty(source)) then 
                let
                    value = if(schemaOnly) then type table [tenantId = text] else firstRequests
                in 
                    value
            else 
                let 
                    renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
                    policyRequests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates?$select=id"),
                    policies = Rest.Feed(policyRequests, true, false, false, "deviceId = text"),
                    policyIdRenamed = Table.RenameColumns(policies, {"id", "policyId"}),
                    requests = Table.AddColumn(policyIdRenamed, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates/" & [policyId] & "/settingStates"),
                    data = Rest.Feed(requests, true, true, schemaOnly, "deviceId = text")
                in 
                    data
    in 
        output;

SecMgmtInsights.DeviceCompliancePolicies = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/deviceCompliancePolicies?$select=id,displayName,lastModifiedDateTime,roleScopeTagIds", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.DeviceCompliancePolicyStates = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates"),
        data = Rest.Feed(requests, true, true, schemaOnly, "deviceId = text")
    in 
        data;

SecMgmtInsights.DeviceConfigurationProfiles = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/deviceConfigurations?$select=id,displayName,lastModifiedDateTime,roleScopeTagIds", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.DeviceConfigurationProfileSettingStates = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        policyRequests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates?$select=id"),
        policies = Rest.Feed(policyRequests, true, false, false, "deviceId = text"),
        policyIdRenamed = Table.RenameColumns(policies, {"id", "policyId"}),
        requests = Table.AddColumn(policyIdRenamed, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates/" & [policyId] & "/settingStates"),
        data = Rest.Feed(requests, true, true, schemaOnly, "deviceId = text")
    in 
        data;

SecMgmtInsights.DeviceConfigurationProfileStates = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let        
        firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates"),
        data = Rest.Feed(requests, true, true, schemaOnly, "deviceId = text")
    in 
        data;

SecMgmtInsights.Intents = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/intents", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.ManagedDevices = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/managedDevices", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.MobileAppDeviceStatuses = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        firstRequests = Graph.BuildRequests(tenants, "/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "mobileAppId"}),
        requests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/deviceStatuses"),
        data = Rest.Feed(requests, true, true, schemaOnly, "mobileAppId = text")
    in 
        data;

SecMgmtInsights.MobileAppUserStatuses = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        firstRequests = Graph.BuildRequests(tenants, "/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "mobileAppId"}),
        requests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/userStatuses"),
        data = Rest.Feed(requests, true, true, schemaOnly, "mobileAppId = text")
    in 
        data;

SecMgmtInsights.MobileApps = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/deviceAppManagement/mobileApps?$select=id,displayName,lastModifiedDateTime,roleScopeTagIds", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SecurityBaselineSettingStates = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        templateRequests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates?$select=id"),
        templates = Rest.Feed(templateRequests, true, false, false, "deviceId = text"),
        templateIdRenamed = Table.RenameColumns(templates, {"id", "templateId"}),
        requests = Table.AddColumn(templateIdRenamed, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates/" & [templateId] & "/settingStates"),
        data = Rest.Feed(requests, true, true, schemaOnly, "deviceId = text, templateId = text")
    in 
        data;

SecMgmtInsights.SecurityBaselineStates = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let        
        firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
        source = Rest.Feed(firstRequests, true, false, false),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates"),
        data = Rest.Feed(requests, true, true, schemaOnly, "deviceId = text")
    in 
        data; 

SecMgmtInsights.SoftwareUpdateStatusSummary = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        // TODO -  The query specified in the URI is not valid. The requested resource is not a collection. Query options $filter, $orderby, $count, $skip, and $top can be applied only on collections.
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/softwareUpdateStatusSummary", queryString),
        data = Rest.Feed(requests, false, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SubscriptionState = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        // TODO - Expression.Error: We cannot convert the value null to type Type. This is caused by schema not have support for enumeration types
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/subscriptionState", queryString),
        data = Rest.Feed(requests, false, true, schemaOnly)
    in
        data;

SecMgmtInsights.WindowsAutopilotDeviceIdentities = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/windowsAutopilotDeviceIdentities", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.WindowsAutopilotProfiles = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/windowsAutopilotDeploymentProfiles", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.WindowsMalwareInformation = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/deviceManagement/windowsMalwareInformation", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.WindowsProtectionState = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
         firstRequests = Graph.BuildRequests(tenants, "/v1.0/deviceManagement/managedDevices?$select=id"),
         source = Rest.Feed(firstRequests, true, false, false),
         renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
         requests = Table.AddColumn(renamedColumn, "secMgmtInsightsRequest", each graph_endpoint & "/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState"),
         data = Rest.Feed(requests, false, true, schemaOnly, "deviceId = text")
     in  
         data; 

// Entities

EntityTable = #table({"Entity", "Action"}, {
    { "Alerts", SecMgmtInsights.Alerts },
    { "ConditionalAccessPolicies", SecMgmtInsights.ConditionalAccessPolicies },
    { "Contracts", SecMgmtInsights.Contracts },
    { "Controls", SecMgmtInsights.Controls },
    { "CredentialUserRegistrationDetails", SecMgmtInsights.CredentialUserRegistrationDetails },
    { "DetectApps", SecMgmtInsights.DetectedApps },
    { "DetectedMalwareState", SecMgmtInsights.DetectedMalwareState },
    { "DeviceActions", SecMgmtInsights.DeviceActions },
    { "DeviceCompliancePolicySettingStates", SecMgmtInsights.DeviceCompliancePolicySettingStates },
    { "DeviceCompliancePolicies", SecMgmtInsights.DeviceCompliancePolicies },
    { "DeviceCompliancePolicyStates", SecMgmtInsights.DeviceCompliancePolicyStates },
    { "DeviceConfigurationProfiles", SecMgmtInsights.DeviceConfigurationProfiles },
    { "DeviceConfigurationProfileSettingStates", SecMgmtInsights.DeviceConfigurationProfileSettingStates },
    { "DeviceConfigurationProfileStates", SecMgmtInsights.DeviceConfigurationProfileStates },
    { "Devices", SecMgmtInsights.Devices },
    { "IdentitySecurityDefaultsEnforcementPolicy", SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy },
    { "Intents", SecMgmtInsights.Intents },
    { "MailboxUsageDetail", SecMgmtInsights.MailboxUsageDetail },
    { "ManagedDevices", SecMgmtInsights.ManagedDevices },
    { "MobileApps", SecMgmtInsights.MobileApps },
    { "MobileAppDeviceStatuses", SecMgmtInsights.MobileAppDeviceStatuses },
    { "MobileAppUserStatuses", SecMgmtInsights.MobileAppUserStatuses },
    { "Office365ActiveUserDetails", SecMgmtInsights.Office365ActiveUserDetails },
    { "Office365ServicesUserCounts", SecMgmtInsights.Office365ServicesUserCounts },
    { "OneDriveUsageAccountDetail", SecMgmtInsights.OneDriveUsageAccountDetail },
    { "RiskDetections", SecMgmtInsights.RiskDetections },
    { "RiskyUsers", SecMgmtInsights.RiskyUsers },
    { "SecureScore", SecMgmtInsights.SecureScore },
    { "SecureScoreControlProfiles", SecMgmtInsights.SecureScoreControlProfiles },
    { "SecurityBaselineSettingStates", SecMgmtInsights.SecurityBaselineSettingStates },
    { "SecurityBaselineStates", SecMgmtInsights.SecurityBaselineStates },
    { "ServiceCurrentStatus", SecMgmtInsights.ServiceCurrentStatus },
    { "ServiceHistoricalStatus", SecMgmtInsights.ServiceHistoricalStatus },
    { "SharePointSiteUsageDetail", SecMgmtInsights.SharePointSiteUsageDetail },
    { "SignIns", SecMgmtInsights.SignIns },
    { "SoftwareUpdateStatusSummary", SecMgmtInsights.SoftwareUpdateStatusSummary },
    { "SubscribedSkus", SecMgmtInsights.SubscribedSkus }, 
    { "SubscriptionState", SecMgmtInsights.SubscriptionState },
    { "TeamsUserActivityUserDetail", SecMgmtInsights.TeamsUserActivityUserDetail },
    { "Users", SecMgmtInsights.Users },
    { "WindowsAutopilotDeviceIdentities", SecMgmtInsights.WindowsAutopilotDeviceIdentities },
    { "WindowsAutopilotProfiles", SecMgmtInsights.WindowsAutopilotProfiles },
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

GetSchemaForEntity = (tenants as list, entity as text) as type => GetActionForEntity(entity)(tenants, true);

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

Schema.GetTable = Extension.LoadFunction("Schema.GetTable.pqm"); 
Table.ChangeType = Extension.LoadFunction("Table.ChangeType.pqm");
Table.GenerateByPage = Extension.LoadFunction("Table.GenerateByPage.pqm");
Table.ToNavigationTable = Extension.LoadFunction("Table.ToNavigationTable.pqm");

// GitHub

SecMgmtInsights.Controls = (tenants as list, schemaOnly as logical, optional queryString as text) =>
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

SecMgmtInsights.DeviceActions = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let

        GetActions = (func as function, expectedValue as text, id as text, resource as text, tenantId as text) => 
            let
                source = Table.SelectColumns(func(tenants, false), {"tenantId", "deviceId", "policyId", "setting", "state", "currentValue"}),
                filterRows = Table.SelectRows(source, each ([setting] = id and [state] <> "compliant" and [tenantId] = tenantId))
            in
                filterRows, 

        GetPortalLink = (resource as text, tenantId as text) =>
            let 
                source = if resource = "deviceCompliancePolicy" then "https://endpoint.microsoft.com/" & tenantId & "/#blade/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu/policies" else "https://endpoint.microsoft.com/" & tenantId & "/#blade/Microsoft_Intune_DeviceSettings/DevicesMenu/configurationProfiles"
            in 
                source,

        output = if(schemaOnly) then 
            type table[tenantId = text, deviceId = text, #"type" = text, policyId = text, id = text, resource = text, expectedValue = text, currentValue = text, state = text, info = text, poratl = text]
        else 
            let
                source = SecMgmtInsights.Controls(tenants, false),
        
                // TODO - When there are no device compliance policy setting states there will be an error 'tenantId column not found'
                deviceComplianceRecords = Table.SelectRows(source, each [resource] = "deviceCompliancePolicy"),
                deviceComplianceActions = Table.AddColumn(deviceComplianceRecords, "action", each GetActions(SecMgmtInsights.DeviceCompliancePolicySettingStates, [expectedValue], [id], [resource], [tenantId])),

                // TODO - When there are no device configuration profile setting states there will be an error 'tenantId column not found'
                deviceConfigurationRecords = Table.SelectRows(source, each [resource] = "deviceConfigurationPolicy"),
                deviceConfigurationActions = Table.AddColumn(deviceConfigurationRecords, "action", each GetActions(SecMgmtInsights.DeviceConfigurationProfileSettingStates, [expectedValue], [id], [resource], [tenantId])),
    
                combineTables = Table.Combine({deviceComplianceActions, deviceConfigurationActions}),
                expandTable = Table.ExpandTableColumn(combineTables, "action", {"deviceId", "policyId", "state", "currentValue"}, {"deviceId", "policyId", "state", "currentValue"}),
                addPortalColumn = Table.AddColumn(expandTable, "portal", each GetPortalLink([resource], [tenantId]))
            in 
                addPortalColumn
        in
            output;

// Identity Protection

SecMgmtInsights.RiskDetections = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/identityProtection/riskDetections", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.RiskyUsers = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/identityProtection/riskyUsers", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

// Intelligent Security Graph

SecMgmtInsights.Alerts = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/v1.0/security/alerts", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SecureScore = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/v1.0/security/secureScores", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SecureScoreControlProfiles = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/v1.0/security/secureScoreControlProfiles", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in
        data;

// Navigation

[DataSource.Kind="SecMgmtInsights", Publish="SecMgmtInsights.Publish"]
shared SecMgmtInsights.Contents = Value.ReplaceType(SecMgmtInsights.NavigationTable, SecMgmtInsightsType);

SecMgmtInsights.NavigationTable = (operatingModel as text) as table =>
    let
        contracts = Rest.GetPage(graph_endpoint & "/v1.0/contracts", Token.GetAccessToken()),

        // Use our schema table as the source of top level items in the navigation tree
        entities = Table.SelectColumns(EntityTable, {"Entity"}),
        rename = Table.RenameColumns(entities, {{"Entity", "Name"}}),
        // Add Data as a calculated column
        withData = Table.AddColumn(rename, "Data", each SecMgmtInsights.View([Name], contracts[customerId]), type table),
        // Add ItemKind and ItemName as fixed text values
        withItemKind = Table.AddColumn(withData, "ItemKind", each "Table", type text),
        withItemName = Table.AddColumn(withItemKind, "ItemName", each "Table", type text),
        // Indicate that the node should not be expandable
        withIsLeaf = Table.AddColumn(withItemName, "IsLeaf", each true, type logical),
        // Generate the nav table
        navTable = Table.ToNavigationTable(withIsLeaf, {"Name"}, "Name", "Data", "ItemKind", "ItemName", "IsLeaf")
    in
        navTable;

SecMgmtInsights.View = (entity as text, tenants as list) as table =>
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
                    result = GetActionForEntity(entity)(tenants, false, finalUrl),
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
                        value =  GetActionForEntity(entity)(tenants, false, finalUrl, tenants),
                        converted = Number.FromText(value)
                    in
                        converted,

            // OnTake - handles the Table.FirstN transform, limiting
            // the maximum number of rows returned in the result set.
            // The count value should be >= 0.
            OnTake = (count as number) =>
                let
                    size = if(count >= 1000) then 999 else count,
                    newState = state & [ Top = size ]
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
                    GetSchemaForEntity(tenants, entity)
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
                            qsWithSkip & [ #"$select" = Text.Combine(state[SelectColumns], ",") ]
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
        View([Entity = entity, Tenants = tenants]);

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

Rest.GetContents = (url as text, token as text, optional isPaged as logical) =>
    let 
        response = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "application/json;odata.metadata=minimal;odata.streaming=false;IEEE754Compatible=false",
                    #"Authorization" = "Bearer " & token,
                    #"User-Agent" = "secmgmt-insights-connector" 
                ],
                ManualCredentials = true,
                ManualStatusHandling = {400, 401, 403}
            ]),
        buffered = Binary.Buffer(response),
        body = Json.Document(buffered), 
        result = if (Record.HasFields(body, {"error"})) then 
                let 
                    source = if (body[error][code] = "Request_UnsupportedQuery" or Text.Contains(body[error][message], "Query option 'Top'")) then 
                            // TODO - This should only remove the top parameter and not the entire query string
                            Rest.GetContents(Text.BeforeDelimiter(url, "?"), token, isPaged)
                        else 
                            error Error.Record(body[error][code], body[error][message], body)
                in 
                    source
            else 
                let
                    value = if(isPaged <> null and isPaged) then 
                        Table.FromRecords(body[value])
                    else 
                        let
                            contents = Table.FromList({body}, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                            firstRow = contents{0}?,
                            value = if(firstRow = null) then Table.FromRows({}) else Table.ExpandRecordColumn(contents, "Column1", Record.FieldNames(firstRow[Column1]))
                        in
                            value
                    in
                        value,
        link = Record.FieldOrDefault(body, "@odata.nextLink")
    in
        result meta [Next = link];

 Rest.GetPage = (url as text, token as text) => Table.GenerateByPage((previous) => 
    let
        // If previous is null, then this is our first page of data
        next = if (previous = null) then url else Value.Metadata(previous)[Next]?,
        // If we have a next link, use it, otherwise use the original URL
        urlToUse = if (next <> null) then next else url,
        // If the next link was set to null by the previous call, we know we have no more data
        page = if (next <> null) then Rest.GetContents(urlToUse, token, true) else null
    in
        page);

// Office 365

SecMgmtInsights.MailboxUsageDetail = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests(tenants, "/beta/reports/getMailboxUsageDetail(period='D30')?$format=application/json", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.Office365ActiveUserDetails = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.Office365ServicesUserCounts = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/reports/getOffice365ServicesUserCounts(period='D30')?$format=application/json", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.OneDriveUsageAccountDetail = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/reports/getOneDriveUsageAccountDetail(period='D30')?$format=application/json", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SharePointSiteUsageDetail = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/reports/getSharePointSiteUsageDetail(period='D30')?$format=application/json", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.TeamsUserActivityUserDetail = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/reports/getTeamsUserActivityUserDetail(period='D30')?$format=application/json", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.YammerActivityUserDetail = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests(tenants, "/beta/reports/getYammerActivityUserDetail(period='D30')?$format=application/json", queryString),
        data = Rest.Feed(requests, true, true, schemaOnly)
    in 
        data;

// Office 365 Service Communication

SecMgmtInsights.ServiceCurrentStatus = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = ServiceCommunications.BuildRequests(tenants, "/ServiceComms/CurrentStatus"),
        data = Rest.Feed(requests, true, true, schemaOnly, "", true)
    in
        data;

SecMgmtInsights.ServiceHistoricalStatus = (tenants as list, schemaOnly as logical, optional queryString as text) =>
    let
        requests = ServiceCommunications.BuildRequests(tenants, "/ServiceComms/HistoricalStatus"),
        data = Rest.Feed(requests, true, true, schemaOnly, "", true)
    in
        data;

// Requests

Graph.BuildRequests = (tenants as list, relativeUrl as text, optional queryString as text) =>
    let 
        request = if(queryString = null or queryString = "") then 
            Uri.Combine(graph_endpoint, relativeUrl)
        else if(Text.Contains(relativeUrl, "?")) then 
            Uri.Combine(graph_endpoint, relativeUrl) & "&" & Text.AfterDelimiter(queryString, "?")
        else 
            Uri.Combine(graph_endpoint, relativeUrl) & queryString,

        data = #table({"tenantId", "secMgmtInsightsScope", "secMgmtInsightsRequest"}, {{tenants, "https://graph.microsoft.com/.default", request}}),
        expandedList = Table.ExpandListColumn(data, "tenantId")
    in 
        expandedList;

Rest.Feed = (requests as table, isPaged as logical, isSchemaRequired as logical, schemaOnly as logical, optional additionalSchema as text, optional inferSchema as logical) => 
    let
        // TODO - This can be optomized by checking if the requests are paged. If not then the first request does not need to be made because it will always return a HTTP 400
        GetContext = (request as text, scope as text, optional tenantId as text) =>
            let 
                context = try schemaCache{[entity = request]}[schema] otherwise
                    let 
                        parts = Uri.Parts(request),
                        queryString = if (Record.HasFields(parts[Query], "top")) then parts[Query][Top] = 1 else Record.AddField(parts[Query], "top", 1),
                        data = try Rest.GetContents(Text.Format("#{0}://#{1}:#{2}/#{3}?#{4}", {parts[Scheme], parts[Host], parts[Port], parts[Path], Uri.BuildQueryString(queryString)}), Token.GetAccessToken(tenantId, scope)) otherwise null,
                        value = if(data = null or Table.HasColumns(data, "error")) then 
                            let
                                contents = Rest.GetContents(request, Token.GetAccessToken(tenantId, scope))
                            in 
                                contents
                        else 
                            data,
                        addValueToCache = Table.InsertRows(schemaCache, 0, {[entity] = request, [schema] = value})
                    in
                        value
            in 
                context,

        GetData = (input as record) =>
            let
                data = try if(isPaged) then 
                        Rest.GetPage(input[secMgmtInsightsRequest], Token.GetAccessToken(input[tenantId], input[secMgmtInsightsScope]))
                    else
                        Rest.GetContents(input[secMgmtInsightsRequest], Token.GetAccessToken(input[tenantId], input[secMgmtInsightsScope]))
                    otherwise null,
                value = if(data = null) then null else 
                    let 
                        baseInfo = Table.AddColumn(data, "Base Info", each input), 
                        listOfFields = List.RemoveMatchingItems(Record.FieldNames(input), { "secMgmtInsightsRequest" }),
                        expandedRecord = Table.ExpandRecordColumn(baseInfo, "Base Info", listOfFields),
                        value = Table.ToRecords(expandedRecord)
                    in
                        value
            in 
                value,

        additionalSchmeaValue = if(additionalSchema = null or additionalSchema = "") then "tenantId = text" else "tenantId = text, " & additionalSchema,
        schemaCache = #table({"entity", "schema"}, {}),

        schema = if(not isSchemaRequired or (inferSchema <> null and inferSchema)) then 
            null 
        else 
            let
                data = Table.AddColumn(requests, "Column1", each GetContext([secMgmtInsightsRequest], [secMgmtInsightsScope], [tenantId])),
                nonNullRows = Table.SelectRows(data, each [Column1] <> null),
                context = if(Table.IsEmpty(nonNullRows)) then 
                        null 
                    else if(Table.HasColumns(nonNullRows{0}[Column1], "@odata.context")) then 
                        nonNullRows{0}[Column1][#"@odata.context"]{0}
                    else 
                        nonNullRows{0}[Column1][#"@odata.type"]{0},
                value = if(context = null) then null else Schema.GetTable(context, additionalSchmeaValue)
            in 
                value,

        inferredSchema = if(inferSchema <> null and inferSchema) then 
                let
                    data = Table.AddColumn(requests, "Column1", each GetContext([secMgmtInsightsRequest], [secMgmtInsightsScope], [tenantId])),
                    nonNullRows = Table.SelectRows(data, each [Column1] <> null),
                    values = Table.FromRecords(nonNullRows{0}[Column1][value]{0}),
                    columnNames = Table.ColumnNames(values),
                    value = Text.Combine(List.Transform(columnNames, each _), " = any, ") & " = any"
                in 
                    Expression.Evaluate("type table [tenantId = text, " & value & "]")
            else 
                null,

        response = if(schemaOnly) then 
            if(inferSchema <> null and inferSchema) then inferredSchema else schema
        else
            let
                data = Table.AddColumn(requests, "Column1", each GetData(_), schema),
        
                nonNullRows = Table.SelectRows(data, each [Column1] <> null),
                mergedLists = if(Table.IsEmpty(nonNullRows)) then null else List.Combine(nonNullRows[Column1]),
    
                output = if(List.IsEmpty(mergedLists)) then 
                        Table.FromRows({})
                    else if(mergedLists <> null) then 
                        let
                            tableFromList = Table.FromList(mergedLists, Splitter.SplitByNothing(), {"Column1"}),
                            listOfColumns = Record.FieldNames(tableFromList{0}[Column1]),
                            expandedRecord = Table.ExpandRecordColumn(tableFromList, "Column1", listOfColumns)
                        in
                            expandedRecord
                    else 
                        data
            in 
                output
    in 
        response;

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
