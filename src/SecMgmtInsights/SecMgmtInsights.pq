section SecMgmtInsights;

// Global variables

authorize_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
client_id = Text.FromBinary(Extension.Contents("client_id"));
graph_endpoint = "https://graph.microsoft.com";
logout_uri = "https://login.microsoftonline.com/logout.srf";
redirect_uri = "https://oauth.powerbi.com/views/oauthredirect.html";
token_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
version = "2.0";

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
    TestConnection = (dataSourcePath) => {"SecMgmtInsights.Contracts"}
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

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ConditionalAccessPolicies = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/identity/conditionalAccess/policies", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Contracts = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/v1.0/contracts", true, true, tenants),
        removedColumn = try Table.RemoveColumns(data, "tenantId") otherwise data,
        renamedColumn = Table.RenameColumns(removedColumn, {"customerId", "tenantId"}, MissingField.Ignore)
    in
        renamedColumn;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.CredentialUserRegistrationDetails = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/reports/credentialUserRegistrationDetails", true, true, tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Devices = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/devices", true, true, tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", false, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SignIns = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/auditLogs/signIns", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Users = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/users", true, true, tenants)
    in
        data;

// Device Management

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedApps = (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId]  & "/detectedApps"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "deviceId = text")
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedMalwareState = (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState/detectedMalwareState"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "deviceId = text")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicySettingStates = (optional tenants as list) as table => 
    let
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        policyRequests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates?$select=id"),
        policies = Request.NewGraphFeed(policyRequests, true, false, {"id", "tenantId"}, "deviceId = text"),
        policyIdRenamed = Table.RenameColumns(policies, {"id", "policyId"}),
        statesRequest = Table.AddColumn(policyIdRenamed, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates/" & [policyId] & "/settingStates"),
        data = Request.NewGraphFeed(statesRequest, true, true, {"id", "tenantId"}, "deviceId = text, policyId = text") 
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicies = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/deviceCompliancePolicies", true, true, tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicyStates = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/v1.0/deviceManagement/managedDevices?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "deviceId = text")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicies = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/deviceConfigurations", true, true, tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicySettingStates = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", true, false, tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        policies = Table.AddColumn(renamedColumns, "Column1", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates?$select=id", true, false, {[tenantId]}) otherwise null), 
        expandedTable = Table.ExpandTableColumn(policies, "Column1", {"id"}, {"policyId"}),
        data = Table.AddColumn(expandedTable, "Column1", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates/" & [policyId] & "/settingStates", true, true, {[tenantId]}) otherwise null)    
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicyStates = (optional tenants as list) as table =>
    let        
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "deviceId = text")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Intents = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/intents", true, true, tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ManagedDevices = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/managedDevices", true, true, tenants)
    in
        data;

// BUG - There weren't enough elements in the enumeration to complete the operation.
[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppDeviceStatuses = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "mobileAppId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/deviceStatuses"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "mobileAppId = text")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppInstallSummary = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "mobileAppId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/installSummary"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "mobileAppId = text")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppUserStatuses = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "mobileAppId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/userStatuses"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "mobileAppId = text")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileApps = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceAppManagement/mobileApps", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineSettingStates = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", true, true, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates?$select=id"),
        states = Request.NewGraphFeed(requests, true, false, {"id", "tenantId"}, "deviceId = text"),
        templateIdRenamed = Table.RenameColumns(states,{"id", "templateId"}),
        statesRequests = Table.AddColumn(templateIdRenamed, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates/" & [templateId] & "/settingStates"),
        data = Request.NewGraphFeed(statesRequests, true, true, {"id", "tenantId"}, "deviceId = text, templateId = text")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineStates = (optional tenants as list) as table =>
    let        
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "deviceId = text")
    in 
        data; 

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SoftwareUpdateStatusSummary = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/deviceManagement/softwareUpdateStatusSummary", false, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SubscriptionState = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/subscriptionState", false, true, tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserExperienceAnalyticsDevicePerformance = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/deviceManagement/userExperienceAnalyticsDevicePerformance", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotDeviceIdentities = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/deviceManagement/windowsAutopilotDeviceIdentities", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotProfiles = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/windowsAutopilotDeploymentProfiles", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotSettings = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/windowsAutopilotSettings", false, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsMalwareInformation = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/windowsMalwareInformation", true, true, tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsProtectionState = (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("/v1.0/deviceManagement/managedDevices?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState"),
        data = Request.NewGraphFeed(requests, false, true, {"id", "tenantId"}, "deviceId = text")
    in  
        data; 

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

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Controls = (optional tenants as list, optional jsonText as text) =>
    let
        data = if(jsonText = null or jsonText = "") then GitHub.GetContent("https://raw.githubusercontent.com/microsoft/secmgmt-insights-connector/master/controls/recommended.json") else Json.Document(jsonText),
        controls = Table.FromList(data[controls], Splitter.SplitByNothing(), null, null, ExtraValues.Error),
        expandRecord = Table.ExpandRecordColumn(controls, "Column1", {"expectedValue", "id", "info", "resource", "tenantFilter", "type"}, {"expectedValue", "id", "info", "resource", "tenantFilter", "type"}),

        GetControls = (tenantId as text) => 
            let 
                source = Table.SelectRows(expandRecord, each (List.Contains([tenantFilter], tenantId) = false))
            in 
                source,

       source = if (tenants = null or tenants = "") then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),
       appliedControls = Table.AddColumn(source, "Custom", each GetControls([tenantId])),
       expandcustom = Table.ExpandTableColumn(appliedControls, "Custom", {"expectedValue", "id", "info", "resource", "type"}, {"expectedValue", "id", "info", "resource", "type"})
    in 
        expandcustom;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceActions = (optional tenants as list, optional jsonText as text) =>
    let
        GetActions = (func as function, expectedValue as text, id as text, resource as text, tenantId as text) => 
            let
                source = Table.SelectColumns(func(tenants), {"tenantId", "deviceId", "policyId", "setting", "state", "currentValue"}),
                filterRows = Table.SelectRows(source, each ([setting] = id and [state] <> "compliant" and [tenantId] = tenantId))
            in
                filterRows, 

        GetPortalLink = (resource as text, tenantId as text) =>
            let 
                source = if resource = "deviceCompliancePolicy" then "https://endpoint.microsoft.com/" & tenantId & "/#blade/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu/policies" else "https://endpoint.microsoft.com/" & tenantId & "/#blade/Microsoft_Intune_DeviceSettings/DevicesMenu/configurationProfiles"
            in 
                source,

        source = SecMgmtInsights.Controls(tenants, jsonText), 
        
        deviceComplianceRecords = Table.SelectRows(source, each [resource] = "deviceCompliancePolicy"),
        deviceComplianceActions = Table.AddColumn(deviceComplianceRecords, "action", each GetActions(SecMgmtInsights.DeviceCompliancePolicySettingStates, [expectedValue], [id], [resource], [tenantId])),

        deviceConfigurationRecords = Table.SelectRows(source, each [resource] = "deviceConfigurationPolicy"),
        deviceConfigurationActions = Table.AddColumn(deviceComplianceRecords, "action", each GetActions(SecMgmtInsights.DeviceConfigurationPolicySettingStates, [expectedValue], [id], [resource], [tenantId])),
    
        combineTables = Table.Combine({deviceComplianceActions, deviceConfigurationActions}),
        expandTable = Table.ExpandTableColumn(combineTables, "action", {"deviceId", "policyId", "state", "currentValue"}, {"deviceId", "policyId", "state", "currentValue"}),
        addPortalColumn = Table.AddColumn(expandTable, "portal", each GetPortalLink([resource], [tenantId]))
    in 
        addPortalColumn;

// Identity Protection

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.RiskDetections = (optional tenants as list) as table =>
    let
        // TODO - This request requires a new permission to be added. With the test environment this is being left broken 
        // so we can fix the error handling and reporting
        data = Request.GraphFeed("/beta/identityProtection/riskDetections", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.RiskyUsers = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/identityProtection/riskyUsers", true, true, tenants)
    in 
        data;

// Information Protection 

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserDataLossPreventionPolicies = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/v1.0/users?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "userId"}), 
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/users/" & [userId] & "/informationProtection/dataLossPreventionPolicies"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "userId = text")
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserSensitivityLabels = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/v1.0/users?$select=id", true, false, tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "userId"}), 
        requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/users/" & [userId] & "/informationProtection/sensitivityLabels"),
        data = Request.NewGraphFeed(requests, true, true, {"id", "tenantId"}, "userId = text")
    in 
        data;

// Intelligent Security Graph

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Alerts = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/security/alerts", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScore = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/security/secureScores", true, true, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScoreControlProfiles = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/security/secureScoreControlProfiles", true, true, tenants)
    in
        data;

// Navigation 

[DataSource.Kind="SecMgmtInsights", Publish="SecMgmtInsights.Publish"]
shared SecMgmtInsights.Contents = (optional tenants as list) as table =>
    let 
        source = #table({"Name", "Data"}, {
            { "Alerts", SecMgmtInsights.Alerts(tenants) },
            { "ConditionalAccessPolicies", SecMgmtInsights.ConditionalAccessPolicies(tenants) },
            { "Contracts", SecMgmtInsights.Contracts(tenants) },
            { "Controls", SecMgmtInsights.Controls(tenants) },
            { "CredentialUserRegistrationDetails", SecMgmtInsights.CredentialUserRegistrationDetails(tenants) },
            { "DetectApps", SecMgmtInsights.DetectedApps(tenants) },
            { "DetectedMalwareState", SecMgmtInsights.DetectedMalwareState(tenants) },
            { "DeviceActions", SecMgmtInsights.DeviceActions(tenants) },
            { "DeviceCompliancePolicySettingStates", SecMgmtInsights.DeviceCompliancePolicySettingStates(tenants) },
            { "DeviceCompliancePolicies", SecMgmtInsights.DeviceCompliancePolicies(tenants) },
            { "DeviceCompliancePolicyStates", SecMgmtInsights.DeviceCompliancePolicyStates(tenants) },
            { "DeviceConfigurationPolicies", SecMgmtInsights.DeviceConfigurationPolicies(tenants) },
            { "DeviceConfigurationPolicySettingStates", SecMgmtInsights.DeviceConfigurationPolicySettingStates(tenants) },
            { "DeviceConfigurationPolicyStates", SecMgmtInsights.DeviceConfigurationPolicyStates(tenants) },
            { "Devices", SecMgmtInsights.Devices(tenants) },
            { "IdentitySecurityDefaultsEnforcementPolicy", SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy(tenants) },
            { "Intents", SecMgmtInsights.Intents(tenants) },
            { "MailboxUsageDetail", SecMgmtInsights.MailboxUsageDetail(tenants) },
            { "ManagedDevices", SecMgmtInsights.ManagedDevices(tenants) },
            { "MobileAppDeviceStatuses", SecMgmtInsights.MobileAppDeviceStatuses(tenants) },
            { "MobileAppInstallSummary", SecMgmtInsights.MobileAppInstallSummary(tenants) },
            { "MobileAppUserStatuses", SecMgmtInsights.MobileAppUserStatuses(tenants) },
            { "Office365ActiveUserDetails", SecMgmtInsights.Office365ActiveUserDetails(tenants) },
            { "Office365ServicesUserCounts", SecMgmtInsights.Office365ServicesUserCounts(tenants) },
            { "OneDriveUsageAccountDetail", SecMgmtInsights.OneDriveUsageAccountDetail(tenants) },
            { "RiskDetections", SecMgmtInsights.RiskDetections(tenants) },
            { "RiskyUsers", SecMgmtInsights.RiskyUsers(tenants) },
            { "SecureScore", SecMgmtInsights.SecureScore(tenants) },
            { "SecureScoreControlProfiles", SecMgmtInsights.SecureScoreControlProfiles(tenants) },
            { "SecurityBaselineSettingStates", SecMgmtInsights.SecurityBaselineSettingStates(tenants) },
            { "SecurityBaselineStates", SecMgmtInsights.SecurityBaselineStates(tenants) },
            { "ServiceCurrentStatus", SecMgmtInsights.ServiceCurrentStatus(tenants) },
            { "ServiceHistoricalStatus", SecMgmtInsights.ServiceHistoricalStatus(tenants) },
            { "SharePointSiteUsageDetail", SecMgmtInsights.SharePointSiteUsageDetail(tenants) },
            { "SignIns", SecMgmtInsights.SignIns(tenants) },
            { "SoftwareUpdateStatusSummary", SecMgmtInsights.SoftwareUpdateStatusSummary(tenants) },
            { "SubscribedSkus", SecMgmtInsights.SubscribedSkus(tenants) }, 
            { "SubscriptionState", SecMgmtInsights.SubscriptionState(tenants) },
            { "TeamsUserActivityUserDetail", SecMgmtInsights.TeamsUserActivityUserDetail(tenants) },
            { "UserSensitivityLabels", SecMgmtInsights.UserSensitivityLabels(tenants) },
            { "Users", SecMgmtInsights.Users(tenants) },
            { "WindowsAutopilotDeviceIdentities", SecMgmtInsights.WindowsAutopilotDeviceIdentities(tenants) },
            { "WindowsAutopilotProfiles", SecMgmtInsights.WindowsAutopilotProfiles(tenants) },
            { "WindowsAutopilotSettings", SecMgmtInsights.WindowsAutopilotSettings(tenants) },
            { "WindowsMalwareInformation", SecMgmtInsights.WindowsMalwareInformation(tenants) }, 
            { "WindowsProtectionState", SecMgmtInsights.WindowsProtectionState(tenants) },
            { "YammerActivityUserDetail", SecMgmtInsights.YammerActivityUserDetail(tenants) }
        }),
        navTable = Table.ToNavigationTable(source, {"Name"}, "Name", "Data", "ItemKind", "ItemName", "IsLeaf")
    in 
        navTable;

// Network

GitHub.GetContent = (url as text) =>
    let
        source = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "application/json",
                    #"Accept-encoding" = "gzip"
                ], 
                ManualCredentials = true,
                ManualStatusHandling = {401, 403}
            ]),
        buffered = Binary.Buffer(source),
        status = Value.Metadata(source)[Response.Status],
        result = if status = 401 then Json.Document(buffered)[error][message] else Json.Document(buffered)
    in 
        result;

Rest.GetContents = (url as text, optional token as text, optional isResponsePaged as logical) =>
    let
        source = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "application/json;odata.metadata=minimal;odata.streaming=false;IEEE754Compatible=false",
                    #"Accept-encoding" = "gzip",
                    #"Authorization" = "Bearer " & token,
                    #"User-Agent" = "secmgmt-insights-connector"], 
                ManualCredentials = if(token = null or token = "") then false else true,
                ManualStatusHandling = {400, 401, 403}
            ]),
        buffered = Binary.Buffer(source),
        status = Value.Metadata(source)[Response.Status],
        body = Json.Document(buffered),
        data = if (status = 401 or status = 403) then Error.Record("Access denied", "Have you verified the expected permissions are in place?", body) else 
            let
                value = if(isResponsePaged <> null and isResponsePaged) then 
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
        data meta [Next = link];

Rest.GetPage = (url as text, token as text) => Table.GenerateByPage((previous) => 
    let
        // if previous is null, then this is our first page of data
        next = if (previous = null) then url else Value.Metadata(previous)[Next]?,
        // if the next link was set to null by the previous call, we know we have no more data
        page = if (next <> null) then Rest.GetContents(next, token, true) else null
    in
        page);

// Office 365

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MailboxUsageDetail = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/reports/getMailboxUsageDetail(period='D30')?$format=application/json", true, false, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ActiveUserDetails = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json", true, false, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ServicesUserCounts = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getOffice365ServicesUserCounts(period='D30')?$format=application/json", true, false, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.OneDriveUsageAccountDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getOneDriveUsageAccountDetail(period='D30')?$format=application/json", true, false, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SharePointSiteUsageDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getSharePointSiteUsageDetail(period='D30')?$format=application/json", true, false, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.TeamsUserActivityUserDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getTeamsUserActivityUserDetail(period='D30')?$format=application/json", true, false, tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.YammerActivityUserDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getYammerActivityUserDetail(period='D30')?$format=application/json", true, false, tenants)
    in 
        data;

// Office 365 Service Communication

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ServiceCurrentStatus = (optional tenants as list) as table =>
    let
        data = Request.GetServiceCommData("ServiceComms/CurrentStatus", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ServiceHistoricalStatus = (optional tenants as list) as table =>
    let
        data = Request.GetServiceCommData("ServiceComms/HistoricalStatus", tenants)
    in
        data;

// Request

Request.NewGraphFeed = (requests as table, isResponsePaged as logical, isSchemaRequired as logical, optional columnsToRemove as list, optional additionalSchema as text) =>
    let
        GetContext = (relativeUrl as text, tenantId as text) =>
            let
                parts = Uri.Parts(graph_endpoint & relativeUrl),
                // BUG - The request for https://docs.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0&tabs=http does not support custom page size. 
                // So, this means the following query will fail which means the schema while detectable will be set to null and the table will not be expanded as excepted
                
                // TODO - This does not need to be called for each type, only if the type has not been discovered yet.
                data = try Rest.GetContents(Text.Format("#{0}://#{1}:#{2}/#{3}?$top=1", {parts[Scheme], parts[Host], parts[Port], parts[Path]}), Token.GetAccessToken(tenantId)) otherwise null
            in
                data,

        NewGetData = (input as record) =>
            let
                data = try if(isResponsePaged) then 
                        Rest.GetPage(graph_endpoint & input[relativeUrl], Token.GetAccessToken(input[tenantId]))
                    else
                        Rest.GetContents(graph_endpoint & input[relativeUrl], Token.GetAccessToken(input[tenantId]))
                    otherwise null,
                value = if(data = null) then null else 
                    let 
                        baseInfo = Table.AddColumn(data, "Base Info", each input), 
                        listOfFields = List.RemoveMatchingItems(Record.FieldNames(input), { "relativeUrl" }),
                        expandedRecord = Table.ExpandRecordColumn(baseInfo, "Base Info", listOfFields),
                        value = Table.ToRecords(expandedRecord)
                    in
                        value
            in 
                value,

        additionalSchmeaValue = if(additionalSchema = null or additionalSchema = "") then "tenantId = text" else "tenantId = text, " & additionalSchema,

        pagedSchema = if(isResponsePaged and isSchemaRequired) then
            let
                data = Table.AddColumn(requests, "Column1", each GetContext([relativeUrl], [tenantId])),
                nonNullRows = Table.SelectRows(data, each [Column1] <> null),
                context = if(Table.IsEmpty(nonNullRows)) then null else nonNullRows{0}[Column1][#"@odata.context"]{0},
                value = if(context = null) then null else Schema.GetTable(context, additionalSchmeaValue)
            in 
                value
        else
            null,

        data = Table.AddColumn(requests, "Column1", each NewGetData(_), pagedSchema),
        
        nonNullRows = Table.SelectRows(data, each [Column1] <> null),
        mergedLists = if(Table.IsEmpty(nonNullRows)) then null else List.Combine(nonNullRows[Column1]),

        resourceSchema = if(not isResponsePaged and isSchemaRequired) then 
            let 
                context = mergedLists{0}[#"@odata.context"],
                schema = Schema.GetTable(context, additionalSchmeaValue)
            in 
                schema 
            else 
                null,

        schema = if(isResponsePaged and isSchemaRequired) then pagedSchema else resourceSchema,
       
        changedType = if(mergedLists <> null and schema = null) then 
            let
                tableFromList = Table.FromList(mergedLists, Splitter.SplitByNothing(), {"Column1"}),
                listOfColumns = Record.FieldNames(tableFromList{0}[Column1]),
                expandedRecord = Table.ExpandRecordColumn(tableFromList, "Column1", listOfColumns)
            in
                expandedRecord
        else if (mergedLists = null) then 
            Table.ChangeType(data, schema) 
        else 
            Table.ChangeType(mergedLists, schema)
    in 
        changedType;

Request.GraphFeed = (relativeUrl as text, isResponsePaged as logical, isSchemaRequired as logical, optional tenants as list) =>
    let 
        source = if (tenants = null or List.IsEmpty(tenants)) then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),

        GetContext = (tenantId as text) =>
            let
                parts = Uri.Parts(graph_endpoint & relativeUrl),
                // BUG - The request for https://docs.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0&tabs=http does not support custom page size. 
                // So, this means the following query will fail which means the schema while detectable will be set to null and the table will not be expanded as excepted
                data = try Rest.GetContents(Text.Format("#{0}://#{1}:#{2}/#{3}?$top=1", {parts[Scheme], parts[Host], parts[Port], parts[Path]}), Token.GetAccessToken(tenantId)) otherwise null
            in
                data,

         GetData = (tenantId as text) =>
            let
                data = try if(isResponsePaged) then 
                        Rest.GetPage(graph_endpoint & relativeUrl, Token.GetAccessToken(tenantId))
                    else
                        Rest.GetContents(graph_endpoint & relativeUrl, Token.GetAccessToken(tenantId))
                    otherwise null,
                value = if(data = null) then null else 
                    let 
                        addedColumn = if(Table.HasColumns(data, "tenantId")) then data else Table.AddColumn(data, "tenantId", each tenantId),
                        value = Table.ToRecords(addedColumn)
                    in
                        value
            in 
                value,
    
        pagedSchema = if(isResponsePaged and isSchemaRequired) then
            let
                data = Table.AddColumn(source, "Column1", each GetContext([tenantId])),
                nonNullRows = Table.SelectRows(data, each [Column1] <> null),
                context = if(Table.IsEmpty(nonNullRows)) then null else nonNullRows{0}[Column1][#"@odata.context"]{0},
                value = if(context = null) then null else Schema.GetTable(context, "tenantId = text")
            in 
                value
        else
            null,

        data = Table.AddColumn(source, "Column1", each GetData([tenantId]), pagedSchema),
        
        nonNullRows = Table.SelectRows(data, each [Column1] <> null),
        mergedLists = if(Table.IsEmpty(nonNullRows)) then null else List.Combine(nonNullRows[Column1]),

        resourceSchema = if(not isResponsePaged and isSchemaRequired) then 
            let 
                context = mergedLists{0}[#"@odata.context"],
                schema = Schema.GetTable(context, "tenantId = text")
            in 
                schema 
            else 
                null,

        schema = if(isResponsePaged and isSchemaRequired) then pagedSchema else resourceSchema,
       
        changedType = if(mergedLists <> null and schema = null) then 
            let
                tableFromList = Table.FromList(mergedLists, Splitter.SplitByNothing(), {"Column1"}),
                listOfColumns = Record.FieldNames(tableFromList{0}[Column1]),
                expandedRecord = Table.ExpandRecordColumn(tableFromList, "Column1", listOfColumns)
            in
                expandedRecord
        else if (mergedLists = null) then 
            Table.ChangeType(data, schema) 
        else 
            Table.ChangeType(mergedLists, schema)
    in 
        changedType;

Request.GetServiceCommData = (relativeUrl as text, optional tenants as list) =>
    let 
        GetData = (tenantId as text) =>
            let
                data = Rest.GetContents("https://manage.office.com/api/v1.0/" & tenantId & "/" & relativeUrl, Token.GetAccessToken(tenantId, "https://manage.office.com/.default"))
            in 
                data,

        source = if (tenants = null or tenants = "") then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),
        data = Table.AddColumn(source, "Custom", each try GetData([tenantId]) otherwise null),

        // TODO - Service Communications is returning data with the @odata.context property. 

        expandedCustom = Table.ExpandTableColumn(data, "Custom", {"Name", "Value"}, {"Name", "Value"}),

        filteredRows = Table.SelectRows(expandedCustom, each [Name] = "value"), 
        filteredColumns = Table.SelectColumns(filteredRows, {"tenantId", "Value"}),
        expandedList = Table.ExpandListColumn(filteredColumns, "Value"),

        listOfColumns = Record.FieldNames(expandedList{0}[Value]), 
        expandedTable = Table.ExpandRecordColumn(expandedList, "Value", listOfColumns, listOfColumns)
    in
        data;

Request.GetTenant = () =>
    let
        data = Rest.GetContents(graph_endpoint & "/v1.0/organization?$select=id", Extension.CurrentCredential()[access_token], true),
        renamedColumns = Table.RenameColumns(data, {{"id", "tenantId"}}, MissingField.Ignore)
    in
        renamedColumns;

// Tenant 

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SubscribedSkus = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/v1.0/subscribedSkus", true, true, tenants)
    in
        data;
