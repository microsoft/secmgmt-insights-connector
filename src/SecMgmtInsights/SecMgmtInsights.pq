section SecMgmtInsights;

// Global variables

authorize_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
client_id = Text.FromBinary(Extension.Contents("client_id"));
graph_endpoint = "https://graph.microsoft.com/beta";
logout_uri = "https://login.microsoftonline.com/logout.srf";
redirect_uri = "https://oauth.powerbi.com/views/oauthredirect.html";
token_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";

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
            ManualStatusHandling = {400} 
        ]),
        body = Json.Document(tokenResponse),
        result = if (Record.HasFields(body, {"error", "error_description"})) then 
                    error Error.Record(body[error], body[error_description], body)
                 else
                    body
    in 
        result;

// Azure Active Directory

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ConditionalAccessPolicies = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("identity/conditionalAccess/policies", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Contracts = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("contracts", tenants),
        removeColumn = Table.RemoveColumns(data, "tenantId")
    in
        removeColumn;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.CredentialUserRegistrationDetails = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("reports/credentialUserRegistrationDetails", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Devices = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("devices", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy = (optional tenants as list) as table =>
    let
       data = Request.GraphFeed("policies/identitySecurityDefaultsEnforcementPolicy", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SignIns = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("auditLogs/signIns", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Users = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("users", tenants)
    in
        data;

// Device Management

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedApps= (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("deviceManagement/managedDevices?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"deviceId"}),
        data = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId]  & "/detectedApps", {[tenantId]}) otherwise null)
    in
        Table.ExpandData(data, {"@odata.context", "tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedMalwareState = (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("deviceManagement/managedDevices?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"deviceId"}),
        data = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState/detectedMalwareState", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"@odata.context", "tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicySettingStates = (optional tenants as list) as table => 
    let
        source = Request.GraphFeed("deviceManagement/managedDevices?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"deviceId"}),
        policies = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates?$select=id", {[tenantId]}) otherwise null), 
        expandPolicies  = Table.ExpandTableColumn(policies, "Custom", {"Column1"}, {"Column1"}),
        expandRecord = Table.ExpandRecordColumn(expandPolicies, "Column1", {"id"}, {"policyId"}),
        data = Table.AddColumn(expandRecord, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates/" & [policyId] & "/settingStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}, {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}),
        expandedSources = Table.ExpandListColumn(expandedRecord, "sources"),
        expandedSourcesRecord = Table.ExpandRecordColumn(expandedSources, "sources", {"id", "displayName"}, {"sources.id", "sources.displayName"})
    in 
        expandedSourcesRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicies = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceManagement/deviceCompliancePolicies", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicyStates = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("deviceManagement/managedDevices?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"deviceId"}),
        data = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"@odata.context", "tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicies = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceManagement/deviceConfigurations", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicySettingStates = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("deviceManagement/managedDevices?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"deviceId"}),
        policies = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates?$select=id", {[tenantId]}) otherwise null), 
        expandPolicies  = Table.ExpandTableColumn(policies, "Custom", {"Column1"}, {"Column1"}),
        expandRecord = Table.ExpandRecordColumn(expandPolicies, "Column1", {"id"}, {"policyId"}),
        data = Table.AddColumn(expandRecord, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates/" & [policyId] & "/settingStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}, {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}),
        expandedSourcesList = Table.ExpandListColumn(expandedRecord, "sources"),
        expandedSourcesRecord = Table.ExpandRecordColumn(expandedSourcesList, "sources", {"id", "displayName"}, {"sources.id", "sources.displayName"})
    in 
        expandedSourcesRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicyStates = (optional tenants as list) as table =>
    let        
        source = Request.GraphFeed("deviceManagement/managedDevices?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"deviceId"}),
        data = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"@odata.context", "tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Intents = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceManagement/intents", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ManagedDevices = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceManagement/managedDevices", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppDeviceStatuses = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.MobileApps(tenants),
        filteredRows = Table.SelectRows(source, each [isAssigned] = true),
        mobileApps = Table.SelectColumns(filteredRows, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(mobileApps, {{"id", "mobileAppId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GraphFeed("deviceAppManagement/mobileApps/" & [mobileAppId] & "/deviceStatuses", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "deviceName", "deviceId", "lastSyncDateTime", "mobileAppInstallStatusValue", "installState", "installStateDetail", "errorCode", "osVersion", "osDescription", "userName", "userPrincipalName", "displayVersion"}, {"id", "deviceName", "deviceId", "lastSyncDateTime", "mobileAppInstallStatusValue", "installState", "installStateDetail", "errorCode", "osVersion", "osDescription", "userName", "userPrincipalName", "displayVersion"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"lastSyncDateTime", type datetimezone}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppInstallSummary = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.MobileApps(tenants),
        filteredRows = Table.SelectRows(source, each [isAssigned] = true),
        mobileApps = Table.SelectColumns(filteredRows, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(mobileApps, {{"id", "mobileAppId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GraphFeed("deviceAppManagement/mobileApps/" & [mobileAppId] & "/installSummary", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "installedDeviceCount", "failedDeviceCount", "notApplicableDeviceCount", "notInstalledDeviceCount", "pendingInstallDeviceCount", "installedUserCount", "failedUserCount", "notApplicableUserCount", "notInstalledUserCount", "pendingInstallUserCount"}, {"id", "installedDeviceCount", "failedDeviceCount", "notApplicableDeviceCount", "notInstalledDeviceCount", "pendingInstallDeviceCount", "installedUserCount", "failedUserCount", "notApplicableUserCount", "notInstalledUserCount", "pendingInstallUserCount"}),
        changedType = Table.TransformColumnTypes(expandRecord, {{"installedDeviceCount", Int64.Type}, {"failedDeviceCount", Int64.Type}, {"notApplicableDeviceCount", Int64.Type}, {"notInstalledDeviceCount", Int64.Type}, {"pendingInstallDeviceCount", Int64.Type}, {"installedUserCount", Int64.Type}, {"failedUserCount", Int64.Type}, {"notApplicableUserCount", Int64.Type}, {"notInstalledUserCount", Int64.Type}, {"pendingInstallUserCount", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppUserStatuses = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.MobileApps(tenants),
        filteredRows = Table.SelectRows(source, each [isAssigned] = true),
        mobileApps = Table.SelectColumns(filteredRows, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(mobileApps, {{"id", "mobileAppId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GraphFeed("deviceAppManagement/mobileApps/" & [mobileAppId] & "/userStatuses", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "userName", "userPrincipalName", "installedDeviceCount", "failedDeviceCount", "notInstalledDeviceCount"}, {"id", "userName", "userPrincipalName", "installedDeviceCount", "failedDeviceCount", "notInstalledDeviceCount"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"installedDeviceCount", Int64.Type}, {"failedDeviceCount", Int64.Type}, {"notInstalledDeviceCount", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileApps = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceAppManagement/mobileApps", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineSettingStates = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.SecurityBaselineStates(tenants),
        filterColumns = Table.SelectColumns(source, {"tenantId", "deviceId", "id"}),
        renamedColumn =  Table.RenameColumns(filterColumns, {{"id", "templateId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates/" & [templateId] & "/settingStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "settingName", "state", "settingCategoryId"}, {"id", "settingName", "state", "settingCategoryId"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineStates = (optional tenants as list) as table =>
    let        
        source = Request.GraphFeed("deviceManagement/managedDevices?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"deviceId"}),
        data = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"@odata.context", "tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SoftwareUpdateStatusSummary = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("deviceManagement/softwareUpdateStatusSummary", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SubscriptionState = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceManagement/subscriptionState", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserExperienceAnalyticsDevicePerformance = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("deviceManagement/userExperienceAnalyticsDevicePerformance", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotDeviceIdentities = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("deviceManagement/windowsAutopilotDeviceIdentities", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotProfiles = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceManagement/windowsAutopilotDeploymentProfiles", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotSettings = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceManagement/windowsAutopilotSettings", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsMalwareInformation = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("deviceManagement/windowsMalwareInformation", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsProtectionState = (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("deviceManagement/managedDevices?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"deviceId"}),
        data = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState", {[tenantId]}) otherwise null)
    in
        Table.ExpandData(data, {"@odata.context", "tenantId"});

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

// Helper

Request.GraphFeed = (relativeUrl as text, optional tenants as list) as table =>
    let      
        GetData = (tenantId as text) =>
            let
                data = MicrosoftGraph.Feed(graph_endpoint & "/" & relativeUrl, Token.GetAccessToken(tenantId))
            in 
                data,

        source = if (tenants = null or tenants = "") then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),
        data = Table.AddColumn(source, "Custom", each GetData([tenantId]))
    in
        Table.ExpandData(data);

Request.GetServiceCommData = (relativeUrl as text, optional tenants as list) =>
    let 
        GetData = (tenantId as text) =>
            let
                data = Microsoft.GetPagedContent("https://manage.office.com/api/v1.0/" & tenantId & "/" & relativeUrl, Token.GetAccessToken(tenantId, "https://manage.office.com/.default")),
                expandedList = Table.ExpandListColumn(data, "Column1"),
                filteredRows = Table.SelectRows(expandedList, each [Column1] <> null)
            in 
                data,

        source = if (tenants = null or tenants = "") then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),
        data = Table.AddColumn(source, "Custom", each try GetData([tenantId]) otherwise null),
        expandColumn = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandList = Table.ExpandListColumn(expandColumn, "Column1")
    in
        expandList;

Request.GetTenant = () =>
    let
        data = Microsoft.GetPagedContent(graph_endpoint & "/organization", Extension.CurrentCredential()[access_token]),
        expandList = Table.ExpandListColumn(data, "Column1"),
        expandRecord = Table.ExpandRecordColumn(expandList, "Column1", {"id"}, {"tenantId"})
    in
        expandRecord;

Table.ExpandData = (data as table, optional columnsToRemove as list) =>
    let 
        expandedValue = if(Type.Is(Value.Type(Record.Field(data{0}[Custom]{0}, Table.ColumnNames(data{0}[Custom]){0})), type list)) then 
        let 
            source = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
            expandedList = Table.ExpandListColumn(source, "Column1"),
            removedColumns = if(columnsToRemove <> null) then Table.RemoveColumns(expandedList{0}[Column1], columnsToRemove) else expandedList{0}[Column1],
            listOfColumns = Record.FieldNames(removedColumns),
            expandedColumn = Table.ExpandRecordColumn(expandedList, "Column1", listOfColumns, listOfColumns)
        in 
            expandedColumn
    else 
        let
            removedColumns = if(columnsToRemove <> null) then Table.RemoveColumns(data{0}[Custom], columnsToRemove) else data{0}[Custom],
            listOfColumns = Table.ColumnNames(removedColumns), 
            expandedTable = Table.ExpandTableColumn(data, "Custom", listOfColumns, listOfColumns)
        in
            expandedTable
    in
        expandedValue;

Table.GenerateByPage = (getNextPage as function) as table =>
    let        
        listOfPages = List.Generate(
            () => getNextPage(null),            
            (lastPage) => lastPage <> null,     
            (lastPage) => getNextPage(lastPage) 
        ),
        tableOfPages = Table.FromList(listOfPages, Splitter.SplitByNothing(), {"Column1"}),
        firstRow = tableOfPages{0}?
    in
        if (firstRow = null) then
            Table.FromRows({})
        else        
            Value.ReplaceType(
                Table.ExpandTableColumn(tableOfPages, "Column1", Table.ColumnNames(firstRow[Column1])),
                Value.Type(firstRow[Column1])
            );

Table.ToNavigationTable = (
    table as table,
    keyColumns as list,
    nameColumn as text,
    dataColumn as text,
    itemKindColumn as text,
    itemNameColumn as text,
    isLeafColumn as text
) as table =>
    let
        tableType = Value.Type(table),
        newTableType = Type.AddTableKey(tableType, keyColumns, true) meta 
        [
            NavigationTable.NameColumn = nameColumn, 
            NavigationTable.DataColumn = dataColumn,
            NavigationTable.ItemKindColumn = itemKindColumn, 
            Preview.DelayColumn = itemNameColumn, 
            NavigationTable.IsLeafColumn = isLeafColumn
        ],
        navigationTable = Value.ReplaceType(table, newTableType)
    in
        navigationTable;

Token.GetAccessToken = (optional tenantId as text, optional scope as text) =>
    let 
        authResult = if (tenantId <> null) then 
            TokenMethod("https://login.microsoftonline.com/" & tenantId & "/oauth2/v2.0/token", "refresh_token", "refresh_token", Extension.CurrentCredential()[refresh_token], scope)
        else
            TokenMethod(token_uri, "refresh_token", "refresh_token", Extension.CurrentCredential()[refresh_token], scope)
    in 
        authResult[access_token];

// Identity Protection

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.RiskDetections = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("identityProtection/riskDetections", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.RiskyUsers = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("identityProtection/riskyUsers", tenants)
    in 
        data;

// Information Protection 

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserDataLossPreventionPolicies = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("users?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"userId"}),
        data = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("users/" & [userId] & "/informationProtection/dataLossPreventionPolicies", {[tenantId]}) otherwise null)
    in
        Table.ExpandData(data, {"@odata.context", "tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserSensitivityLabels = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("users?$select=id", tenants),
        expandColumn = Table.ExpandRecordColumn(source, "Column1", {"id"}, {"userId"}),
        data = Table.AddColumn(expandColumn, "Custom", each try Request.GraphFeed("users/" & [userId] & "/informationProtection/sensitivityLabels", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"@odata.context", "tenantId"});

// Intelligent Security Graph

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Alerts = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("security/alerts", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScore = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("security/secureScores", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScoreControlProfiles = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("security/secureScoreControlProfiles", tenants)
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

MicrosoftGraph.Contents = (url as text, token as text) =>
    let
        source = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "application/json",
                    #"Accept-encoding" = "gzip",
                    #"Authorization" = "Bearer " & token,
                    #"User-Agent" = "secmgmt-insights-connector"
                ], 
                ManualCredentials = true,
                ManualStatusHandling = {401, 403}
            ]),
        buffered = Binary.Buffer(source),
        status = Value.Metadata(source)[Response.Status],
        result = if status = 401 then Json.Document(buffered)[error][message] else if status = 403 then Json.Document(buffered) else Json.Document(buffered),
        link = try result[#"@odata.nextLink"] otherwise null
    in 
         Record.ToTable(result) meta [Next = link];

MicrosoftGraph.Feed = (url as text, token as text) => Table.GenerateByPage((previous) =>
    let
        // If we have a previous page, get its Next link from metadata on the page.
        next = if (previous <> null) then try Value.Metadata(previous)[Next] otherwise null else null,
        // If we have a next link, use it, otherwise use the original URL that was passed in.
        urlToUse = if (next <> null) then next else url,
        // If we have a previous page, but don't have a next link, then we're done paging. Otherwise retrieve the next page.
        current = if (previous <> null and next = null) then null else MicrosoftGraph.Contents(urlToUse, token),
        // If we got data back from the current page, get the link for the next page
        link = if (current <> null) then Value.Metadata(current)[Next] else null,
        // Check if the table has the value column
        flag = if(current <> null) then Table.Contains(current, [Name = "value"]) else null,
        // Microsoft Graph utilizes OData, so the value needs to be extracted
        data = if(flag = true) then Table.FromList(Table.SelectRows(current, each ([Name] = "value"))[Value], Splitter.SplitByNothing()) else if(flag = false) then Table.FromList({Record.FromList(current[Value], current[Name])}, Record.FieldValues, current[Name]) else null
    in
        data meta [Next=link]);

// Office 365

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MailboxUsageDetail = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("reports/getMailboxUsageDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ActiveUserDetails = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ServicesUserCounts = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("reports/getOffice365ServicesUserCounts(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.OneDriveUsageAccountDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("reports/getOneDriveUsageAccountDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SharePointSiteUsageDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("reports/getSharePointSiteUsageDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.TeamsUserActivityUserDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("reports/getTeamsUserActivityUserDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.YammerActivityUserDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("reports/getYammerActivityUserDetail(period='D30')?$format=application/json", tenants)
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

// Tenant 

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SubscribedSkus = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("subscribedSkus", tenants)
    in
        data;
