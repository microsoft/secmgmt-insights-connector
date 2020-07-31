section SecMgmtInsights;

// Global variables

authorize_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
client_id = Text.FromBinary(Extension.Contents("client_id"));
graph_endpoint = "https://graph.microsoft.com";
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
        data = Request.GraphFeed("/beta/identity/conditionalAccess/policies", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Contracts = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/v1.0/contracts", tenants),
        removeColumn = try Table.RemoveColumns(data, "tenantId") otherwise data
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.CredentialUserRegistrationDetails = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/reports/credentialUserRegistrationDetails", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Devices = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/devices", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy = (optional tenants as list) as table =>
    let
       data = Request.GraphContents("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SignIns = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/auditLogs/signIns", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Users = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/users", tenants)
    in
        data;

// Device Management

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedApps= (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        data = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId]  & "/detectedApps", {[tenantId]}) otherwise null)
    in
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedMalwareState = (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        data = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState/detectedMalwareState", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicySettingStates = (optional tenants as list) as table => 
    let
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        policies = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates?$select=id", {[tenantId]}) otherwise null), 
        expandedTable = Table.ExpandTableColumn(policies, "Custom", {"id"}, {"policyId"}),
        data = Table.AddColumn(expandedTable, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates/" & [policyId] & "/settingStates", {[tenantId]}) otherwise null)    
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicies = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/deviceCompliancePolicies", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicyStates = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/v1.0/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        data = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicies = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/deviceConfigurations", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicySettingStates = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        policies = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates?$select=id", {[tenantId]}) otherwise null), 
        expandedTable = Table.ExpandTableColumn(policies, "Custom", {"id"}, {"policyId"}),
        data = Table.AddColumn(expandedTable, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates/" & [policyId] & "/settingStates", {[tenantId]}) otherwise null)    
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicyStates = (optional tenants as list) as table =>
    let        
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        data = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/v1.0/deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Intents = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/intents", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ManagedDevices = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/managedDevices", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppDeviceStatuses = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true"),
        renamedColumn = Table.RenameColumns(source, {"id", "mobileAppId"}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GraphFeed("/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/deviceStatuses", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});


[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppInstallSummary = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true"),
        renamedColumn = Table.RenameColumns(source, {"id", "mobileAppId"}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GraphContents("/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/installSummary", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppUserStatuses = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceAppManagement/mobileApps?$select=id&filter=isAssigned+eq+true"),
        renamedColumn = Table.RenameColumns(source, {"id", "mobileAppId"}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GraphFeed("/beta/deviceAppManagement/mobileApps/" & [mobileAppId] & "/userStatuses", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileApps = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceAppManagement/mobileApps", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineSettingStates = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        states = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates?$select=id", {[tenantId]}) otherwise null),
        statesColumnsRenamed = Table.RenameColumns(Table.ExpandData(states, {"tenantId"}), {"id", "templateId"}),
        data = Table.AddColumn(statesColumnsRenamed, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates/" & [templateId] & "/settingStates", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineStates = (optional tenants as list) as table =>
    let        
        source = Request.GraphFeed("/beta/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "deviceId"}),
        data = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/beta/deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SoftwareUpdateStatusSummary = (optional tenants as list) as table =>
    let
        data = Request.GraphContents("/beta/deviceManagement/softwareUpdateStatusSummary", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SubscriptionState = (optional tenants as list) as table =>
    let 
        data = Request.GraphContents("/beta/deviceManagement/subscriptionState", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserExperienceAnalyticsDevicePerformance = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/deviceManagement/userExperienceAnalyticsDevicePerformance", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotDeviceIdentities = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/deviceManagement/windowsAutopilotDeviceIdentities", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotProfiles = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/windowsAutopilotDeploymentProfiles", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotSettings = (optional tenants as list) as table =>
    let 
        data = Request.GraphContents("/beta/deviceManagement/windowsAutopilotSettings", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsMalwareInformation = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/deviceManagement/windowsMalwareInformation", tenants)
    in
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsProtectionState = (optional tenants as list) as table =>
    let 
        source = Request.GraphFeed("/v1.0/deviceManagement/managedDevices?$select=id", tenants),
        renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GraphContents("/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState", {[tenantId]}) otherwise null)
    in
        Table.ExpandData(data, {"id", "tenantId"});

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

Extension.LoadFunction = (name as text) =>
    let
        binary = Extension.Contents(name),
        asText = Text.FromBinary(binary)
    in
        Expression.Evaluate(asText, #shared);

Request.GraphContents = (relativeUrl as text, optional tenants as list) =>
    let      
        source = if (tenants = null or tenants = "") then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),

        GetData = (tenantId as text) =>
            let
                data = Rest.Contents(graph_endpoint & relativeUrl, Token.GetAccessToken(tenantId)), 
                record = Record.FromTable(data)
            in 
                record, 

        // BUG - The typing will be lost when the table column is expanded because the schema type is not included in the AddColumn call
        // DEBUG - Temporarily adding try otherwise null, need to find a way to expose the errors
        data = Table.AddColumn(source, "Custom", each try GetData([tenantId]) otherwise null),

        nonNullRows = Table.SelectRows(data, each [Custom] <> null),
        listOfColumns = Record.FieldNames(nonNullRows{0}[Custom]), 
        expandedTable = Table.ExpandRecordColumn(data, "Custom", listOfColumns, listOfColumns),
        
        schema = Schema.GetTable(nonNullRows{0}[Custom][#"@odata.context"], "tenantId = text"),
        value = if(schema = null) then Table.RemoveColumns(expandedTable, {"@odata.context", "@odata.type"}, MissingField.Ignore) else Table.ChangeType(expandedTable, schema)
   in
       value;

Request.GraphFeed = (relativeUrl as text, optional tenants as list) =>
    let      
        source = if (tenants = null or tenants = "") then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),

        GetData = (tenantId as text) =>
            let
                data = Rest.Feed(graph_endpoint & relativeUrl, Token.GetAccessToken(tenantId))
            in 
                data,

        // BUG - The typing will be lost when the table column is expanded because the schema type is not included in the AddColumn call
        // DEBUG - Determine if we should return null or if there is a way to return the error without breaking the processing
        data = Table.AddColumn(source, "Custom", each try GetData([tenantId]) otherwise null),
        expandedCustom = Table.ExpandTableColumn(data, "Custom", {"Name", "Value"}, {"Name", "Value"}),
        context = expandedCustom{0}[Value],

        filteredRows = Table.SelectRows(expandedCustom, each [Name] = "value"), 
        filteredColumns = Table.SelectColumns(filteredRows, {"tenantId", "Value"}),
        expandedList = Table.ExpandListColumn(filteredColumns, "Value"),
        schema = Schema.GetTable(context, "tenantId = text"),

        entries = if(expandedList{0}[Value] = null) then 
                expandedList 
            else 
                let
                    listOfColumns = Record.FieldNames(expandedList{0}[Value]), 
                    expandedTable = Table.ExpandRecordColumn(expandedList, "Value", listOfColumns, listOfColumns)
                in 
                    expandedTable,

        value = if(schema = null) then Table.RemoveColumns(entries, {"@odata.context", "@odata.type"}, MissingField.Ignore) else Table.ChangeType(entries, schema)
   in
       value;

Request.GetServiceCommData = (relativeUrl as text, optional tenants as list) =>
    let 
        GetData = (tenantId as text) =>
            let
                data = Rest.Feed("https://manage.office.com/api/v1.0/" & tenantId & "/" & relativeUrl, Token.GetAccessToken(tenantId, "https://manage.office.com/.default"))
            in 
                data,

        source = if (tenants = null or tenants = "") then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),
        data = Table.AddColumn(source, "Custom", each try GetData([tenantId]) otherwise null),

        expandedCustom = Table.ExpandTableColumn(data, "Custom", {"Name", "Value"}, {"Name", "Value"}),

        filteredRows = Table.SelectRows(expandedCustom, each [Name] = "value"), 
        filteredColumns = Table.SelectColumns(filteredRows, {"tenantId", "Value"}),
        expandedList = Table.ExpandListColumn(filteredColumns, "Value"),

        listOfColumns = Record.FieldNames(expandedList{0}[Value]), 
        expandedTable = Table.ExpandRecordColumn(expandedList, "Value", listOfColumns, listOfColumns)
    in
        expandedTable;

Request.GetTenant = () =>
    let
        data = Rest.Feed(graph_endpoint & "/v1.0/organization?$select=id", Extension.CurrentCredential()[access_token]),
        schema = Schema.GetTable(data{0}[Value]), 
        value = Table.ChangeType(data{1}[Value], schema),
        renamedColumns = Table.RenameColumns(value, {{"id", "tenantId"}})
    in
        renamedColumns;

Schema.GetEntityFromEntitySet = (entityContainer as table, value as text) =>
    let
        entity = if(Text.Contains(value, "microsoft.graph.")) then List.Last(Text.Split(value, ".")) else if(Text.Contains(value, "Collection(")) then
                null
            else
                let
                    entitySetTable = entityContainer{0}[EntitySet],
                    entityValue = Table.SelectRows(entitySetTable, each [#"Attribute:Name"] = Text.BeforeDelimiter(value, "(")),
                    entity = Text.Split(entityValue{0}[#"Attribute:EntityType"], "."){2}
                in 
                    entity
    in 
        entity;

Schema.GetEntityFromSingleton = (entityContainer as table, entityType as table, values as list) =>
    let 
        singletonTable = entityContainer{0}[Singleton],
        singletonValue = Table.SelectRows(singletonTable, each [#"Attribute:Name"] = values{0}),
        singleton = Text.Split(singletonValue{0}[#"Attribute:Type"], "."){2},
        
        filtered = Table.SelectRows(entityType, each [#"Attribute:Name"] = singleton),
        property = if(filtered{0}[Property] <> null) then Table.SelectRows(filtered{0}[Property], each [#"Attribute:Name"] = values{1}) else null,

        entity = if(property <> null and not Table.IsEmpty(property)) then 
            let 
                value = Text.Split(property{0}[#"Attribute:Type"], "."){1}
            in 
                value
            else 
                Schema.GetTypeFromNavigationProperty(entityType, singleton, values)
    in 
        entity;

Schema.GetEntityProperties = (entityType as table, entity as text, tables as list) =>
    let 
        entry = Table.SelectRows(entityType, each [#"Attribute:Name"] = entity),
        properties = List.InsertRange(tables, 0, entry[Property]),
        value = if(entry{0}[#"Attribute:BaseType"] = null) then properties else @Schema.GetEntityProperties(entityType, Text.AfterDelimiter(entry{0}[#"Attribute:BaseType"], "."), properties)
    in 
        value;

Schema.GetEntityType = (entityContainer as table, entityType as table, value as text) => 
    let 
        parts = Text.Split(value, "/"),
        removedEntity = if(List.Last(parts) = "$entity") then List.RemoveLastN(parts, 1) else parts,
        entity = if(List.Count(removedEntity) = 1) then Schema.GetEntityFromEntitySet(entityContainer, value) else Schema.GetEntityFromSingleton(entityContainer, entityType, removedEntity)
    in 
        entity;

Schema.GetTable = (context as text, optional additionalTypes as text) =>
    let
        schema = Xml.Tables(Web.Contents(Text.BeforeDelimiter(context, "$") & "$metadata")){0}[DataServices]{0}[#"http://docs.oasis-open.org/odata/ns/edm"]{0}[Schema],

        entity = Schema.GetEntityType(schema{0}[EntityContainer], schema{0}[EntityType], Text.AfterDelimiter(context, "#")),
        entityType = Table.SelectRows(schema{0}[EntityType], each [#"Attribute:Name"] = entity),
  
        GetData = (row as any) => 
            let
                data = if(Record.HasFields(row, "Attribute:Nullable") and row[#"Attribute:Nullable"] <> null and row[#"Attribute:Nullable"] = true) then 
                    [Entity = row[#"Attribute:Name"], Type = " nullable " & GetDataType(row[#"Attribute:Type"])] 
                else 
                    [Entity = row[#"Attribute:Name"], Type = GetDataType(row[#"Attribute:Type"])]
            in 
                data,

        GetDataType = (value) as text =>
            if (value = "Edm.Boolean") then "logical" else if (value = "Collection(Edm.String)") then "list" 
                else if (value = "Edm.DateTimeOffset") then "datetimezone"  else if (value = "Edm.Int32") then "number" 
                else if(value = "Edm.String") then "text" else "any",

        output = if(Table.IsEmpty(entityType)) then 
            null 
        else
            let 
                // Build the schema table based on data from the property table
                propertyTableList = Schema.GetEntityProperties(schema{0}[EntityType], entity, {}),
                convertedTable = Table.FromList(propertyTableList, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                propertyTable = Table.ExpandTableColumn(convertedTable, "Column1", {"Attribute:Name", "Attribute:Type", "Attribute:Nullable"}, {"Attribute:Name", "Attribute:Type", "Attribute:Nullable"}),
                addedSchema = Table.AddColumn(propertyTable, "schema", each GetData(_)),
                schemaTable = Table.FromList(addedSchema[schema], Splitter.SplitByNothing(), null, null, ExtraValues.Error),
                expandedColumn = Table.ExpandRecordColumn(schemaTable, "Column1", {"Entity", "Type"}, {"Entity", "Type"}),

                // Build the filter 
                parts = Text.Split(Text.AfterDelimiter(context, "#"), "/"),
                filter = if(List.Last(parts) = "$entity") then Text.BetweenDelimiters(List.LastN(parts, 2){0}, "(", ")") else Text.BetweenDelimiters(List.Last(parts), "(", ")"),
                filterList = Text.Split(filter, ","),

                // Remove the columns that are not included in the filter
                filteredTable = if(filter = null or filter = "") then expandedColumn else Table.SelectRows(expandedColumn, each List.Contains(filterList, [Entity])),

                custom = Table.AddColumn(filteredTable, "Expression", each [Entity] & " = " & [Type]),
                output = if(additionalTypes = null or additionalTypes = "") then Expression.Evaluate("type table [" & Text.Combine(custom[Expression], ", ") & "]") else Expression.Evaluate("type table [" & additionalTypes & "," & Text.Combine(custom[Expression], ", ") & "]")
            in 
                output
    in
        output;

Schema.GetTypeFromNavigationProperty = (entityType as table, entityName as text, values as list) =>
    let
        filtered = Table.SelectRows(entityType, each [#"Attribute:Name"] = entityName),

        dataTable = if(filtered{0}[NavigationProperty] = null) then 
                    Table.SelectRows(filtered{0}[Property], each [#"Attribute:Name"] = Text.BeforeDelimiter(values{1}, "("))
                else
                    Table.SelectRows(filtered{0}[NavigationProperty], each [#"Attribute:Name"] = Text.BeforeDelimiter(values{1}, "(")), 

        resource = dataTable{0}[#"Attribute:Type"], 
        entity = if(Text.Contains(resource, "(")) then Text.AfterDelimiter(Text.BetweenDelimiters(resource, "(", ")"), ".") else Text.AfterDelimiter(resource, "."),

        value = if(List.Count(values) <= 2) then entity else @Schema.GetTypeFromNavigationProperty(entityType, entity, List.RemoveFirstN(values, 1))
    in 
        value;

Table.ChangeType = Extension.LoadFunction("Table.ChangeType.pqm");

Table.ExpandData = (data as table, optional columnsToRemove as list) =>
    let 
        value = if(Table.IsEmpty(Table.SelectRows(data, each [Custom] <> null))) then 
                data
            else
                let 
                    nonNullRows = Table.SelectRows(data, each [Custom] <> null and not Table.HasColumns([Custom], "Value")),
                    removedColumns = if(columnsToRemove <> null) then Table.RemoveColumns(nonNullRows{0}[Custom], columnsToRemove) else nonNullRows{0}[Custom],
                    listOfColumns = Table.ColumnNames(removedColumns), 
                    expandedTable = Table.ExpandTableColumn(data, "Custom", listOfColumns, listOfColumns)
                in 
                    expandedTable
    in
        value;

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
        // TODO - This request requires a new permission to be added. With the test environment this is being left broken 
        // so we can fix the error handling and reporting
        data = Request.GraphFeed("/beta/identityProtection/riskDetections", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.RiskyUsers = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/identityProtection/riskyUsers", tenants)
    in 
        data;

// Information Protection 

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserDataLossPreventionPolicies = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/v1.0/users?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "userId"}), 
        data = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/beta/users/" & [userId] & "/informationProtection/dataLossPreventionPolicies", {[tenantId]}) otherwise null)
    in
        Table.ExpandData(data, {"tenantId"});

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserSensitivityLabels = (optional tenants as list) as table =>
    let
        source = Request.GraphFeed("/v1.0/users?$select=id", tenants),
        renamedColumns = Table.RenameColumns(source, {"id", "userId"}), 
        data = Table.AddColumn(renamedColumns, "Custom", each try Request.GraphFeed("/beta/users/" & [userId] & "/informationProtection/sensitivityLabels", {[tenantId]}) otherwise null)
    in 
        Table.ExpandData(data, {"tenantId"});

// Intelligent Security Graph

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Alerts = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/security/alerts", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScore = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/security/secureScores", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScoreControlProfiles = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/v1.0/security/secureScoreControlProfiles", tenants)
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

Rest.Contents = (url as text, token as text) =>
    let
        source = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "application/json;odata.metadata=minimal;odata.streaming=false;IEEE754Compatible=false",
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

Rest.Feed = (url as text, token as text) => Table.GenerateByPage((previous) =>
    let
        // If we have a previous page, get its Next link from metadata on the page.
        next = if (previous <> null) then try Value.Metadata(previous)[Next] otherwise null else null,
        // If we have a next link, use it, otherwise use the original URL that was passed in.
        urlToUse = if (next <> null) then next else url,
        // If we have a previous page, but don't have a next link, then we're done paging. Otherwise retrieve the next page.
        current = if (previous <> null and next = null) then null else Rest.Contents(urlToUse, token),
        // If we got data back from the current page, get the link for the next page
        link = if (current <> null) then Value.Metadata(current)[Next] else null
    in
        current meta [Next = link]);

// Office 365

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MailboxUsageDetail = (optional tenants as list) as table =>
    let 
        data = Request.GraphFeed("/beta/reports/getMailboxUsageDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ActiveUserDetails = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ServicesUserCounts = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getOffice365ServicesUserCounts(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.OneDriveUsageAccountDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getOneDriveUsageAccountDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SharePointSiteUsageDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getSharePointSiteUsageDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.TeamsUserActivityUserDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getTeamsUserActivityUserDetail(period='D30')?$format=application/json", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.YammerActivityUserDetail = (optional tenants as list) as table =>
    let
        data = Request.GraphFeed("/beta/reports/getYammerActivityUserDetail(period='D30')?$format=application/json", tenants)
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
        data = Request.GraphFeed("/v1.0/subscribedSkus", tenants)
    in
        data;
