section SecMgmtInsights.PowerShell;

// Global Variables

api_uri = Text.FromBinary(Extension.Contents("api_uri"));
authorize_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
client_id = Text.FromBinary(Extension.Contents("client_id")); 
logout_uri = "https://login.microsoftonline.com/logout.srf";
redirect_uri = "https://oauth.powerbi.com/views/oauthredirect.html";
token_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";

// Data Source Kind description

SecMgmtInsights.PowerShell = [
    Authentication = [
        OAuth = [
            FinishLogin = FinishLogin,
            Logout = Logout,
            Refresh = Refresh,
            StartLogin = StartLogin
        ]
    ],
    Label = Extension.LoadString("DataSourceLabel")
];

// Data Source UI publishing description

SecMgmtInsights.PowerShell.Publish = [
    Beta = true,
    Category = "Other",
    ButtonText = { Extension.LoadString("ButtonTitle"), Extension.LoadString("ButtonHelp") },
    LearnMoreUrl = "https://github.com/microsoft/secmgmt-insights-connector",
    SourceImage = SecMgmtInsights.PowerShell.Icons,
    SourceTypeImage = SecMgmtInsights.PowerShell.Icons
];

SecMgmtInsights.PowerShell.Icons = [
    Icon16 = { Extension.Contents("SecMgmtInsights.PowerShell16.png"), Extension.Contents("SecMgmtInsights.PowerShell20.png"), Extension.Contents("SecMgmtInsights.PowerShell24.png"), Extension.Contents("SecMgmtInsights.PowerShell32.png") },
    Icon32 = { Extension.Contents("SecMgmtInsights.PowerShell32.png"), Extension.Contents("SecMgmtInsights.PowerShell40.png"), Extension.Contents("SecMgmtInsights.PowerShell48.png"), Extension.Contents("SecMgmtInsights.PowerShell64.png") }
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
            login = "login"
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

// Network

SecMgmtInsights.PowerShell.Request = (defaultDomainName as text) => 
    let 
        source = Web.Contents(api_uri,
            [
                Headers = [ #"Accept" = "application/json" ], 
                ManualCredentials = true,
                ManualStatusHandling = {401},
                RelativePath = "api/" & defaultDomainName
            ]), 
            document = Json.Document(source)
    in 
        document;

// Office 365

[DataSource.Kind="SecMgmtInsights.PowerShell"]
shared SecMgmtInsights.PowerShell.Office365AtpPolicies = (optional tenants as list) as table =>
    let
        configs = SecMgmtInsights.PowerShell.Office365Configs(tenants),
        data = Table.SelectColumns(configs, {"defaultDomainName", "AtpPolicyForO365"}),
        expandedRecord = Table.ExpandRecordColumn(data, "AtpPolicyForO365", {"AdminDisplayName", "TrackClicks", "AllowClickThrough", "EnableSafeLinksForClients", "EnableSafeLinksForWebAccessCompanion", "EnableSafeLinksForO365Clients", "BlockUrls", "EnableATPForSPOTeamsODB", "EnableSafeDocs", "AllowSafeDocsOpen", "Identity", "Id", "IsValid", "Name", "WhenChanged", "WhenCreated", "WhenChangedUTC", "WhenCreatedUTC", "ExchangeObjectId", "Guid", "ObjectState"}, {"AdminDisplayName", "TrackClicks", "AllowClickThrough", "EnableSafeLinksForClients", "EnableSafeLinksForWebAccessCompanion", "EnableSafeLinksForO365Clients", "BlockUrls", "EnableATPForSPOTeamsODB", "EnableSafeDocs", "AllowSafeDocsOpen", "Identity", "Id", "IsValid", "Name", "WhenChanged", "WhenCreated", "WhenChangedUTC", "WhenCreatedUTC", "ExchangeObjectId", "Guid", "ObjectState"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"TrackClicks", type logical}, {"AllowClickThrough", type logical}, {"EnableSafeLinksForClients", type logical}, {"EnableSafeLinksForWebAccessCompanion", type logical}, {"EnableSafeLinksForO365Clients", type logical}, {"EnableATPForSPOTeamsODB", type logical}, {"EnableSafeDocs", type logical}, {"AllowSafeDocsOpen", type logical}, {"IsValid", type logical}, {"WhenChanged", type datetimezone}, {"WhenCreated", type datetimezone}, {"WhenChangedUTC", type datetimezone}, {"WhenCreatedUTC", type datetimezone}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights.PowerShell", Publish="SecMgmtInsights.PowerShell.Publish"]
shared SecMgmtInsights.PowerShell.Office365Configs = (optional tenants as list) as table =>
    let 
        GetData = (defaultDomainName as text) => 
            let 
                data = SecMgmtInsights.PowerShell.Request("tenant/" & defaultDomainName & "/office365data")
            in 
                data,

        source = Table.FromList(tenants, Splitter.SplitByNothing(), {"defaultDomainName"}), 
        data = Table.AddColumn(source, "Custom", each try GetData([defaultDomainName]) otherwise null),
        expandedCustom = Table.ExpandRecordColumn(data, "Custom", {"MailDetailAtpReport", "MailTrafficAtpReport", "AtpPolicyForO365", "MalwareFilterPolicy", "AdminAuditLogConfig", "AntiPhishPolicy"}, {"MailDetailAtpReport", "MailTrafficAtpReport", "AtpPolicyForO365", "MalwareFilterPolicy", "AdminAuditLogConfig", "AntiPhishPolicy"})
    in 
        expandedCustom;

[DataSource.Kind="SecMgmtInsights.PowerShell"]
shared SecMgmtInsights.PowerShell.AdminAuditLogConfigs = (optional tenants as list) as table =>
    let
        configs = SecMgmtInsights.PowerShell.Office365Configs(tenants),
        data = Table.SelectColumns(configs, {"defaultDomainName", "AdminAuditLogConfig"}),
        expandedRecord = Table.ExpandRecordColumn(data, "AdminAuditLogConfig", {"AdminAuditLogEnabled", "LogLevel", "TestCmdletLoggingEnabled", "AdminAuditLogCmdlets", "AdminAuditLogParameters", "AdminAuditLogExcludedCmdlets", "AdminAuditLogAgeLimit", "LoadBalancerCount", "RefreshInterval", "PartitionInfo", "UnifiedAuditLogIngestionEnabled", "UnifiedAuditLogFirstOptInDate", "AdminDisplayName", "Name", "Identity", "WhenChanged", "WhenCreated", "WhenChangedUTC", "WhenCreatedUTC", "ExchangeObjectId", "Id", "Guid", "IsValid", "ObjectState"}, {"AdminAuditLogEnabled", "LogLevel", "TestCmdletLoggingEnabled", "AdminAuditLogCmdlets", "AdminAuditLogParameters", "AdminAuditLogExcludedCmdlets", "AdminAuditLogAgeLimit", "LoadBalancerCount", "RefreshInterval", "PartitionInfo", "UnifiedAuditLogIngestionEnabled", "UnifiedAuditLogFirstOptInDate", "AdminDisplayName", "Name", "Identity", "WhenChanged", "WhenCreated", "WhenChangedUTC", "WhenCreatedUTC", "ExchangeObjectId", "Id", "Guid", "IsValid", "ObjectState"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"AdminAuditLogEnabled", type logical}, {"LoadBalancerCount", Int64.Type}, {"RefreshInterval", Int64.Type}, {"UnifiedAuditLogIngestionEnabled", type logical}, {"UnifiedAuditLogFirstOptInDate", type datetimezone}, {"WhenChanged", type datetimezone}, {"WhenCreated", type datetimezone}, {"WhenChangedUTC", type datetimezone}, {"WhenCreatedUTC", type datetimezone}, {"IsValid", type logical}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights.PowerShell"]
shared SecMgmtInsights.PowerShell.AntiPhishPolicies = (optional tenants as list) as table =>
    let
        configs = SecMgmtInsights.PowerShell.Office365Configs(tenants),
        data = Table.SelectColumns(configs, {"defaultDomainName", "AntiPhishPolicy"}),
        expandedList = Table.ExpandListColumn(data, "AntiPhishPolicy"),
        expandedRecord = Table.ExpandRecordColumn(expandedList, "AntiPhishPolicy", {"Enabled", "ImpersonationProtectionState", "EnableTargetedUserProtection", "EnableMailboxIntelligenceProtection", "EnableTargetedDomainsProtection", "EnableOrganizationDomainsProtection", "EnableMailboxIntelligence", "EnableSimilarUsersSafetyTips", "EnableSimilarDomainsSafetyTips", "EnableUnusualCharactersSafetyTips", "TargetedUserProtectionAction", "MailboxIntelligenceProtectionAction", "TargetedDomainProtectionAction", "AuthenticationFailAction", "EnableAntiSpoofEnforcement", "EnableUnauthenticatedSender", "EnableSuspiciousSafetyTip", "PhishThresholdLevel", "TargetedUsersToProtect", "TargetedUserActionRecipients", "MailboxIntelligenceProtectionActionRecipients", "TargetedDomainsToProtect", "TargetedDomainActionRecipients", "ExcludedDomains", "ExcludedSenders", "IsDefault", "AdminDisplayName", "PolicyTag", "RecommendedPolicyType", "Identity", "Id", "IsValid", "Name", "WhenChanged", "WhenCreated", "WhenChangedUTC", "WhenCreatedUTC", "ExchangeObjectId", "Guid", "ObjectState"}, {"Enabled", "ImpersonationProtectionState", "EnableTargetedUserProtection", "EnableMailboxIntelligenceProtection", "EnableTargetedDomainsProtection", "EnableOrganizationDomainsProtection", "EnableMailboxIntelligence", "EnableSimilarUsersSafetyTips", "EnableSimilarDomainsSafetyTips", "EnableUnusualCharactersSafetyTips", "TargetedUserProtectionAction", "MailboxIntelligenceProtectionAction", "TargetedDomainProtectionAction", "AuthenticationFailAction", "EnableAntiSpoofEnforcement", "EnableUnauthenticatedSender", "EnableSuspiciousSafetyTip", "PhishThresholdLevel", "TargetedUsersToProtect", "TargetedUserActionRecipients", "MailboxIntelligenceProtectionActionRecipients", "TargetedDomainsToProtect", "TargetedDomainActionRecipients", "ExcludedDomains", "ExcludedSenders", "IsDefault", "AdminDisplayName", "PolicyTag", "RecommendedPolicyType", "Identity", "Id", "IsValid", "Name", "WhenChanged", "WhenCreated", "WhenChangedUTC", "WhenCreatedUTC", "ExchangeObjectId", "Guid", "ObjectState"}),
        changedType = Table.TransformColumnTypes(expandedRecord,{{"Enabled", type logical}, {"EnableTargetedUserProtection", type logical}, {"EnableMailboxIntelligenceProtection", type logical}, {"EnableTargetedDomainsProtection", type logical}, {"EnableOrganizationDomainsProtection", type logical}, {"EnableMailboxIntelligence", type logical}, {"EnableSimilarUsersSafetyTips", type logical}, {"EnableSimilarDomainsSafetyTips", type logical}, {"EnableUnusualCharactersSafetyTips", type logical}, {"EnableAntiSpoofEnforcement", type logical}, {"EnableUnauthenticatedSender", type logical}, {"EnableSuspiciousSafetyTip", type logical}, {"PhishThresholdLevel", Int64.Type}, {"IsDefault", type logical}, {"IsValid", type logical}, {"WhenChanged", type datetimezone}, {"WhenCreated", type datetimezone}, {"WhenChangedUTC", type datetimezone}, {"WhenCreatedUTC", type datetimezone}})
   in
        changedType;

[DataSource.Kind="SecMgmtInsights.PowerShell"]
shared SecMgmtInsights.PowerShell.MailDetailAtpReport = (optional tenants as list) as table =>
    let 
        configs = SecMgmtInsights.PowerShell.Office365Configs(tenants),
        data = Table.SelectColumns(configs, {"defaultDomainName", "MailDetailAtpReport"}),
        expandedList = Table.ExpandListColumn(data, "MailDetailAtpReport")
    in
        expandedList;

[DataSource.Kind="SecMgmtInsights.PowerShell"]
shared SecMgmtInsights.PowerShell.MailTrafficAtpReport = (optional tenants as list) as table =>
    let 
        configs = SecMgmtInsights.PowerShell.Office365Configs(tenants),
        data = Table.SelectColumns(configs, {"defaultDomainName", "MailTrafficAtpReport"}),
        expandedList = Table.ExpandListColumn(data, "MailTrafficAtpReport"),
        expandedColumn = Table.ExpandRecordColumn(expandedList, "MailTrafficAtpReport", {"Domain", "Date", "EventType", "Direction", "Action", "MessageCount", "SubType", "PolicySource", "VerdictSource", "DeliveryStatus", "SummarizeBy", "PivotBy", "StartDate", "EndDate", "AggregateBy", "Index"}, {"Domain", "Date", "EventType", "Direction", "Action", "MessageCount", "SubType", "PolicySource", "VerdictSource", "DeliveryStatus", "SummarizeBy", "PivotBy", "StartDate", "EndDate", "AggregateBy", "Index"}),
        changedType = Table.TransformColumnTypes(expandedColumn, {{"Date", type datetimezone}, {"MessageCount", Int64.Type}, {"StartDate", type datetimezone}, {"EndDate", type datetimezone}, {"Index", Int64.Type}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights.PowerShell"]
shared SecMgmtInsights.PowerShell.MalwareFilterPolicies = (optional tenants as list) as table =>
    let
        configs = SecMgmtInsights.PowerShell.Office365Configs(tenants),
        data = Table.SelectColumns(configs, {"defaultDomainName", "MalwareFilterPolicy"}),
        expandedList = Table.ExpandListColumn(data, "MalwareFilterPolicy"),
        expandedRecord = Table.ExpandRecordColumn(expandedList, "MalwareFilterPolicy", {"CustomAlertText", "AdminDisplayName", "CustomInternalSubject", "CustomInternalBody", "CustomExternalSubject", "CustomExternalBody", "CustomFromName", "CustomFromAddress", "InternalSenderAdminAddress", "ExternalSenderAdminAddress", "BypassInboundMessages", "BypassOutboundMessages", "Action", "IsDefault", "CustomNotifications", "EnableInternalSenderNotifications", "EnableExternalSenderNotifications", "EnableInternalSenderAdminNotifications", "EnableExternalSenderAdminNotifications", "EnableFileFilter", "FileTypes", "ZapEnabled", "RecommendedPolicyType", "Name", "Identity", "WhenChanged", "WhenCreated", "WhenChangedUTC", "WhenCreatedUTC", "Id", "Guid", "IsValid", "ObjectState"}, {"CustomAlertText", "AdminDisplayName", "CustomInternalSubject", "CustomInternalBody", "CustomExternalSubject", "CustomExternalBody", "CustomFromName", "CustomFromAddress", "InternalSenderAdminAddress", "ExternalSenderAdminAddress", "BypassInboundMessages", "BypassOutboundMessages", "Action", "IsDefault", "CustomNotifications", "EnableInternalSenderNotifications", "EnableExternalSenderNotifications", "EnableInternalSenderAdminNotifications", "EnableExternalSenderAdminNotifications", "EnableFileFilter", "FileTypes", "ZapEnabled", "RecommendedPolicyType", "Name", "Identity", "WhenChanged", "WhenCreated", "WhenChangedUTC", "WhenCreatedUTC", "Id", "Guid", "IsValid", "ObjectState"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"EnableInternalSenderNotifications", type logical}, {"EnableExternalSenderNotifications", type logical}, {"EnableInternalSenderAdminNotifications", type logical}, {"EnableExternalSenderAdminNotifications", type logical}, {"EnableFileFilter", type logical}, {"IsDefault", type logical}, {"BypassInboundMessages", type logical}, {"BypassOutboundMessages", type logical}, {"ZapEnabled", type logical}, {"WhenChanged", type datetimezone}, {"WhenCreated", type datetimezone}, {"WhenChangedUTC", type datetimezone}, {"WhenCreatedUTC", type datetimezone}, {"IsValid", type logical}})
    in
        changedType;
