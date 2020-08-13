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

SecMgmtInsights.ConditionalAccessPolicies = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/beta/identity/conditionalAccess/policies", queryString),
        data = Graph.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.Contracts = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/v1.0/contracts", queryString),
        data = Graph.Feed(requests, true, true, schemaOnly),       

        value = if(schemaOnly) then data else 
            let 
                removedColumn = try Table.RemoveColumns(data, "tenantId") otherwise data,
                renamedColumn = Table.RenameColumns(removedColumn, {"customerId", "tenantId"}, MissingField.Ignore)
            in
                renamedColumn
    in
        value;

SecMgmtInsights.CredentialUserRegistrationDetails = (schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests("/beta/reports/credentialUserRegistrationDetails", queryString),
        // TODO - If the tenant does not have an entiltment, then this request will fail with a HTTP 403
        data = Graph.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.Devices = (schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests("/v1.0/devices", queryString),
        data = Graph.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", queryString),
        // TODO - Due to one of the todo statements in the Graph.Feed function the schema will be null. THis is due to the data coming back from Microsoft Graph not being paged
        data = Graph.Feed(requests, false, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SignIns = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/beta/auditLogs/signIns", queryString),
        // TODO - There is an issue here that needs to be investigated. Currently you are getting @odata.context was not found
        data = Graph.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SubscribedSkus = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/v1.0/subscribedSkus", queryString),
        data = Graph.Feed(requests, true, true, schemaOnly)
    in
        data;

SecMgmtInsights.Users = (schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests("/v1.0/users", queryString),
        data = Graph.Feed(requests, true, true, schemaOnly)
    in
        data;

// Device Management

SecMgmtInsights.WindowsProtectionState = (schemaOnly as logical, optional queryString as text) =>
    let 
         firstRequests = Graph.BuildRequests("/v1.0/deviceManagement/managedDevices?$select=id"),
         source = Graph.Feed(firstRequests, true, false, false),
         renamedColumn = Table.RenameColumns(source, {"id", "deviceId"}),
         requests = Table.AddColumn(renamedColumn, "relativeUrl", each "/beta/deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState"),
         data = Graph.Feed(requests, false, true, schemaOnly, "deviceId = text")
     in  
         source; 

// Entities

EntityTable = #table({"Entity", "Action"}, {
    {"Alerts", SecMgmtInsights.Alerts},
    {"ConditionalAccessPolicies", SecMgmtInsights.ConditionalAccessPolicies},
    {"Contracts", SecMgmtInsights.Contracts},
    {"CredentialUserRegistrationDetails", SecMgmtInsights.CredentialUserRegistrationDetails},
    {"Devices", SecMgmtInsights.Devices},
    {"IdentitySecurityDefaultsEnforcementPolicy", SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy},
    {"MailboxUsageDetail", SecMgmtInsights.MailboxUsageDetail},
    {"Office365ActiveUserDetails", SecMgmtInsights.Office365ActiveUserDetails},
    {"Office365ServicesUserCounts", SecMgmtInsights.Office365ServicesUserCounts},
    {"OneDriveUsageAccountDetail", SecMgmtInsights.OneDriveUsageAccountDetail},
    {"SharePointSiteUsageDetail", SecMgmtInsights.SharePointSiteUsageDetail},
    {"SecureScore", SecMgmtInsights.SecureScore},
    {"SecureScoreControlProfile", SecMgmtInsights.SecureScoreControlProfiles},
    {"SingIns", SecMgmtInsights.SignIns},
    {"SubscribedSkus", SecMgmtInsights.SubscribedSkus},
    {"TeamsUserActivityUserDetail", SecMgmtInsights.TeamsUserActivityUserDetail},
    {"Users", SecMgmtInsights.Users},
    {"WindowsProtectionState", SecMgmtInsights.WindowsProtectionState}, 
    {"YammerActivityUserDetail", SecMgmtInsights.YammerActivityUserDetail}
});

GetActionForEntity = (entity as text) =>
    try 
        EntityTable{[Entity = entity]}[Action]
     otherwise
         let
             message = Text.Format("Could not find entity: '#{0}'", {entity})
         in
             Diagnostics.Trace(TraceLevel.Error, message, () => error message, true);

GetSchemaForEntity = (entity as text) as type => GetActionForEntity(entity)(true);

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

// Intelligent Security Graph

SecMgmtInsights.Alerts = (schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests("/v1.0/security/alerts", queryString),
        data = Graph.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SecureScore = (schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests("/v1.0/security/secureScores", queryString),
        data = Graph.Feed(requests, true, true, schemaOnly)
    in 
        data;

SecMgmtInsights.SecureScoreControlProfiles = (schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests("/v1.0/security/secureScoreControlProfiles", queryString),
        data = Graph.Feed(requests, true, true, schemaOnly)
    in
        data;

// Navigation

[DataSource.Kind="SecMgmtInsights", Publish="SecMgmtInsights.Publish"]
shared SecMgmtInsights.Contents = Value.ReplaceType(SecMgmtInsights.NavigationTable, SecMgmtInsightsType);

SecMgmtInsights.NavigationTable = (operatingModel as text) as table =>
    let
        // Use our schema table as the source of top level items in the navigation tree
        entities = Table.SelectColumns(EntityTable, {"Entity"}),
        rename = Table.RenameColumns(entities, {{"Entity", "Name"}}),
        // Add Data as a calculated column
        withData = Table.AddColumn(rename, "Data", each SecMgmtInsights.View(operatingModel, [Name]), type table),
        // Add ItemKind and ItemName as fixed text values
        withItemKind = Table.AddColumn(withData, "ItemKind", each "Table", type text),
        withItemName = Table.AddColumn(withItemKind, "ItemName", each "Table", type text),
        // Indicate that the node should not be expandable
        withIsLeaf = Table.AddColumn(withItemName, "IsLeaf", each true, type logical),
        // Generate the nav table
        navTable = Table.ToNavigationTable(withIsLeaf, {"Name"}, "Name", "Data", "ItemKind", "ItemName", "IsLeaf")
    in
        navTable;

SecMgmtInsights.View = (operatingModel as text, entity as text) as table =>
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
                    result = GetActionForEntity(entity)(false, finalUrl),
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
                        value =  GetActionForEntity(entity)(false, finalUrl),
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
                    GetSchemaForEntity(entity)
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
        View([OperatingModel = operatingModel, Entity = entity]);

// Network

Rest.GetContents = (url as text, token as text, optional isPaged as logical) =>
    let 
        contents = Web.Contents(url,
            [
                Headers = [
                    #"Accept" = "application/json;odata.metadata=minimal;odata.streaming=false;IEEE754Compatible=false",
                    #"Authorization" = "Bearer " & token,
                    #"User-Agent" = "secmgmt-insights-connector" 
                ],
                ManualCredentials = true,
                ManualStatusHandling = {400, 401, 403}
            ]),
        buffered = Binary.Buffer(contents),
        status = Value.Metadata(contents)[Response.Status],
        body = Json.Document(buffered),

        value = if(status = 400) then 
            let 
                // TODO - Determine if this should be body[error][message] = "This resource does not support custom page sizes. Please retry without a page size argument."
                value = if(Record.HasFields(body, "error") and body[error][code] = "Request_UnsupportedQuery") then
                    // TODO - This should only remove the top parameter and not the entire query string
                    Rest.GetContents(Text.BeforeDelimiter(url, "?"), token, isPaged)
                else 
                    error Error.Record(body[error][code], body[error][message], body)
            in 
                value
        else if(status = 401 or status = 403) then 
            error Error.Record(body[error][code], body[error][message], body)
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
        value meta [Next = link];

Rest.GetPage = (url as text, token as text) => Table.GenerateByPage((previous) => 
    let
        // if previous is null, then this is our first page of data
        next = if (previous = null) then url else Value.Metadata(previous)[Next]?,
        // if the next link was set to null by the previous call, we know we have no more data
        page = if (next <> null) then Rest.GetContents(next, token, true) else null
    in
        page);

// Office 365

// TODO - Due to the current implementation in the get schema functions each of the Office 365 report operations will return 
// Error: We cannot convert the value null to type Type.

SecMgmtInsights.MailboxUsageDetail = (schemaOnly as logical, optional queryString as text) =>
    let 
        requests = Graph.BuildRequests("/beta/reports/getMailboxUsageDetail(period='D30')?$format=application/json", queryString),
        data = Graph.Feed(requests, true, false, schemaOnly)
    in 
        data;

SecMgmtInsights.Office365ActiveUserDetails = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/beta/reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json", queryString),
        data = Graph.Feed(requests, true, false, schemaOnly)
    in 
        data;

SecMgmtInsights.Office365ServicesUserCounts = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/beta/reports/getOffice365ServicesUserCounts(period='D30')?$format=application/json", queryString),
        data = Graph.Feed(requests, true, false, schemaOnly)
    in 
        data;

SecMgmtInsights.OneDriveUsageAccountDetail = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/beta/reports/getOneDriveUsageAccountDetail(period='D30')?$format=application/json", queryString),
        data = Graph.Feed(requests, true, false, schemaOnly)
    in 
        data;

SecMgmtInsights.SharePointSiteUsageDetail = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/beta/reports/getSharePointSiteUsageDetail(period='D30')?$format=application/json", queryString),
        data = Graph.Feed(requests, true, false, schemaOnly)
    in 
        data;

SecMgmtInsights.TeamsUserActivityUserDetail = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/beta/reports/getTeamsUserActivityUserDetail(period='D30')?$format=application/json", queryString),
        data = Graph.Feed(requests, true, false, schemaOnly)
    in 
        data;

SecMgmtInsights.YammerActivityUserDetail = (schemaOnly as logical, optional queryString as text) =>
    let
        requests = Graph.BuildRequests("/beta/reports/getYammerActivityUserDetail(period='D30')?$format=application/json", queryString),
        data = Graph.Feed(requests, true, false, schemaOnly)
    in 
        data;

// Requests

Graph.BuildRequests = (relativeUrl as text, optional queryString as text) =>
    let 
        relativeAddress = if(queryString = null or queryString = "") then relativeUrl else relativeUrl & queryString,
        // tenantsList = if(tenants = null or List.IsEmpty(tenants)) then null else tenants,
        data = #table({"relativeUrl", "tenantId"}, {{relativeAddress, null}})
        // expandedList = Table.ExpandListColumn(data, "tenantId")
    in 
        data;

Graph.Feed = (requests as table, isPaged as logical, isSchemaRequired as logical, schemaOnly as logical, optional additionalSchema as text) => 
    let
        GetContext = (relativeUrl as text, optional tenantId as text) =>
            let
                // TODO - This does not need to be called for each type, only if the type has not been discovered yet.
                
                parts = Uri.Parts(graph_endpoint & relativeUrl),
                data = try Rest.GetContents(Text.Format("#{0}://#{1}:#{2}/#{3}?$top=1", {parts[Scheme], parts[Host], parts[Port], parts[Path]}), Token.GetAccessToken(tenantId)) otherwise null,
                // TODO - Need to follow up regarding the comment in the GetContents functions about handling HTTP 400 errors
                value = if(data = null or Table.HasColumns(data, "error")) then 
                    let
                        contents = Rest.GetContents(graph_endpoint & relativeUrl, Token.GetAccessToken(tenantId))
                    in 
                        contents
                else 
                    data
            in
                value,

        GetData = (input as record) =>
            let
                data = try if(isPaged) then 
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

        pagedSchema = if(isPaged and isSchemaRequired) then
            let
                data = Table.AddColumn(requests, "Column1", each GetContext([relativeUrl], [tenantId])),
                nonNullRows = Table.SelectRows(data, each [Column1] <> null),
                context = if(Table.IsEmpty(nonNullRows)) then null else nonNullRows{0}[Column1][#"@odata.context"]{0},
                value = if(context = null) then null else Schema.GetTable(context, additionalSchmeaValue)
            in 
                value
        else
            null,

        // TODO - Implement the required logic to leverage List.ParallelInvoke with concurrancy of five to ten. This should decrease the time it takes to get data from Microsoft Graph for larger environments
        // TODO - Currently this design will only work for paged resources (talking about returning the pagedSchema variable when the schemaOnly flag is true
        
        value = if(schemaOnly) then pagedSchema else 
            let
                data = Table.AddColumn(requests, "Column1", each GetData(_), pagedSchema),
        
                nonNullRows = Table.SelectRows(data, each [Column1] <> null),
                mergedLists = if(Table.IsEmpty(nonNullRows)) then null else List.Combine(nonNullRows[Column1]),

                resourceSchema = if(not isPaged and isSchemaRequired) then 
                    let 
                        context = mergedLists{0}[#"@odata.context"],
                        schema = Schema.GetTable(context, additionalSchmeaValue)
                    in 
                        schema 
                    else 
                        null,

                schema = if(isPaged and isSchemaRequired) then pagedSchema else resourceSchema,
       
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
                changedType
        in
            value;
