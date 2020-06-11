section SecMgmtInsights;

// Global variables

authorize_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
client_id = Text.FromBinary(Extension.Contents("client_id")); 
logout_uri = "https://login.microsoftonline.com/logout.srf";
redirect_uri = "https://oauth.powerbi.com/views/oauthredirect.html";
token_uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";

shared SecMgmtInsights.Contents = (optional message as text) =>
    let
        _message = if (message <> null) then message else "(no message)",
        a = "Hello from SecMgmtInsights: " & _message
    in
        a;

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

// Azure Active Directory 

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ConditionalAccessPolicies = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("identity/conditionalAccess/policies"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "displayName", "createdDateTime", "modifiedDateTime", "state", "sessionControls", "conditions", "grantControls"}, {"id", "displayName", "createdDateTime", "modifiedDateTime", "state", "sessionControls", "conditions", "grantControls"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"createdDateTime", type datetimezone}, {"modifiedDateTime", type datetimezone}}),
        expandedConditions = Table.ExpandRecordColumn(changedType, "conditions", {"signInRiskLevels", "clientAppTypes", "platforms", "locations", "deviceStates", "devices", "applications", "users"}, {"conditions.signInRiskLevels", "conditions.clientAppTypes", "conditions.platforms", "conditions.locations", "conditions.deviceStates", "conditions.devices", "conditions.applications", "conditions.users"}),
        expandedGrantControls = Table.ExpandRecordColumn(expandedConditions, "grantControls", {"operator", "builtInControls", "customAuthenticationFactors", "termsOfUse"}, {"grantControls.operator", "grantControls.builtInControls", "grantControls.customAuthenticationFactors", "grantControls.termsOfUse"})
    in 
        expandedGrantControls;


[DataSource.Kind="SecMgmtInsights", Publish="SecMgmtInsights.Publish"]
shared SecMgmtInsights.Contracts = () =>
    let
        accessToken = Helper.GetAccessToken(),
        contracts = MicrosoftGraph.GetPagedContent("contracts", accessToken),
        convertedTable = Table.FromList(contracts, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
        expandedColumn = Table.ExpandListColumn(convertedTable, "Column1"),
        expandedRecord = Table.ExpandRecordColumn(expandedColumn, "Column1", {"id", "deletedDateTime", "contractType", "customerId", "defaultDomainName", "displayName"}, {"id", "deletedDateTime", "contractType", "customerId", "defaultDomainName", "displayName"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"deletedDateTime", type datetime}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.CredentialUserRegistrationDetails = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("reports/credentialUserRegistrationDetails"),
        expandedCustom = Table.ExpandRecordColumn(data, "Custom", {"id", "userPrincipalName", "userDisplayName", "isRegistered", "isEnabled", "isCapable", "isMfaRegistered", "authMethods"}, {"id", "userPrincipalName", "userDisplayName", "isRegistered", "isEnabled", "isCapable", "isMfaRegistered", "authMethods"}),
        expandedAuthMethods = Table.ExpandListColumn(expandedCustom, "authMethods"),
        changedType = Table.TransformColumnTypes(expandedAuthMethods, {{"isRegistered", type logical}, {"isEnabled", type logical}, {"isCapable", type logical}, {"isMfaRegistered", type logical}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Devices = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("devices"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "deletedDateTime", "accountEnabled", "approximateLastSignInDateTime", "complianceExpirationDateTime", "deviceId", "deviceMetadata", "deviceVersion", "displayName", "isCompliant", "isManaged", "Manufacturer", "mdmAppId", "Model", "onPremisesLastSyncDateTime", "onPremisesSyncEnabled", "operatingSystem", "operatingSystemVersion", "physicalIds", "profileType", "systemLabels", "trustType", "alternativeSecurityIds"}, {"id", "deletedDateTime", "accountEnabled", "approximateLastSignInDateTime", "complianceExpirationDateTime", "deviceId", "deviceMetadata", "deviceVersion", "displayName", "isCompliant", "isManaged", "Manufacturer", "mdmAppId", "Model", "onPremisesLastSyncDateTime", "onPremisesSyncEnabled", "operatingSystem", "operatingSystemVersion", "physicalIds", "profileType", "systemLabels", "trustType", "alternativeSecurityIds"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"deletedDateTime", type datetimezone}, {"accountEnabled", type logical}, {"approximateLastSignInDateTime", type datetimezone}, {"complianceExpirationDateTime", type datetimezone}, {"deviceVersion", Int64.Type}, {"isCompliant", type logical}, {"isManaged", type logical}, {"onPremisesLastSyncDateTime", type datetimezone}, {"onPremisesSyncEnabled", type logical}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy = () =>
    let
       data = Helper.GetDataForAllCustomers("policies/identitySecurityDefaultsEnforcementPolicy"),
       expandedCustom = Table.ExpandRecordColumn(data, "Custom", {"id", "displayName", "description", "isEnabled"}, {"id", "displayName", "description", "isEnabled"}),
       changedType = Table.TransformColumnTypes(expandedCustom, {{"isEnabled", type logical}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.RiskyUsers = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("riskyUsers"),
        expandedCustom = Table.ExpandRecordColumn(data, "Custom", {"id", "riskLastUpdatedDateTime", "isGuest", "isProcessing", "isDeleted", "riskDetail", "riskLevel", "riskState", "userDisplayName", "userPrincipalName"}, {"id", "riskLastUpdatedDateTime", "isGuest", "isProcessing", "isDeleted", "riskDetail", "riskLevel", "riskState", "userDisplayName", "userPrincipalName"}),
        changedType = Table.TransformColumnTypes(expandedCustom, {{"riskLastUpdatedDateTime", type datetimezone}, {"isGuest", type logical}, {"isProcessing", type logical}, {"isDeleted", type logical}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SignIns = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("auditLogs/signIns"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "createdDateTime", "userDisplayName", "userPrincipalName", "userId", "appId", "appDisplayName", "ipAddress", "clientAppUsed", "userAgent", "correlationId", "conditionalAccessStatus", "originalRequestId", "isInteractive", "tokenIssuerName", "tokenIssuerType", "processingTimeInMilliseconds", "riskDetail", "riskLevelAggregated", "riskLevelDuringSignIn", "riskState", "riskEventTypes", "riskEventTypes_v2", "resourceDisplayName", "resourceId", "authenticationMethodsUsed", "authenticationRequirement", "alternateSignInName", "servicePrincipalName", "servicePrincipalId", "mfaDetail", "status", "deviceDetail", "location", "appliedConditionalAccessPolicies", "authenticationProcessingDetails", "networkLocationDetails", "authenticationDetails", "authenticationRequirementPolicies"}, {"id", "createdDateTime", "userDisplayName", "userPrincipalName", "userId", "appId", "appDisplayName", "ipAddress", "clientAppUsed", "userAgent", "correlationId", "conditionalAccessStatus", "originalRequestId", "isInteractive", "tokenIssuerName", "tokenIssuerType", "processingTimeInMilliseconds", "riskDetail", "riskLevelAggregated", "riskLevelDuringSignIn", "riskState", "riskEventTypes", "riskEventTypes_v2", "resourceDisplayName", "resourceId", "authenticationMethodsUsed", "authenticationRequirement", "alternateSignInName", "servicePrincipalName", "servicePrincipalId", "mfaDetail", "status", "deviceDetail", "location", "appliedConditionalAccessPolicies", "authenticationProcessingDetails", "networkLocationDetails", "authenticationDetails", "authenticationRequirementPolicies"}),
        expandedAuthMethodList = Table.ExpandListColumn(expandedRecord, "authenticationDetails"),
        expandedAuthMethodRecord = Table.ExpandRecordColumn(expandedAuthMethodList, "authenticationDetails", {"authenticationStepDateTime", "authenticationMethod", "authenticationMethodDetail", "succeeded", "authenticationStepResultDetail", "authenticationStepRequirement"}, {"authenticationStepDateTime", "authenticationMethod", "authenticationMethodDetail", "succeeded", "authenticationStepResultDetail", "authenticationStepRequirement"}),
        changedType = Table.TransformColumnTypes(expandedAuthMethodRecord, {{"createdDateTime", type datetime}, {"isInteractive", type logical}, {"processingTimeInMilliseconds", Int64.Type}, {"authenticationStepDateTime", type datetimezone}, {"succeeded", type logical}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Users = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("users"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "deletedDateTime", "accountEnabled", "ageGroup", "businessPhones", "city", "createdDateTime", "creationType", "companyName", "consentProvidedForMinor", "country", "department", "displayName", "employeeId", "faxNumber", "givenName", "imAddresses", "infoCatalogs", "isResourceAccount", "jobTitle", "legalAgeGroupClassification", "mail", "mailNickname", "mobilePhone", "onPremisesDistinguishedName", "officeLocation", "onPremisesDomainName", "onPremisesImmutableId", "onPremisesLastSyncDateTime", "onPremisesSecurityIdentifier", "onPremisesSamAccountName", "onPremisesSyncEnabled", "onPremisesUserPrincipalName", "otherMails", "passwordPolicies", "passwordProfile", "postalCode", "preferredDataLocation", "preferredLanguage", "proxyAddresses", "refreshTokensValidFromDateTime", "showInAddressList", "signInSessionsValidFromDateTime", "state", "streetAddress", "surname", "usageLocation", "userPrincipalName", "externalUserState", "externalUserStateChangeDateTime", "userType", "assignedLicenses", "assignedPlans", "deviceKeys", "identities", "onPremisesExtensionAttributes", "onPremisesProvisioningErrors", "provisionedPlans"}, {"id", "deletedDateTime", "accountEnabled", "ageGroup", "businessPhones", "city", "createdDateTime", "creationType", "companyName", "consentProvidedForMinor", "country", "department", "displayName", "employeeId", "faxNumber", "givenName", "imAddresses", "infoCatalogs", "isResourceAccount", "jobTitle", "legalAgeGroupClassification", "mail", "mailNickname", "mobilePhone", "onPremisesDistinguishedName", "officeLocation", "onPremisesDomainName", "onPremisesImmutableId", "onPremisesLastSyncDateTime", "onPremisesSecurityIdentifier", "onPremisesSamAccountName", "onPremisesSyncEnabled", "onPremisesUserPrincipalName", "otherMails", "passwordPolicies", "passwordProfile", "postalCode", "preferredDataLocation", "preferredLanguage", "proxyAddresses", "refreshTokensValidFromDateTime", "showInAddressList", "signInSessionsValidFromDateTime", "state", "streetAddress", "surname", "usageLocation", "userPrincipalName", "externalUserState", "externalUserStateChangeDateTime", "userType", "assignedLicenses", "assignedPlans", "deviceKeys", "identities", "onPremisesExtensionAttributes", "onPremisesProvisioningErrors", "provisionedPlans"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"accountEnabled", type logical}, {"createdDateTime", type datetimezone}, {"onPremisesLastSyncDateTime", type datetimezone}, {"onPremisesSyncEnabled", type logical}, {"postalCode", Int64.Type}, {"refreshTokensValidFromDateTime", type datetimezone}, {"signInSessionsValidFromDateTime", type datetimezone}})
    in
        changedType;

// Device Management

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedApps= () =>
    let 
        GetData = (deviceId as text, tenantId as text) =>
            let
                accessToken = Helper.GetAccessToken(tenantId),
                data = MicrosoftGraph.GetPagedContent("deviceManagement/managedDevices/" & deviceId & "/detectedApps", accessToken)
            in 
                data,

        source = SecMgmtInsights.ManagedDevices(),
        managedDevices = Table.SelectColumns(source, {"customerId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [customerId]) otherwise null), 
        expandedCustom = Table.ExpandListColumn(data, "Custom"),
        expandedList = Table.ExpandListColumn(expandedCustom, "Custom"),
        expandedRecord = Table.ExpandRecordColumn(expandedList, "Custom", {"id", "displayName", "version", "sizeInByte", "deviceCount"}, {"id", "displayName", "version", "sizeInByte", "deviceCount"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"sizeInByte", Int64.Type}, {"deviceCount", Int64.Type}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicySettingStates = () => 
    let
        GetData = (deviceId as text, policyId as text, tenantId as text) => 
            let
                accessToken = Helper.GetAccessToken(tenantId),
                data = MicrosoftGraph.GetPagedContent("deviceManagement/managedDevices/" & deviceId & "/deviceCompliancePolicyStates/" & policyId & "/settingStates", accessToken)
            in 
                data,

        source = SecMgmtInsights.DeviceCompliancePolicyStates(),
        policyStates = Table.SelectColumns(source, {"customerId", "deviceId", "id"}),
        renamedColumn =  Table.RenameColumns(policyStates, {{"id", "policyId"}}),
        policySettingStates = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [policyId], [customerId]) otherwise null),
        settingsTable = Table.ExpandListColumn(policySettingStates, "Custom"),
        expandedCustom = Table.ExpandListColumn(settingsTable, "Custom"),
        expandedRecord = Table.ExpandRecordColumn(expandedCustom, "Custom", {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}, {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}),
        expandedSources = Table.ExpandListColumn(expandedRecord, "sources"),
        expandedSourcesRecord = Table.ExpandRecordColumn(expandedSources, "sources", {"id", "displayName"}, {"sources.id", "sources.displayName"})
    in 
        expandedSourcesRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicies = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/deviceCompliancePolicies"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"roleScopeTagIds", "id", "createdDateTime", "description", "lastModifiedDateTime", "displayName", "version", "passwordRequired", "passwordMinimumLength", "passwordRequiredType", "passwordMinutesOfInactivityBeforeLock", "passwordExpirationDays", "passwordPreviousPasswordBlockCount", "passwordSignInFailureCountBeforeFactoryReset", "securityPreventInstallAppsFromUnknownSources", "securityDisableUsbDebugging", "securityRequireVerifyApps", "deviceThreatProtectionEnabled", "deviceThreatProtectionRequiredSecurityLevel", "advancedThreatProtectionRequiredSecurityLevel", "securityBlockJailbrokenDevices", "securityBlockDeviceAdministratorManagedDevices", "osMinimumVersion", "osMaximumVersion", "minAndroidSecurityPatchLevel", "storageRequireEncryption", "securityRequireSafetyNetAttestationBasicIntegrity", "securityRequireSafetyNetAttestationCertifiedDevice", "securityRequireGooglePlayServices", "securityRequireUpToDateSecurityProviders", "securityRequireCompanyPortalAppIntegrity", "conditionStatementId", "restrictedApps", "passwordBlockSimple", "passwordRequiredToUnlockFromIdle", "passwordMinimumCharacterSetCount", "requireHealthyDeviceReport", "mobileOsMinimumVersion", "mobileOsMaximumVersion", "earlyLaunchAntiMalwareDriverEnabled", "bitLockerEnabled", "secureBootEnabled", "codeIntegrityEnabled", "activeFirewallRequired", "defenderEnabled", "defenderVersion", "signatureOutOfDate", "rtpEnabled", "antivirusRequired", "antiSpywareRequired", "configurationManagerComplianceRequired", "tpmRequired", "validOperatingSystemBuildRanges"}, {"roleScopeTagIds", "id", "createdDateTime", "description", "lastModifiedDateTime", "displayName", "version", "passwordRequired", "passwordMinimumLength", "passwordRequiredType", "passwordMinutesOfInactivityBeforeLock", "passwordExpirationDays", "passwordPreviousPasswordBlockCount", "passwordSignInFailureCountBeforeFactoryReset", "securityPreventInstallAppsFromUnknownSources", "securityDisableUsbDebugging", "securityRequireVerifyApps", "deviceThreatProtectionEnabled", "deviceThreatProtectionRequiredSecurityLevel", "advancedThreatProtectionRequiredSecurityLevel", "securityBlockJailbrokenDevices", "securityBlockDeviceAdministratorManagedDevices", "osMinimumVersion", "osMaximumVersion", "minAndroidSecurityPatchLevel", "storageRequireEncryption", "securityRequireSafetyNetAttestationBasicIntegrity", "securityRequireSafetyNetAttestationCertifiedDevice", "securityRequireGooglePlayServices", "securityRequireUpToDateSecurityProviders", "securityRequireCompanyPortalAppIntegrity", "conditionStatementId", "restrictedApps", "passwordBlockSimple", "passwordRequiredToUnlockFromIdle", "passwordMinimumCharacterSetCount", "requireHealthyDeviceReport", "mobileOsMinimumVersion", "mobileOsMaximumVersion", "earlyLaunchAntiMalwareDriverEnabled", "bitLockerEnabled", "secureBootEnabled", "codeIntegrityEnabled", "activeFirewallRequired", "defenderEnabled", "defenderVersion", "signatureOutOfDate", "rtpEnabled", "antivirusRequired", "antiSpywareRequired", "configurationManagerComplianceRequired", "tpmRequired", "validOperatingSystemBuildRanges"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"createdDateTime", type datetimezone}, {"lastModifiedDateTime", type datetimezone}, {"version", Int64.Type}, {"passwordRequired", type logical}, {"securityDisableUsbDebugging", type logical}, {"securityPreventInstallAppsFromUnknownSources", type logical}, {"securityRequireVerifyApps", type logical}, {"deviceThreatProtectionEnabled", type logical}, {"securityBlockJailbrokenDevices", type logical}, {"securityBlockDeviceAdministratorManagedDevices", type logical}, {"storageRequireEncryption", type logical}, {"securityRequireSafetyNetAttestationBasicIntegrity", type logical}, {"securityRequireSafetyNetAttestationCertifiedDevice", type logical}, {"securityRequireGooglePlayServices", type logical}, {"securityRequireUpToDateSecurityProviders", type logical}, {"securityRequireCompanyPortalAppIntegrity", type logical}, {"passwordBlockSimple", type logical}, {"passwordRequiredToUnlockFromIdle", type logical}, {"requireHealthyDeviceReport", type logical}, {"earlyLaunchAntiMalwareDriverEnabled", type logical}, {"bitLockerEnabled", type logical}, {"secureBootEnabled", type logical}, {"codeIntegrityEnabled", type logical}, {"activeFirewallRequired", type logical}, {"defenderEnabled", type logical}, {"signatureOutOfDate", type logical}, {"rtpEnabled", type logical}, {"antivirusRequired", type logical}, {"antiSpywareRequired", type logical}, {"configurationManagerComplianceRequired", type logical}, {"tpmRequired", type logical}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicyStates = () =>
    let
        GetData = (deviceId as text, tenantId as text) =>
            let
                accessToken = Helper.GetAccessToken(tenantId),
                data = MicrosoftGraph.GetPagedContent("deviceManagement/managedDevices/" & deviceId & "/deviceCompliancePolicyStates", accessToken)
            in 
                data,

        source = SecMgmtInsights.ManagedDevices(),
        managedDevices = Table.SelectColumns(source, {"customerId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        policyStates = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [customerId]) otherwise null),
        statesTable = Table.ExpandListColumn(policyStates, "Custom"),
        expandedCustom = Table.ExpandListColumn(statesTable, "Custom"),
        expandedRecord = Table.ExpandRecordColumn(expandedCustom, "Custom", {"id", "displayName", "version", "platformType", "state", "settingCount", "userId", "userPrincipalName", "settingStates"}, {"id", "displayName", "version", "platformType", "state", "settingCount", "userId", "userPrincipalName", "settingStates"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicies = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/deviceConfigurations"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "lastModifiedDateTime", "roleScopeTagIds", "supportsScopeTags", "deviceManagementApplicabilityRuleOsEdition", "deviceManagementApplicabilityRuleOsVersion", "deviceManagementApplicabilityRuleDeviceMode", "createdDateTime", "description", "displayName", "version", "dmaGuardDeviceEnumerationPolicy", "userRightsAccessCredentialManagerAsTrustedCaller", "userRightsAllowAccessFromNetwork", "userRightsBlockAccessFromNetwork", "userRightsActAsPartOfTheOperatingSystem", "userRightsLocalLogOn", "userRightsDenyLocalLogOn", "userRightsBackupData", "userRightsChangeSystemTime", "userRightsCreateGlobalObjects", "userRightsCreatePageFile", "userRightsCreatePermanentSharedObjects", "userRightsCreateSymbolicLinks", "userRightsCreateToken", "userRightsDebugPrograms", "userRightsRemoteDesktopServicesLogOn", "userRightsDelegation", "userRightsGenerateSecurityAudits", "userRightsImpersonateClient", "userRightsIncreaseSchedulingPriority", "userRightsLoadUnloadDrivers", "userRightsLockMemory", "userRightsManageAuditingAndSecurityLogs", "userRightsManageVolumes", "userRightsModifyFirmwareEnvironment", "userRightsModifyObjectLabels", "userRightsProfileSingleProcess", "userRightsRemoteShutdown", "userRightsRestoreData", "userRightsTakeOwnership", "xboxServicesEnableXboxGameSaveTask", "xboxServicesAccessoryManagementServiceStartupMode", "xboxServicesLiveAuthManagerServiceStartupMode", "xboxServicesLiveGameSaveServiceStartupMode", "xboxServicesLiveNetworkingServiceStartupMode", "localSecurityOptionsBlockMicrosoftAccounts", "localSecurityOptionsBlockRemoteLogonWithBlankPassword", "localSecurityOptionsDisableAdministratorAccount", "localSecurityOptionsAdministratorAccountName", "localSecurityOptionsDisableGuestAccount", "localSecurityOptionsGuestAccountName", "localSecurityOptionsAllowUndockWithoutHavingToLogon", "localSecurityOptionsBlockUsersInstallingPrinterDrivers", "localSecurityOptionsBlockRemoteOpticalDriveAccess", "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser", "localSecurityOptionsMachineInactivityLimit", "localSecurityOptionsMachineInactivityLimitInMinutes", "localSecurityOptionsDoNotRequireCtrlAltDel", "localSecurityOptionsHideLastSignedInUser", "localSecurityOptionsHideUsernameAtSignIn", "localSecurityOptionsLogOnMessageTitle", "localSecurityOptionsLogOnMessageText", "localSecurityOptionsAllowPKU2UAuthenticationRequests", "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool", "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager", "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients", "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers", "lanManagerAuthenticationLevel", "lanManagerWorkstationDisableInsecureGuestLogons", "localSecurityOptionsClearVirtualMemoryPageFile", "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn", "localSecurityOptionsAllowUIAccessApplicationElevation", "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations", "localSecurityOptionsOnlyElevateSignedExecutables", "localSecurityOptionsAdministratorElevationPromptBehavior", "localSecurityOptionsStandardUserElevationPromptBehavior", "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation", "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation", "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations", "localSecurityOptionsUseAdminApprovalMode", "localSecurityOptionsUseAdminApprovalModeForAdministrators", "localSecurityOptionsInformationShownOnLockScreen", "localSecurityOptionsInformationDisplayedOnLockScreen", "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees", "localSecurityOptionsClientDigitallySignCommunicationsAlways", "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers", "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways", "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees", "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares", "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts", "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares", "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange", "localSecurityOptionsSmartCardRemovalBehavior", "defenderSecurityCenterDisableAppBrowserUI", "defenderSecurityCenterDisableFamilyUI", "defenderSecurityCenterDisableHealthUI", "defenderSecurityCenterDisableNetworkUI", "defenderSecurityCenterDisableVirusUI", "defenderSecurityCenterDisableAccountUI", "defenderSecurityCenterDisableClearTpmUI", "defenderSecurityCenterDisableHardwareUI", "defenderSecurityCenterDisableNotificationAreaUI", "defenderSecurityCenterDisableRansomwareUI", "defenderSecurityCenterDisableSecureBootUI", "defenderSecurityCenterDisableTroubleshootingUI", "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI", "defenderSecurityCenterOrganizationDisplayName", "defenderSecurityCenterHelpEmail", "defenderSecurityCenterHelpPhone", "defenderSecurityCenterHelpURL", "defenderSecurityCenterNotificationsFromApp", "defenderSecurityCenterITContactDisplay", "windowsDefenderTamperProtection", "firewallBlockStatefulFTP", "firewallIdleTimeoutForSecurityAssociationInSeconds", "firewallPreSharedKeyEncodingMethod", "firewallIPSecExemptionsAllowNeighborDiscovery", "firewallIPSecExemptionsAllowICMP", "firewallIPSecExemptionsAllowRouterDiscovery", "firewallIPSecExemptionsAllowDHCP", "firewallCertificateRevocationListCheckMethod", "firewallMergeKeyingModuleSettings", "firewallPacketQueueingMethod", "firewallProfileDomain", "firewallProfilePublic", "firewallProfilePrivate", "defenderAdobeReaderLaunchChildProcess", "defenderAttackSurfaceReductionExcludedPaths", "defenderOfficeAppsOtherProcessInjectionType", "defenderOfficeAppsOtherProcessInjection", "defenderOfficeCommunicationAppsLaunchChildProcess", "defenderOfficeAppsExecutableContentCreationOrLaunchType", "defenderOfficeAppsExecutableContentCreationOrLaunch", "defenderOfficeAppsLaunchChildProcessType", "defenderOfficeAppsLaunchChildProcess", "defenderOfficeMacroCodeAllowWin32ImportsType", "defenderOfficeMacroCodeAllowWin32Imports", "defenderScriptObfuscatedMacroCodeType", "defenderScriptObfuscatedMacroCode", "defenderScriptDownloadedPayloadExecutionType", "defenderScriptDownloadedPayloadExecution", "defenderPreventCredentialStealingType", "defenderProcessCreationType", "defenderProcessCreation", "defenderUntrustedUSBProcessType", "defenderUntrustedUSBProcess", "defenderUntrustedExecutableType", "defenderUntrustedExecutable", "defenderEmailContentExecutionType", "defenderEmailContentExecution", "defenderAdvancedRansomewareProtectionType", "defenderGuardMyFoldersType", "defenderGuardedFoldersAllowedAppPaths", "defenderAdditionalGuardedFolders", "defenderNetworkProtectionType", "defenderExploitProtectionXml", "defenderExploitProtectionXmlFileName", "defenderSecurityCenterBlockExploitProtectionOverride", "appLockerApplicationControl", "deviceGuardLocalSystemAuthorityCredentialGuardSettings", "deviceGuardEnableVirtualizationBasedSecurity", "deviceGuardEnableSecureBootWithDMA", "deviceGuardSecureBootWithDMA", "deviceGuardLaunchSystemGuard", "smartScreenEnableInShell", "smartScreenBlockOverrideForFiles", "applicationGuardEnabled", "applicationGuardEnabledOptions", "applicationGuardBlockFileTransfer", "applicationGuardBlockNonEnterpriseContent", "applicationGuardAllowPersistence", "applicationGuardForceAuditing", "applicationGuardBlockClipboardSharing", "applicationGuardAllowPrintToPDF", "applicationGuardAllowPrintToXPS", "applicationGuardAllowPrintToLocalPrinters", "applicationGuardAllowPrintToNetworkPrinters", "applicationGuardAllowVirtualGPU", "applicationGuardAllowFileSaveOnHost", "bitLockerAllowStandardUserEncryption", "bitLockerDisableWarningForOtherDiskEncryption", "bitLockerEnableStorageCardEncryptionOnMobile", "bitLockerEncryptDevice", "bitLockerSystemDrivePolicy", "bitLockerFixedDrivePolicy", "bitLockerRemovableDrivePolicy", "bitLockerRecoveryPasswordRotation", "defenderDisableScanArchiveFiles", "defenderAllowScanArchiveFiles", "defenderDisableBehaviorMonitoring", "defenderAllowBehaviorMonitoring", "defenderDisableCloudProtection", "defenderAllowCloudProtection", "defenderEnableScanIncomingMail", "defenderEnableScanMappedNetworkDrivesDuringFullScan", "defenderDisableScanRemovableDrivesDuringFullScan", "defenderAllowScanRemovableDrivesDuringFullScan", "defenderDisableScanDownloads", "defenderAllowScanDownloads", "defenderDisableIntrusionPreventionSystem", "defenderAllowIntrusionPreventionSystem", "defenderDisableOnAccessProtection", "defenderAllowOnAccessProtection", "defenderDisableRealTimeMonitoring", "defenderAllowRealTimeMonitoring", "defenderDisableScanNetworkFiles", "defenderAllowScanNetworkFiles", "defenderDisableScanScriptsLoadedInInternetExplorer", "defenderAllowScanScriptsLoadedInInternetExplorer", "defenderBlockEndUserAccess", "defenderAllowEndUserAccess", "defenderScanMaxCpuPercentage", "defenderCheckForSignaturesBeforeRunningScan", "defenderCloudBlockLevel", "defenderCloudExtendedTimeoutInSeconds", "defenderDaysBeforeDeletingQuarantinedMalware", "defenderDisableCatchupFullScan", "defenderDisableCatchupQuickScan", "defenderEnableLowCpuPriority", "defenderFileExtensionsToExclude", "defenderFilesAndFoldersToExclude", "defenderProcessesToExclude", "defenderPotentiallyUnwantedAppAction", "defenderScanDirection", "defenderScanType", "defenderScheduledQuickScanTime", "defenderScheduledScanDay", "defenderScheduledScanTime", "defenderSignatureUpdateIntervalInHours", "defenderSubmitSamplesConsentType", "defenderDetectedMalwareActions", "firewallRules", "taskManagerBlockEndTask", "energySaverOnBatteryThresholdPercentage", "energySaverPluggedInThresholdPercentage", "powerLidCloseActionOnBattery", "powerLidCloseActionPluggedIn", "powerButtonActionOnBattery", "powerButtonActionPluggedIn", "powerSleepButtonActionOnBattery", "powerSleepButtonActionPluggedIn", "powerHybridSleepOnBattery", "powerHybridSleepPluggedIn", "windows10AppsForceUpdateSchedule", "enableAutomaticRedeployment", "microsoftAccountSignInAssistantSettings", "authenticationAllowSecondaryDevice", "authenticationWebSignIn", "authenticationPreferredAzureADTenantDomainName", "cryptographyAllowFipsAlgorithmPolicy", "displayAppListWithGdiDPIScalingTurnedOn", "displayAppListWithGdiDPIScalingTurnedOff", "enterpriseCloudPrintDiscoveryEndPoint", "enterpriseCloudPrintOAuthAuthority", "enterpriseCloudPrintOAuthClientIdentifier", "enterpriseCloudPrintResourceIdentifier", "enterpriseCloudPrintDiscoveryMaxLimit", "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier", "experienceDoNotSyncBrowserSettings", "messagingBlockSync", "messagingBlockMMS", "messagingBlockRichCommunicationServices", "printerNames", "printerDefaultName", "printerBlockAddition", "searchBlockDiacritics", "searchDisableAutoLanguageDetection", "searchDisableIndexingEncryptedItems", "searchEnableRemoteQueries", "searchDisableUseLocation", "searchDisableLocation", "searchDisableIndexerBackoff", "searchDisableIndexingRemovableDrive", "searchEnableAutomaticIndexSizeManangement", "searchBlockWebResults", "findMyFiles", "securityBlockAzureADJoinedDevicesAutoEncryption", "diagnosticsDataSubmissionMode", "oneDriveDisableFileSync", "systemTelemetryProxyServer", "edgeTelemetryForMicrosoft365Analytics", "inkWorkspaceAccess", "inkWorkspaceAccessState", "inkWorkspaceBlockSuggestedApps", "smartScreenEnableAppInstallControl", "smartScreenAppInstallControl", "personalizationDesktopImageUrl", "personalizationLockScreenImageUrl", "bluetoothAllowedServices", "bluetoothBlockAdvertising", "bluetoothBlockPromptedProximalConnections", "bluetoothBlockDiscoverableMode", "bluetoothBlockPrePairing", "edgeBlockAutofill", "edgeBlocked", "edgeCookiePolicy", "edgeBlockDeveloperTools", "edgeBlockSendingDoNotTrackHeader", "edgeBlockExtensions", "edgeBlockInPrivateBrowsing", "edgeBlockJavaScript", "edgeBlockPasswordManager", "edgeBlockAddressBarDropdown", "edgeBlockCompatibilityList", "edgeClearBrowsingDataOnExit", "edgeAllowStartPagesModification", "edgeDisableFirstRunPage", "edgeBlockLiveTileDataCollection", "edgeSyncFavoritesWithInternetExplorer", "edgeFavoritesListLocation", "edgeBlockEditFavorites", "edgeNewTabPageURL", "edgeHomeButtonConfiguration", "edgeHomeButtonConfigurationEnabled", "edgeOpensWith", "edgeBlockSideloadingExtensions", "edgeRequiredExtensionPackageFamilyNames", "edgeBlockPrinting", "edgeFavoritesBarVisibility", "edgeBlockSavingHistory", "edgeBlockFullScreenMode", "edgeBlockWebContentOnNewTabPage", "edgeBlockTabPreloading", "edgeBlockPrelaunch", "edgeShowMessageWhenOpeningInternetExplorerSites", "edgePreventCertificateErrorOverride", "edgeKioskModeRestriction", "edgeKioskResetAfterIdleTimeInMinutes", "cellularBlockDataWhenRoaming", "cellularBlockVpn", "cellularBlockVpnWhenRoaming", "cellularData", "defenderRequireRealTimeMonitoring", "defenderRequireBehaviorMonitoring", "defenderRequireNetworkInspectionSystem", "defenderScanDownloads", "defenderScheduleScanEnableLowCpuPriority", "defenderScanScriptsLoadedInInternetExplorer", "defenderMonitorFileActivity", "defenderScanMaxCpu", "defenderScanArchiveFiles", "defenderScanIncomingMail", "defenderScanRemovableDrivesDuringFullScan", "defenderScanMappedNetworkDrivesDuringFullScan", "defenderScanNetworkFiles", "defenderRequireCloudProtection", "defenderCloudExtendedTimeout", "defenderPromptForSampleSubmission", "defenderSystemScanSchedule", "defenderPotentiallyUnwantedAppActionSetting", "defenderBlockOnAccessProtection", "lockScreenAllowTimeoutConfiguration", "lockScreenBlockActionCenterNotifications", "lockScreenBlockCortana", "lockScreenBlockToastNotifications", "lockScreenTimeoutInSeconds", "lockScreenActivateAppsWithVoice", "passwordBlockSimple", "passwordExpirationDays", "passwordMinimumLength", "passwordMinutesOfInactivityBeforeScreenTimeout", "passwordMinimumCharacterSetCount", "passwordPreviousPasswordBlockCount", "passwordRequired", "passwordRequireWhenResumeFromIdleState", "passwordRequiredType", "passwordSignInFailureCountBeforeFactoryReset", "passwordMinimumAgeInDays", "privacyAdvertisingId", "privacyAutoAcceptPairingAndConsentPrompts", "privacyDisableLaunchExperience", "privacyBlockInputPersonalization", "privacyBlockPublishUserActivities", "privacyBlockActivityFeed", "activateAppsWithVoice", "startBlockUnpinningAppsFromTaskbar", "startMenuAppListVisibility", "startMenuHideChangeAccountSettings", "startMenuHideFrequentlyUsedApps", "startMenuHideHibernate", "startMenuHideLock", "startMenuHidePowerButton", "startMenuHideRecentJumpLists", "startMenuHideRecentlyAddedApps", "startMenuHideRestartOptions", "startMenuHideShutDown", "startMenuHideSignOut", "startMenuHideSleep", "startMenuHideSwitchAccount", "startMenuHideUserTile", "startMenuLayoutEdgeAssetsXml", "startMenuLayoutXml", "startMenuMode", "startMenuPinnedFolderDocuments", "startMenuPinnedFolderDownloads", "startMenuPinnedFolderFileExplorer", "startMenuPinnedFolderHomeGroup", "startMenuPinnedFolderMusic", "startMenuPinnedFolderNetwork", "startMenuPinnedFolderPersonalFolder", "startMenuPinnedFolderPictures", "startMenuPinnedFolderSettings", "startMenuPinnedFolderVideos", "settingsBlockSettingsApp", "settingsBlockSystemPage", "settingsBlockDevicesPage", "settingsBlockNetworkInternetPage", "settingsBlockPersonalizationPage", "settingsBlockAccountsPage", "settingsBlockTimeLanguagePage", "settingsBlockEaseOfAccessPage", "settingsBlockPrivacyPage", "settingsBlockUpdateSecurityPage", "settingsBlockAppsPage", "settingsBlockGamingPage", "windowsSpotlightBlockConsumerSpecificFeatures", "windowsSpotlightBlocked", "windowsSpotlightBlockOnActionCenter", "windowsSpotlightBlockTailoredExperiences", "windowsSpotlightBlockThirdPartyNotifications", "windowsSpotlightBlockWelcomeExperience", "windowsSpotlightBlockWindowsTips", "windowsSpotlightConfigureOnLockScreen", "networkProxyApplySettingsDeviceWide", "networkProxyDisableAutoDetect", "networkProxyAutomaticConfigurationUrl", "networkProxyServer", "accountsBlockAddingNonMicrosoftAccountEmail", "antiTheftModeBlocked", "bluetoothBlocked", "cameraBlocked", "connectedDevicesServiceBlocked", "certificatesBlockManualRootCertificateInstallation", "copyPasteBlocked", "cortanaBlocked", "deviceManagementBlockFactoryResetOnMobile", "deviceManagementBlockManualUnenroll", "safeSearchFilter", "edgeBlockPopups", "edgeBlockSearchSuggestions", "edgeBlockSearchEngineCustomization", "edgeBlockSendingIntranetTrafficToInternetExplorer", "edgeSendIntranetTrafficToInternetExplorer", "edgeRequireSmartScreen", "edgeEnterpriseModeSiteListLocation", "edgeFirstRunUrl", "edgeSearchEngine", "edgeHomepageUrls", "edgeBlockAccessToAboutFlags", "smartScreenBlockPromptOverride", "smartScreenBlockPromptOverrideForFiles", "webRtcBlockLocalhostIpAddress", "internetSharingBlocked", "settingsBlockAddProvisioningPackage", "settingsBlockRemoveProvisioningPackage", "settingsBlockChangeSystemTime", "settingsBlockEditDeviceName", "settingsBlockChangeRegion", "settingsBlockChangeLanguage", "settingsBlockChangePowerSleep", "locationServicesBlocked", "microsoftAccountBlocked", "microsoftAccountBlockSettingsSync", "nfcBlocked", "resetProtectionModeBlocked", "screenCaptureBlocked", "storageBlockRemovableStorage", "storageRequireMobileDeviceEncryption", "usbBlocked", "voiceRecordingBlocked", "wiFiBlockAutomaticConnectHotspots", "wiFiBlocked", "wiFiBlockManualConfiguration", "wiFiScanInterval", "wirelessDisplayBlockProjectionToThisDevice", "wirelessDisplayBlockUserInputFromReceiver", "wirelessDisplayRequirePinForPairing", "windowsStoreBlocked", "appsAllowTrustedAppsSideloading", "windowsStoreBlockAutoUpdate", "developerUnlockSetting", "sharedUserAppDataAllowed", "appsBlockWindowsStoreOriginatedApps", "windowsStoreEnablePrivateStoreOnly", "storageRestrictAppDataToSystemVolume", "storageRestrictAppInstallToSystemVolume", "gameDvrBlocked", "experienceBlockDeviceDiscovery", "experienceBlockErrorDialogWhenNoSIM", "experienceBlockTaskSwitcher", "logonBlockFastUserSwitching", "tenantLockdownRequireNetworkDuringOutOfBoxExperience", "appManagementMSIAllowUserControlOverInstall", "appManagementMSIAlwaysInstallWithElevatedPrivileges", "dataProtectionBlockDirectMemoryAccess", "appManagementPackageFamilyNamesToLaunchAfterLogOn", "uninstallBuiltInApps", "configureTimeZone", "deliveryOptimizationMode", "prereleaseFeatures", "automaticUpdateMode", "microsoftUpdateServiceAllowed", "driversExcluded", "installationSchedule", "qualityUpdatesDeferralPeriodInDays", "featureUpdatesDeferralPeriodInDays", "qualityUpdatesPaused", "featureUpdatesPaused", "qualityUpdatesPauseExpiryDateTime", "featureUpdatesPauseExpiryDateTime", "businessReadyUpdatesOnly", "skipChecksBeforeRestart", "updateWeeks", "qualityUpdatesPauseStartDate", "featureUpdatesPauseStartDate", "featureUpdatesRollbackWindowInDays", "qualityUpdatesWillBeRolledBack", "featureUpdatesWillBeRolledBack", "qualityUpdatesRollbackStartDateTime", "featureUpdatesRollbackStartDateTime", "engagedRestartDeadlineInDays", "engagedRestartSnoozeScheduleInDays", "engagedRestartTransitionScheduleInDays", "deadlineForFeatureUpdatesInDays", "deadlineForQualityUpdatesInDays", "deadlineGracePeriodInDays", "postponeRebootUntilAfterDeadline", "autoRestartNotificationDismissal", "scheduleRestartWarningInHours", "scheduleImminentRestartWarningInMinutes", "userPauseAccess", "userWindowsUpdateScanAccess", "updateNotificationLevel"}, {"id", "lastModifiedDateTime", "roleScopeTagIds", "supportsScopeTags", "deviceManagementApplicabilityRuleOsEdition", "deviceManagementApplicabilityRuleOsVersion", "deviceManagementApplicabilityRuleDeviceMode", "createdDateTime", "description", "displayName", "version", "dmaGuardDeviceEnumerationPolicy", "userRightsAccessCredentialManagerAsTrustedCaller", "userRightsAllowAccessFromNetwork", "userRightsBlockAccessFromNetwork", "userRightsActAsPartOfTheOperatingSystem", "userRightsLocalLogOn", "userRightsDenyLocalLogOn", "userRightsBackupData", "userRightsChangeSystemTime", "userRightsCreateGlobalObjects", "userRightsCreatePageFile", "userRightsCreatePermanentSharedObjects", "userRightsCreateSymbolicLinks", "userRightsCreateToken", "userRightsDebugPrograms", "userRightsRemoteDesktopServicesLogOn", "userRightsDelegation", "userRightsGenerateSecurityAudits", "userRightsImpersonateClient", "userRightsIncreaseSchedulingPriority", "userRightsLoadUnloadDrivers", "userRightsLockMemory", "userRightsManageAuditingAndSecurityLogs", "userRightsManageVolumes", "userRightsModifyFirmwareEnvironment", "userRightsModifyObjectLabels", "userRightsProfileSingleProcess", "userRightsRemoteShutdown", "userRightsRestoreData", "userRightsTakeOwnership", "xboxServicesEnableXboxGameSaveTask", "xboxServicesAccessoryManagementServiceStartupMode", "xboxServicesLiveAuthManagerServiceStartupMode", "xboxServicesLiveGameSaveServiceStartupMode", "xboxServicesLiveNetworkingServiceStartupMode", "localSecurityOptionsBlockMicrosoftAccounts", "localSecurityOptionsBlockRemoteLogonWithBlankPassword", "localSecurityOptionsDisableAdministratorAccount", "localSecurityOptionsAdministratorAccountName", "localSecurityOptionsDisableGuestAccount", "localSecurityOptionsGuestAccountName", "localSecurityOptionsAllowUndockWithoutHavingToLogon", "localSecurityOptionsBlockUsersInstallingPrinterDrivers", "localSecurityOptionsBlockRemoteOpticalDriveAccess", "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser", "localSecurityOptionsMachineInactivityLimit", "localSecurityOptionsMachineInactivityLimitInMinutes", "localSecurityOptionsDoNotRequireCtrlAltDel", "localSecurityOptionsHideLastSignedInUser", "localSecurityOptionsHideUsernameAtSignIn", "localSecurityOptionsLogOnMessageTitle", "localSecurityOptionsLogOnMessageText", "localSecurityOptionsAllowPKU2UAuthenticationRequests", "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool", "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager", "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients", "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers", "lanManagerAuthenticationLevel", "lanManagerWorkstationDisableInsecureGuestLogons", "localSecurityOptionsClearVirtualMemoryPageFile", "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn", "localSecurityOptionsAllowUIAccessApplicationElevation", "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations", "localSecurityOptionsOnlyElevateSignedExecutables", "localSecurityOptionsAdministratorElevationPromptBehavior", "localSecurityOptionsStandardUserElevationPromptBehavior", "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation", "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation", "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations", "localSecurityOptionsUseAdminApprovalMode", "localSecurityOptionsUseAdminApprovalModeForAdministrators", "localSecurityOptionsInformationShownOnLockScreen", "localSecurityOptionsInformationDisplayedOnLockScreen", "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees", "localSecurityOptionsClientDigitallySignCommunicationsAlways", "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers", "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways", "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees", "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares", "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts", "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares", "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange", "localSecurityOptionsSmartCardRemovalBehavior", "defenderSecurityCenterDisableAppBrowserUI", "defenderSecurityCenterDisableFamilyUI", "defenderSecurityCenterDisableHealthUI", "defenderSecurityCenterDisableNetworkUI", "defenderSecurityCenterDisableVirusUI", "defenderSecurityCenterDisableAccountUI", "defenderSecurityCenterDisableClearTpmUI", "defenderSecurityCenterDisableHardwareUI", "defenderSecurityCenterDisableNotificationAreaUI", "defenderSecurityCenterDisableRansomwareUI", "defenderSecurityCenterDisableSecureBootUI", "defenderSecurityCenterDisableTroubleshootingUI", "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI", "defenderSecurityCenterOrganizationDisplayName", "defenderSecurityCenterHelpEmail", "defenderSecurityCenterHelpPhone", "defenderSecurityCenterHelpURL", "defenderSecurityCenterNotificationsFromApp", "defenderSecurityCenterITContactDisplay", "windowsDefenderTamperProtection", "firewallBlockStatefulFTP", "firewallIdleTimeoutForSecurityAssociationInSeconds", "firewallPreSharedKeyEncodingMethod", "firewallIPSecExemptionsAllowNeighborDiscovery", "firewallIPSecExemptionsAllowICMP", "firewallIPSecExemptionsAllowRouterDiscovery", "firewallIPSecExemptionsAllowDHCP", "firewallCertificateRevocationListCheckMethod", "firewallMergeKeyingModuleSettings", "firewallPacketQueueingMethod", "firewallProfileDomain", "firewallProfilePublic", "firewallProfilePrivate", "defenderAdobeReaderLaunchChildProcess", "defenderAttackSurfaceReductionExcludedPaths", "defenderOfficeAppsOtherProcessInjectionType", "defenderOfficeAppsOtherProcessInjection", "defenderOfficeCommunicationAppsLaunchChildProcess", "defenderOfficeAppsExecutableContentCreationOrLaunchType", "defenderOfficeAppsExecutableContentCreationOrLaunch", "defenderOfficeAppsLaunchChildProcessType", "defenderOfficeAppsLaunchChildProcess", "defenderOfficeMacroCodeAllowWin32ImportsType", "defenderOfficeMacroCodeAllowWin32Imports", "defenderScriptObfuscatedMacroCodeType", "defenderScriptObfuscatedMacroCode", "defenderScriptDownloadedPayloadExecutionType", "defenderScriptDownloadedPayloadExecution", "defenderPreventCredentialStealingType", "defenderProcessCreationType", "defenderProcessCreation", "defenderUntrustedUSBProcessType", "defenderUntrustedUSBProcess", "defenderUntrustedExecutableType", "defenderUntrustedExecutable", "defenderEmailContentExecutionType", "defenderEmailContentExecution", "defenderAdvancedRansomewareProtectionType", "defenderGuardMyFoldersType", "defenderGuardedFoldersAllowedAppPaths", "defenderAdditionalGuardedFolders", "defenderNetworkProtectionType", "defenderExploitProtectionXml", "defenderExploitProtectionXmlFileName", "defenderSecurityCenterBlockExploitProtectionOverride", "appLockerApplicationControl", "deviceGuardLocalSystemAuthorityCredentialGuardSettings", "deviceGuardEnableVirtualizationBasedSecurity", "deviceGuardEnableSecureBootWithDMA", "deviceGuardSecureBootWithDMA", "deviceGuardLaunchSystemGuard", "smartScreenEnableInShell", "smartScreenBlockOverrideForFiles", "applicationGuardEnabled", "applicationGuardEnabledOptions", "applicationGuardBlockFileTransfer", "applicationGuardBlockNonEnterpriseContent", "applicationGuardAllowPersistence", "applicationGuardForceAuditing", "applicationGuardBlockClipboardSharing", "applicationGuardAllowPrintToPDF", "applicationGuardAllowPrintToXPS", "applicationGuardAllowPrintToLocalPrinters", "applicationGuardAllowPrintToNetworkPrinters", "applicationGuardAllowVirtualGPU", "applicationGuardAllowFileSaveOnHost", "bitLockerAllowStandardUserEncryption", "bitLockerDisableWarningForOtherDiskEncryption", "bitLockerEnableStorageCardEncryptionOnMobile", "bitLockerEncryptDevice", "bitLockerSystemDrivePolicy", "bitLockerFixedDrivePolicy", "bitLockerRemovableDrivePolicy", "bitLockerRecoveryPasswordRotation", "defenderDisableScanArchiveFiles", "defenderAllowScanArchiveFiles", "defenderDisableBehaviorMonitoring", "defenderAllowBehaviorMonitoring", "defenderDisableCloudProtection", "defenderAllowCloudProtection", "defenderEnableScanIncomingMail", "defenderEnableScanMappedNetworkDrivesDuringFullScan", "defenderDisableScanRemovableDrivesDuringFullScan", "defenderAllowScanRemovableDrivesDuringFullScan", "defenderDisableScanDownloads", "defenderAllowScanDownloads", "defenderDisableIntrusionPreventionSystem", "defenderAllowIntrusionPreventionSystem", "defenderDisableOnAccessProtection", "defenderAllowOnAccessProtection", "defenderDisableRealTimeMonitoring", "defenderAllowRealTimeMonitoring", "defenderDisableScanNetworkFiles", "defenderAllowScanNetworkFiles", "defenderDisableScanScriptsLoadedInInternetExplorer", "defenderAllowScanScriptsLoadedInInternetExplorer", "defenderBlockEndUserAccess", "defenderAllowEndUserAccess", "defenderScanMaxCpuPercentage", "defenderCheckForSignaturesBeforeRunningScan", "defenderCloudBlockLevel", "defenderCloudExtendedTimeoutInSeconds", "defenderDaysBeforeDeletingQuarantinedMalware", "defenderDisableCatchupFullScan", "defenderDisableCatchupQuickScan", "defenderEnableLowCpuPriority", "defenderFileExtensionsToExclude", "defenderFilesAndFoldersToExclude", "defenderProcessesToExclude", "defenderPotentiallyUnwantedAppAction", "defenderScanDirection", "defenderScanType", "defenderScheduledQuickScanTime", "defenderScheduledScanDay", "defenderScheduledScanTime", "defenderSignatureUpdateIntervalInHours", "defenderSubmitSamplesConsentType", "defenderDetectedMalwareActions", "firewallRules", "taskManagerBlockEndTask", "energySaverOnBatteryThresholdPercentage", "energySaverPluggedInThresholdPercentage", "powerLidCloseActionOnBattery", "powerLidCloseActionPluggedIn", "powerButtonActionOnBattery", "powerButtonActionPluggedIn", "powerSleepButtonActionOnBattery", "powerSleepButtonActionPluggedIn", "powerHybridSleepOnBattery", "powerHybridSleepPluggedIn", "windows10AppsForceUpdateSchedule", "enableAutomaticRedeployment", "microsoftAccountSignInAssistantSettings", "authenticationAllowSecondaryDevice", "authenticationWebSignIn", "authenticationPreferredAzureADTenantDomainName", "cryptographyAllowFipsAlgorithmPolicy", "displayAppListWithGdiDPIScalingTurnedOn", "displayAppListWithGdiDPIScalingTurnedOff", "enterpriseCloudPrintDiscoveryEndPoint", "enterpriseCloudPrintOAuthAuthority", "enterpriseCloudPrintOAuthClientIdentifier", "enterpriseCloudPrintResourceIdentifier", "enterpriseCloudPrintDiscoveryMaxLimit", "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier", "experienceDoNotSyncBrowserSettings", "messagingBlockSync", "messagingBlockMMS", "messagingBlockRichCommunicationServices", "printerNames", "printerDefaultName", "printerBlockAddition", "searchBlockDiacritics", "searchDisableAutoLanguageDetection", "searchDisableIndexingEncryptedItems", "searchEnableRemoteQueries", "searchDisableUseLocation", "searchDisableLocation", "searchDisableIndexerBackoff", "searchDisableIndexingRemovableDrive", "searchEnableAutomaticIndexSizeManangement", "searchBlockWebResults", "findMyFiles", "securityBlockAzureADJoinedDevicesAutoEncryption", "diagnosticsDataSubmissionMode", "oneDriveDisableFileSync", "systemTelemetryProxyServer", "edgeTelemetryForMicrosoft365Analytics", "inkWorkspaceAccess", "inkWorkspaceAccessState", "inkWorkspaceBlockSuggestedApps", "smartScreenEnableAppInstallControl", "smartScreenAppInstallControl", "personalizationDesktopImageUrl", "personalizationLockScreenImageUrl", "bluetoothAllowedServices", "bluetoothBlockAdvertising", "bluetoothBlockPromptedProximalConnections", "bluetoothBlockDiscoverableMode", "bluetoothBlockPrePairing", "edgeBlockAutofill", "edgeBlocked", "edgeCookiePolicy", "edgeBlockDeveloperTools", "edgeBlockSendingDoNotTrackHeader", "edgeBlockExtensions", "edgeBlockInPrivateBrowsing", "edgeBlockJavaScript", "edgeBlockPasswordManager", "edgeBlockAddressBarDropdown", "edgeBlockCompatibilityList", "edgeClearBrowsingDataOnExit", "edgeAllowStartPagesModification", "edgeDisableFirstRunPage", "edgeBlockLiveTileDataCollection", "edgeSyncFavoritesWithInternetExplorer", "edgeFavoritesListLocation", "edgeBlockEditFavorites", "edgeNewTabPageURL", "edgeHomeButtonConfiguration", "edgeHomeButtonConfigurationEnabled", "edgeOpensWith", "edgeBlockSideloadingExtensions", "edgeRequiredExtensionPackageFamilyNames", "edgeBlockPrinting", "edgeFavoritesBarVisibility", "edgeBlockSavingHistory", "edgeBlockFullScreenMode", "edgeBlockWebContentOnNewTabPage", "edgeBlockTabPreloading", "edgeBlockPrelaunch", "edgeShowMessageWhenOpeningInternetExplorerSites", "edgePreventCertificateErrorOverride", "edgeKioskModeRestriction", "edgeKioskResetAfterIdleTimeInMinutes", "cellularBlockDataWhenRoaming", "cellularBlockVpn", "cellularBlockVpnWhenRoaming", "cellularData", "defenderRequireRealTimeMonitoring", "defenderRequireBehaviorMonitoring", "defenderRequireNetworkInspectionSystem", "defenderScanDownloads", "defenderScheduleScanEnableLowCpuPriority", "defenderScanScriptsLoadedInInternetExplorer", "defenderMonitorFileActivity", "defenderScanMaxCpu", "defenderScanArchiveFiles", "defenderScanIncomingMail", "defenderScanRemovableDrivesDuringFullScan", "defenderScanMappedNetworkDrivesDuringFullScan", "defenderScanNetworkFiles", "defenderRequireCloudProtection", "defenderCloudExtendedTimeout", "defenderPromptForSampleSubmission", "defenderSystemScanSchedule", "defenderPotentiallyUnwantedAppActionSetting", "defenderBlockOnAccessProtection", "lockScreenAllowTimeoutConfiguration", "lockScreenBlockActionCenterNotifications", "lockScreenBlockCortana", "lockScreenBlockToastNotifications", "lockScreenTimeoutInSeconds", "lockScreenActivateAppsWithVoice", "passwordBlockSimple", "passwordExpirationDays", "passwordMinimumLength", "passwordMinutesOfInactivityBeforeScreenTimeout", "passwordMinimumCharacterSetCount", "passwordPreviousPasswordBlockCount", "passwordRequired", "passwordRequireWhenResumeFromIdleState", "passwordRequiredType", "passwordSignInFailureCountBeforeFactoryReset", "passwordMinimumAgeInDays", "privacyAdvertisingId", "privacyAutoAcceptPairingAndConsentPrompts", "privacyDisableLaunchExperience", "privacyBlockInputPersonalization", "privacyBlockPublishUserActivities", "privacyBlockActivityFeed", "activateAppsWithVoice", "startBlockUnpinningAppsFromTaskbar", "startMenuAppListVisibility", "startMenuHideChangeAccountSettings", "startMenuHideFrequentlyUsedApps", "startMenuHideHibernate", "startMenuHideLock", "startMenuHidePowerButton", "startMenuHideRecentJumpLists", "startMenuHideRecentlyAddedApps", "startMenuHideRestartOptions", "startMenuHideShutDown", "startMenuHideSignOut", "startMenuHideSleep", "startMenuHideSwitchAccount", "startMenuHideUserTile", "startMenuLayoutEdgeAssetsXml", "startMenuLayoutXml", "startMenuMode", "startMenuPinnedFolderDocuments", "startMenuPinnedFolderDownloads", "startMenuPinnedFolderFileExplorer", "startMenuPinnedFolderHomeGroup", "startMenuPinnedFolderMusic", "startMenuPinnedFolderNetwork", "startMenuPinnedFolderPersonalFolder", "startMenuPinnedFolderPictures", "startMenuPinnedFolderSettings", "startMenuPinnedFolderVideos", "settingsBlockSettingsApp", "settingsBlockSystemPage", "settingsBlockDevicesPage", "settingsBlockNetworkInternetPage", "settingsBlockPersonalizationPage", "settingsBlockAccountsPage", "settingsBlockTimeLanguagePage", "settingsBlockEaseOfAccessPage", "settingsBlockPrivacyPage", "settingsBlockUpdateSecurityPage", "settingsBlockAppsPage", "settingsBlockGamingPage", "windowsSpotlightBlockConsumerSpecificFeatures", "windowsSpotlightBlocked", "windowsSpotlightBlockOnActionCenter", "windowsSpotlightBlockTailoredExperiences", "windowsSpotlightBlockThirdPartyNotifications", "windowsSpotlightBlockWelcomeExperience", "windowsSpotlightBlockWindowsTips", "windowsSpotlightConfigureOnLockScreen", "networkProxyApplySettingsDeviceWide", "networkProxyDisableAutoDetect", "networkProxyAutomaticConfigurationUrl", "networkProxyServer", "accountsBlockAddingNonMicrosoftAccountEmail", "antiTheftModeBlocked", "bluetoothBlocked", "cameraBlocked", "connectedDevicesServiceBlocked", "certificatesBlockManualRootCertificateInstallation", "copyPasteBlocked", "cortanaBlocked", "deviceManagementBlockFactoryResetOnMobile", "deviceManagementBlockManualUnenroll", "safeSearchFilter", "edgeBlockPopups", "edgeBlockSearchSuggestions", "edgeBlockSearchEngineCustomization", "edgeBlockSendingIntranetTrafficToInternetExplorer", "edgeSendIntranetTrafficToInternetExplorer", "edgeRequireSmartScreen", "edgeEnterpriseModeSiteListLocation", "edgeFirstRunUrl", "edgeSearchEngine", "edgeHomepageUrls", "edgeBlockAccessToAboutFlags", "smartScreenBlockPromptOverride", "smartScreenBlockPromptOverrideForFiles", "webRtcBlockLocalhostIpAddress", "internetSharingBlocked", "settingsBlockAddProvisioningPackage", "settingsBlockRemoveProvisioningPackage", "settingsBlockChangeSystemTime", "settingsBlockEditDeviceName", "settingsBlockChangeRegion", "settingsBlockChangeLanguage", "settingsBlockChangePowerSleep", "locationServicesBlocked", "microsoftAccountBlocked", "microsoftAccountBlockSettingsSync", "nfcBlocked", "resetProtectionModeBlocked", "screenCaptureBlocked", "storageBlockRemovableStorage", "storageRequireMobileDeviceEncryption", "usbBlocked", "voiceRecordingBlocked", "wiFiBlockAutomaticConnectHotspots", "wiFiBlocked", "wiFiBlockManualConfiguration", "wiFiScanInterval", "wirelessDisplayBlockProjectionToThisDevice", "wirelessDisplayBlockUserInputFromReceiver", "wirelessDisplayRequirePinForPairing", "windowsStoreBlocked", "appsAllowTrustedAppsSideloading", "windowsStoreBlockAutoUpdate", "developerUnlockSetting", "sharedUserAppDataAllowed", "appsBlockWindowsStoreOriginatedApps", "windowsStoreEnablePrivateStoreOnly", "storageRestrictAppDataToSystemVolume", "storageRestrictAppInstallToSystemVolume", "gameDvrBlocked", "experienceBlockDeviceDiscovery", "experienceBlockErrorDialogWhenNoSIM", "experienceBlockTaskSwitcher", "logonBlockFastUserSwitching", "tenantLockdownRequireNetworkDuringOutOfBoxExperience", "appManagementMSIAllowUserControlOverInstall", "appManagementMSIAlwaysInstallWithElevatedPrivileges", "dataProtectionBlockDirectMemoryAccess", "appManagementPackageFamilyNamesToLaunchAfterLogOn", "uninstallBuiltInApps", "configureTimeZone", "deliveryOptimizationMode", "prereleaseFeatures", "automaticUpdateMode", "microsoftUpdateServiceAllowed", "driversExcluded", "installationSchedule", "qualityUpdatesDeferralPeriodInDays", "featureUpdatesDeferralPeriodInDays", "qualityUpdatesPaused", "featureUpdatesPaused", "qualityUpdatesPauseExpiryDateTime", "featureUpdatesPauseExpiryDateTime", "businessReadyUpdatesOnly", "skipChecksBeforeRestart", "updateWeeks", "qualityUpdatesPauseStartDate", "featureUpdatesPauseStartDate", "featureUpdatesRollbackWindowInDays", "qualityUpdatesWillBeRolledBack", "featureUpdatesWillBeRolledBack", "qualityUpdatesRollbackStartDateTime", "featureUpdatesRollbackStartDateTime", "engagedRestartDeadlineInDays", "engagedRestartSnoozeScheduleInDays", "engagedRestartTransitionScheduleInDays", "deadlineForFeatureUpdatesInDays", "deadlineForQualityUpdatesInDays", "deadlineGracePeriodInDays", "postponeRebootUntilAfterDeadline", "autoRestartNotificationDismissal", "scheduleRestartWarningInHours", "scheduleImminentRestartWarningInMinutes", "userPauseAccess", "userWindowsUpdateScanAccess", "updateNotificationLevel"})
    in
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicySettingStates = () =>
    let
        GetData = (deviceId as text, policyId as text, tenantId as text) => 
            let
                accessToken = Helper.GetAccessToken(tenantId),
                source = MicrosoftGraph.GetPagedContent("deviceManagement/managedDevices/" & deviceId & "/deviceConfigurationStates/" & policyId & "/settingStates", accessToken)
            in 
                source,

        source = SecMgmtInsights.DeviceConfigurationPolicyStates(),
        policyStates = Table.SelectColumns(source, {"customerId", "deviceId", "id"}),
        renamedColumn =  Table.RenameColumns(policyStates, {{"id", "policyId"}}),
        policySettingStates = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [policyId], [customerId]) otherwise null),
        settingsTable = Table.ExpandListColumn(policySettingStates, "Custom"),
        expandedCustom = Table.ExpandListColumn(settingsTable, "Custom"), 
        expandedRecord = Table.ExpandRecordColumn(expandedCustom, "Custom", {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}, {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}),
        expandedSourcesList = Table.ExpandListColumn(expandedRecord, "sources"),
        expandedSourcesRecord = Table.ExpandRecordColumn(expandedSourcesList, "sources", {"id", "displayName"}, {"sources.id", "sources.displayName"})
    in 
        expandedSourcesRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicyStates = () =>
    let 
        GetData = (deviceId as text, tenantId as text) =>
            let
                accessToken = Helper.GetAccessToken(tenantId),
                data = MicrosoftGraph.GetPagedContent("deviceManagement/managedDevices/" & deviceId & "/deviceConfigurationStates", accessToken)
            in 
                data,
        
        source = SecMgmtInsights.ManagedDevices(),
        managedDevices = Table.SelectColumns(source, {"customerId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        states = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [customerId]) otherwise null),
        statesTable = Table.ExpandListColumn(states, "Custom"),
        expandedCustom = Table.ExpandListColumn(statesTable, "Custom"),
        expandedRecord = Table.ExpandRecordColumn(expandedCustom, "Custom", {"id", "displayName", "version", "platformType", "state", "settingCount", "userId", "userPrincipalName", "settingStates"}, {"id", "displayName", "version", "platformType", "state", "settingCount", "userId", "userPrincipalName", "settingStates"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Intents = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/intents"),
        expandedCustom = Table.ExpandRecordColumn(data, "Custom", {"id", "displayName", "description", "isAssigned", "lastModifiedDateTime", "templateId", "roleScopeTagIds"}, {"id", "displayName", "description", "isAssigned", "lastModifiedDateTime", "templateId", "roleScopeTagIds"}),
        changedType = Table.TransformColumnTypes(expandedCustom, {{"isAssigned", type logical}, {"lastModifiedDateTime", type datetimezone}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ManagedDevices = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/managedDevices"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "userId", "deviceName", "ownerType", "managedDeviceOwnerType", "managementState", "enrolledDateTime", "lastSyncDateTime", "chassisType", "operatingSystem", "deviceType", "complianceState", "jailBroken", "managementAgent", "osVersion", "easActivated", "easDeviceId", "easActivationDateTime", "aadRegistered", "azureADRegistered", "deviceEnrollmentType", "lostModeState", "activationLockBypassCode", "emailAddress", "azureActiveDirectoryDeviceId", "azureADDeviceId", "deviceRegistrationState", "deviceCategoryDisplayName", "isSupervised", "exchangeLastSuccessfulSyncDateTime", "exchangeAccessState", "exchangeAccessStateReason", "remoteAssistanceSessionUrl", "remoteAssistanceSessionErrorDetails", "isEncrypted", "userPrincipalName", "model", "manufacturer", "imei", "complianceGracePeriodExpirationDateTime", "serialNumber", "phoneNumber", "androidSecurityPatchLevel", "userDisplayName", "configurationManagerClientEnabledFeatures", "wiFiMacAddress", "deviceHealthAttestationState", "subscriberCarrier", "meid", "totalStorageSpaceInBytes", "freeStorageSpaceInBytes", "managedDeviceName", "partnerReportedThreatState", "retireAfterDateTime", "preferMdmOverGroupPolicyAppliedDateTime", "autopilotEnrolled", "requireUserEnrollmentApproval", "managementCertificateExpirationDate", "iccid", "udid", "roleScopeTagIds", "windowsActiveMalwareCount", "windowsRemediatedMalwareCount", "notes", "configurationManagerClientHealthState", "configurationManagerClientInformation", "ethernetMacAddress", "physicalMemoryInBytes", "processorArchitecture", "specificationVersion", "hardwareInformation", "deviceActionResults", "usersLoggedOn"}, {"id", "userId", "deviceName", "ownerType", "managedDeviceOwnerType", "managementState", "enrolledDateTime", "lastSyncDateTime", "chassisType", "operatingSystem", "deviceType", "complianceState", "jailBroken", "managementAgent", "osVersion", "easActivated", "easDeviceId", "easActivationDateTime", "aadRegistered", "azureADRegistered", "deviceEnrollmentType", "lostModeState", "activationLockBypassCode", "emailAddress", "azureActiveDirectoryDeviceId", "azureADDeviceId", "deviceRegistrationState", "deviceCategoryDisplayName", "isSupervised", "exchangeLastSuccessfulSyncDateTime", "exchangeAccessState", "exchangeAccessStateReason", "remoteAssistanceSessionUrl", "remoteAssistanceSessionErrorDetails", "isEncrypted", "userPrincipalName", "model", "manufacturer", "imei", "complianceGracePeriodExpirationDateTime", "serialNumber", "phoneNumber", "androidSecurityPatchLevel", "userDisplayName", "configurationManagerClientEnabledFeatures", "wiFiMacAddress", "deviceHealthAttestationState", "subscriberCarrier", "meid", "totalStorageSpaceInBytes", "freeStorageSpaceInBytes", "managedDeviceName", "partnerReportedThreatState", "retireAfterDateTime", "preferMdmOverGroupPolicyAppliedDateTime", "autopilotEnrolled", "requireUserEnrollmentApproval", "managementCertificateExpirationDate", "iccid", "udid", "roleScopeTagIds", "windowsActiveMalwareCount", "windowsRemediatedMalwareCount", "notes", "configurationManagerClientHealthState", "configurationManagerClientInformation", "ethernetMacAddress", "physicalMemoryInBytes", "processorArchitecture", "specificationVersion", "hardwareInformation", "deviceActionResults", "usersLoggedOn"}),
        changedType = Table.TransformColumnTypes(expandedRecord,{{"enrolledDateTime", type datetimezone}, {"lastSyncDateTime", type datetimezone}, {"easActivated", type logical}, {"easActivationDateTime", type datetimezone}, {"aadRegistered", type logical}, {"azureADRegistered", type logical}, {"exchangeLastSuccessfulSyncDateTime", type datetimezone}, {"isEncrypted", type logical}, {"complianceGracePeriodExpirationDateTime", type datetimezone}, {"retireAfterDateTime", type datetimezone}, {"preferMdmOverGroupPolicyAppliedDateTime", type datetimezone}, {"autopilotEnrolled", type logical}, {"managementCertificateExpirationDate", type datetimezone}, {"windowsActiveMalwareCount", Int64.Type}, {"windowsRemediatedMalwareCount", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineSettingStates = () =>
    let
        GetData = (deviceId as text, templateId as text, tenantId as text) => 
            let
                accessToken = Helper.GetAccessToken(tenantId),
                source = MicrosoftGraph.GetPagedContent("deviceManagement/managedDevices/" & deviceId & "/securityBaselineStates/" & templateId & "/settingStates", accessToken)
            in 
                source,

        source = SecMgmtInsights.SecurityBaselineStates(),
        data = Table.SelectColumns(source, {"customerId", "deviceId", "id"}),
        renamedColumn =  Table.RenameColumns(data, {{"id", "templateId"}}),
        settingStates = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [templateId], [customerId]) otherwise null),
        settingsTable = Table.ExpandListColumn(settingStates, "Custom"),
        expandedCustom = Table.ExpandListColumn(settingsTable, "Custom"),
        expandedRecord = Table.ExpandRecordColumn(expandedCustom, "Custom", {"id", "settingName", "state", "settingCategoryId"}, {"id", "settingName", "state", "settingCategoryId"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineStates = () =>
    let 
        GetData = (deviceId as text, tenantId as text) =>
            let
                accessToken = Helper.GetAccessToken(tenantId),
                data = MicrosoftGraph.GetPagedContent("deviceManagement/managedDevices/" & deviceId & "/securityBaselineStates", accessToken)
            in 
                data,
        
        source = SecMgmtInsights.ManagedDevices(),
        managedDevices = Table.SelectColumns(source, {"customerId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        states = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [customerId]) otherwise null),
        statesTable = Table.ExpandListColumn(states, "Custom"),
        expandedCustom = Table.ExpandListColumn(statesTable, "Custom"),
        expandedRecord = Table.ExpandRecordColumn(expandedCustom, "Custom", {"id", "securityBaselineTemplateId", "displayName"}, {"id", "securityBaselineTemplateId", "displayName"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserExperienceAnalyticsDevicePerformance = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/userExperienceAnalyticsDevicePerformance"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "deviceName", "model", "manufacturer", "diskType", "operatingSystemVersion", "bootScore", "coreBootTimeInMs", "groupPolicyBootTimeInMs", "operatingSystem", "healthStatus", "complianceState", "loginScore", "coreLoginTimeInMs", "groupPolicyLoginTimeInMs", "deviceCount", "responsiveDesktopTimeInMs"}, {"id", "deviceName", "model", "manufacturer", "diskType", "operatingSystemVersion", "bootScore", "coreBootTimeInMs", "groupPolicyBootTimeInMs", "operatingSystem", "healthStatus", "complianceState", "loginScore", "coreLoginTimeInMs", "groupPolicyLoginTimeInMs", "deviceCount", "responsiveDesktopTimeInMs"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserExperienceAnalyticsDeviceStartupHistory = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/userExperienceAnalyticsDeviceStartupHistory")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserExperienceAnalyticsDeviceStartupProcessPerformance = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/userExperienceAnalyticsDeviceStartupProcessPerformance")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotDeviceIdentities = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/windowsAutopilotDeviceIdentities"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "deploymentProfileAssignmentStatus", "deploymentProfileAssignmentDetailedStatus", "deploymentProfileAssignedDateTime", "orderIdentifier", "groupTag", "purchaseOrderIdentifier", "serialNumber", "productKey", "manufacturer", "model", "enrollmentState", "lastContactedDateTime", "addressableUserName", "userPrincipalName", "resourceName", "skuNumber", "systemFamily", "azureActiveDirectoryDeviceId", "managedDeviceId", "displayName"}, {"id", "deploymentProfileAssignmentStatus", "deploymentProfileAssignmentDetailedStatus", "deploymentProfileAssignedDateTime", "orderIdentifier", "groupTag", "purchaseOrderIdentifier", "serialNumber", "productKey", "manufacturer", "model", "enrollmentState", "lastContactedDateTime", "addressableUserName", "userPrincipalName", "resourceName", "skuNumber", "systemFamily", "azureActiveDirectoryDeviceId", "managedDeviceId", "displayName"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"deploymentProfileAssignedDateTime", type datetimezone}, {"lastContactedDateTime", type datetimezone}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotProfiles = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/windowsAutopilotDeploymentProfiles"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "displayName", "description", "language", "createdDateTime", "lastModifiedDateTime", "enrollmentStatusScreenSettings", "extractHardwareHash", "deviceNameTemplate", "deviceType", "enableWhiteGlove", "roleScopeTagIds", "outOfBoxExperienceSettings"}, {"id", "displayName", "description", "language", "createdDateTime", "lastModifiedDateTime", "enrollmentStatusScreenSettings", "extractHardwareHash", "deviceNameTemplate", "deviceType", "enableWhiteGlove", "roleScopeTagIds", "outOfBoxExperienceSettings"}),
        expandedOobe = Table.ExpandRecordColumn(expandedRecord, "outOfBoxExperienceSettings", {"hidePrivacySettings", "hideEULA", "userType", "deviceUsageType", "skipKeyboardSelectionPage", "hideEscapeLink"}, {"outOfBoxExperienceSettings.hidePrivacySettings", "outOfBoxExperienceSettings.hideEULA", "outOfBoxExperienceSettings.userType", "outOfBoxExperienceSettings.deviceUsageType", "outOfBoxExperienceSettings.skipKeyboardSelectionPage", "outOfBoxExperienceSettings.hideEscapeLink"}),
        changedType = Table.TransformColumnTypes(expandedOobe, {{"createdDateTime", type datetimezone}, {"lastModifiedDateTime", type datetimezone}, {"extractHardwareHash", type logical}, {"enableWhiteGlove", type logical}, {"outOfBoxExperienceSettings.hidePrivacySettings", type logical}, {"outOfBoxExperienceSettings.hideEULA", type logical}, {"outOfBoxExperienceSettings.skipKeyboardSelectionPage", type logical}, {"outOfBoxExperienceSettings.hideEscapeLink", type logical}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotSettings = () =>
    let 
        data = Helper.GetDataForAllCustomers("deviceManagement/windowsAutopilotSettings"),
        expandedCustom = Table.ExpandRecordColumn(data, "Custom", {"id", "lastSyncDateTime", "lastManualSyncTriggerDateTime", "syncStatus"}, {"id", "lastSyncDateTime", "lastManualSyncTriggerDateTime", "syncStatus"}),
        changedType = Table.TransformColumnTypes(expandedCustom, {{"lastSyncDateTime", type datetimezone}, {"lastManualSyncTriggerDateTime", type datetimezone}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsProtectionState = () =>
    let 
        GetData = (deviceId as text, tenantId as text) =>
            let
                accessToken = Helper.GetAccessToken(tenantId),
                data = MicrosoftGraph.GetContent("deviceManagement/managedDevices/" & deviceId & "/windowsProtectionState", accessToken)
            in 
                data,
        
        source = SecMgmtInsights.ManagedDevices(),
        managedDevices = Table.SelectColumns(source, {"customerId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [customerId]) otherwise null),
        expandedCustom = Table.ExpandRecordColumn(data, "Custom", {"malwareProtectionEnabled", "deviceState", "realTimeProtectionEnabled", "networkInspectionSystemEnabled", "quickScanOverdue", "fullScanOverdue", "signatureUpdateOverdue", "rebootRequired", "fullScanRequired", "engineVersion", "signatureVersion", "antiMalwareVersion", "lastQuickScanDateTime", "lastFullScanDateTime", "lastQuickScanSignatureVersion", "lastFullScanSignatureVersion", "lastReportedDateTime"}, {"malwareProtectionEnabled", "deviceState", "realTimeProtectionEnabled", "networkInspectionSystemEnabled", "quickScanOverdue", "fullScanOverdue", "signatureUpdateOverdue", "rebootRequired", "fullScanRequired", "engineVersion", "signatureVersion", "antiMalwareVersion", "lastQuickScanDateTime", "lastFullScanDateTime", "lastQuickScanSignatureVersion", "lastFullScanSignatureVersion", "lastReportedDateTime"}),
        changedType = Table.TransformColumnTypes(expandedCustom ,{{"malwareProtectionEnabled", type logical}, {"realTimeProtectionEnabled", type logical}, {"networkInspectionSystemEnabled", type logical}, {"quickScanOverdue", type logical}, {"fullScanOverdue", type logical}, {"signatureUpdateOverdue", type logical}, {"rebootRequired", type logical}, {"fullScanRequired", type logical}, {"lastQuickScanDateTime", type datetimezone}, {"lastFullScanDateTime", type datetimezone}, {"lastReportedDateTime", type datetimezone}}),
        filteredRows = Table.SelectRows(changedType, each [deviceId] <> null and [deviceId] <> "")
    in 
        filteredRows;

// Helper

Helper.GetAccessToken = (optional tenantId as text) =>
    let 
        authResult = if (tenantId <> null) then 
            TokenMethod("https://login.microsoftonline.com/" & tenantId & "/oauth2/v2.0/token", "refresh_token", "refresh_token", Extension.CurrentCredential()[refresh_token])
        else
            TokenMethod(token_uri, "refresh_token", "refresh_token", Extension.CurrentCredential()[refresh_token])
    in 
        authResult[access_token];

Helper.GetDataForAllCustomers = (relativePath as text) as table =>
    let
        GetData = (tenantId as text) =>
            let
                accessToken = Helper.GetAccessToken(tenantId),
                response = MicrosoftGraph.GetContent(relativePath, accessToken)
            in 
                response,

        source = SecMgmtInsights.Contracts(),
        customers = Table.SelectColumns(source, {"customerId"}),
        data = Table.AddColumn(customers, "Custom", each try GetData([customerId]) otherwise null)
    in 
        data;

Helper.GetPagedDataForAllCustomers = (relativePath as text) as table =>
    let
        GetData = (tenantId as text) =>
            let
                accessToken = Helper.GetAccessToken(tenantId),
                response = MicrosoftGraph.GetPagedContent(relativePath, accessToken)
            in 
                response,

        source = SecMgmtInsights.Contracts(),
        customers = Table.SelectColumns(source, {"customerId"}),
        data = Table.AddColumn(customers, "Custom", each try GetData([customerId]) otherwise null),
        dataTable = Table.ExpandListColumn(data, "Custom"),
        expandedCustom = Table.ExpandListColumn(dataTable, "Custom")
    in 
        expandedCustom;

// Intelligent Security Graph

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Alerts = () =>
    let 
        // TODO - Need to get a customer with test data
        data = Helper.GetPagedDataForAllCustomers("security/alerts")
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScore = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("security/secureScores"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "azureTenantId", "activeUserCount", "createdDateTime", "currentScore", "enabledServices", "licensedUserCount", "maxScore", "vendorInformation", "averageComparativeScores", "controlScores"}, {"id", "azureTenantId", "activeUserCount", "createdDateTime", "currentScore", "enabledServices", "licensedUserCount", "maxScore", "vendorInformation", "averageComparativeScores", "controlScores"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"activeUserCount", Int64.Type}, {"createdDateTime", type datetimezone}, {"currentScore", Int64.Type}, {"licensedUserCount", Int64.Type}, {"maxScore", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScoreControlProfiles = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("security/secureScoreControlProfiles"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "azureTenantId", "actionType", "actionUrl", "controlCategory", "title", "deprecated", "implementationCost", "lastModifiedDateTime", "maxScore", "rank", "remediation", "remediationImpact", "service", "threats", "tier", "userImpact", "vendorInformation", "complianceInformation", "controlStateUpdates"}, {"id", "azureTenantId", "actionType", "actionUrl", "controlCategory", "title", "deprecated", "implementationCost", "lastModifiedDateTime", "maxScore", "rank", "remediation", "remediationImpact", "service", "threats", "tier", "userImpact", "vendorInformation", "complianceInformation", "controlStateUpdates"})
    in
        expandedRecord;

// Microsoft Defender

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedMalwareState = () =>
    let 
        GetData = (deviceId as text, tenantId as text) =>
            let
                accessToken = Helper.GetAccessToken(tenantId),
                data = MicrosoftGraph.GetPagedContent("deviceManagement/managedDevices/" & deviceId & "/windowsProtectionState/detectedMalwareState", accessToken)
            in 
                data,
        
        source = SecMgmtInsights.ManagedDevices(),
        managedDevices = Table.SelectColumns(source, {"customerId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try GetData([deviceId], [customerId]) otherwise null),
        expandedCustom = Table.ExpandListColumn(data, "Custom"),
        expandedList = Table.ExpandListColumn(expandedCustom, "Custom"),
        expandedRecord = Table.ExpandRecordColumn(expandedList, "Custom", {"id", "displayName", "additionalInformationUrl", "severity", "catetgory", "executionState", "state", "threatState", "initialDetectionDateTime", "lastStateChangeDateTime", "detectionCount", "category"}, {"id", "displayName", "additionalInformationUrl", "severity", "catetgory", "executionState", "state", "threatState", "initialDetectionDateTime", "lastStateChangeDateTime", "detectionCount", "category"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"initialDetectionDateTime", type datetimezone}, {"lastStateChangeDateTime", type datetimezone}, {"detectionCount", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsMalwareInformation = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("deviceManagement/windowsMalwareInformation"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"id", "displayName", "additionalInformationUrl", "severity", "category", "lastDetectionDateTime"}, {"id", "displayName", "additionalInformationUrl", "severity", "category", "lastDetectionDateTime"}),
        changedType = Table.TransformColumnTypes(expandedRecord,{{"lastDetectionDateTime", type datetimezone}})
    in
        changedType;

// Network 

MicrosoftGraph.GetContent = (relativePath as text, token as text) =>
    let 
        source = Web.Contents("https://graph.microsoft.com/beta/",
            [
                Headers = [
                    #"Accept" = "application/json",
                    #"Accept-encoding" = "gzip",
                    #"Authorization" = "Bearer " & token 
                ], 
                ManualCredentials = true,
                ManualStatusHandling = {401, 403},
                RelativePath = relativePath
            ]),
        buffered = Binary.Buffer(source),
        status = Value.Metadata(source)[Response.Status],
        result = if status = 401 then Json.Document(buffered)[error][message] else if status = 403 then Json.Document(buffered) else Json.Document(buffered)
    in 
        result;

MicrosoftGraph.GetPagedContent = (relativePath as text, token as text) =>
    let
        GetResources = 
            (relativePath as text) as record =>
            let
                data = MicrosoftGraph.GetContent(relativePath, token),
                items = try data[value] otherwise null,
                next = try data[#"@odata.nextLink"] otherwise null,
                res = [Items = items, Next = next]
            in 
                res,

        GetResourcesContinuation = 
            (nextData) as record =>
            let
                relativePath = nextData[uri],
                data = MicrosoftGraph.GetContent(relativePath, token),
                items = try data[value] otherwise null,
                next = try data[#"@odata.nextLink"] otherwise null,
                res = [Items = items, Next = next]
            in 
                res,

        resourcesList = 
            List.Generate(
                () => [result = GetResources(relativePath)], 
                each [result][Items] <> null, 
                each [result = GetResourcesContinuation([result][Next])],
                each [result][Items])
    in
        resourcesList;

// Office 365

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MailboxUsageDetail = () =>
    let 
        data = Helper.GetPagedDataForAllCustomers("reports/getMailboxUsageDetail(period='D30')?$format=application/json"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"userPrincipalName", "displayName", "isDeleted", "deletedDate", "createdDate", "lastActivityDate", "itemCount", "storageUsedInBytes", "deletedItemCount", "deletedItemSizeInBytes", "issueWarningQuotaInBytes", "prohibitSendQuotaInBytes", "prohibitSendReceiveQuotaInBytes"}, {"userPrincipalName", "displayName", "isDeleted", "deletedDate", "createdDate", "lastActivityDate", "itemCount", "storageUsedInBytes", "deletedItemCount", "deletedItemSizeInBytes", "issueWarningQuotaInBytes", "prohibitSendQuotaInBytes", "prohibitSendReceiveQuotaInBytes"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"isDeleted", type logical}, {"deletedDate", type date}, {"createdDate", type date}, {"lastActivityDate", type date}, {"itemCount", Int64.Type}, {"storageUsedInBytes", Int64.Type}, {"deletedItemCount", Int64.Type}, {"deletedItemSizeInBytes", Int64.Type}, {"issueWarningQuotaInBytes", Int64.Type}, {"prohibitSendQuotaInBytes", Int64.Type}, {"prohibitSendReceiveQuotaInBytes", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ActiveUserDetails = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"userPrincipalName", "displayName", "isDeleted", "deletedDate", "hasExchangeLicense", "hasOneDriveLicense", "hasSharePointLicense", "hasSkypeForBusinessLicense", "hasYammerLicense", "hasTeamsLicense", "exchangeLastActivityDate", "oneDriveLastActivityDate", "sharePointLastActivityDate", "skypeForBusinessLastActivityDate", "yammerLastActivityDate", "teamsLastActivityDate", "exchangeLicenseAssignDate", "oneDriveLicenseAssignDate", "sharePointLicenseAssignDate", "skypeForBusinessLicenseAssignDate", "yammerLicenseAssignDate", "teamsLicenseAssignDate", "assignedProducts"}, {"userPrincipalName", "displayName", "isDeleted", "deletedDate", "hasExchangeLicense", "hasOneDriveLicense", "hasSharePointLicense", "hasSkypeForBusinessLicense", "hasYammerLicense", "hasTeamsLicense", "exchangeLastActivityDate", "oneDriveLastActivityDate", "sharePointLastActivityDate", "skypeForBusinessLastActivityDate", "yammerLastActivityDate", "teamsLastActivityDate", "exchangeLicenseAssignDate", "oneDriveLicenseAssignDate", "sharePointLicenseAssignDate", "skypeForBusinessLicenseAssignDate", "yammerLicenseAssignDate", "teamsLicenseAssignDate", "assignedProducts"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"isDeleted", type logical}, {"deletedDate", type date}, {"hasExchangeLicense", type logical}, {"hasOneDriveLicense", type logical}, {"hasSharePointLicense", type logical}, {"hasSkypeForBusinessLicense", type logical}, {"hasYammerLicense", type logical}, {"hasTeamsLicense", type logical}, {"exchangeLastActivityDate", type date}, {"oneDriveLastActivityDate", type date}, {"sharePointLastActivityDate", type date}, {"skypeForBusinessLastActivityDate", type date}, {"yammerLastActivityDate", type date}, {"teamsLastActivityDate", type date}, {"exchangeLicenseAssignDate", type date}, {"oneDriveLicenseAssignDate", type date}, {"sharePointLicenseAssignDate", type date}, {"skypeForBusinessLicenseAssignDate", type date}, {"yammerLicenseAssignDate", type date}, {"teamsLicenseAssignDate", type date}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ServicesUserCounts = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("reports/getOffice365ServicesUserCounts(period='D30')?$format=application/json"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"exchangeActive", "exchangeInactive", "oneDriveActive", "oneDriveInactive", "sharePointActive", "sharePointInactive", "skypeForBusinessActive", "skypeForBusinessInactive", "yammerActive", "yammerInactive", "teamsActive", "teamsInactive", "office365Active", "office365Inactive"}, {"exchangeActive", "exchangeInactive", "oneDriveActive", "oneDriveInactive", "sharePointActive", "sharePointInactive", "skypeForBusinessActive", "skypeForBusinessInactive", "yammerActive", "yammerInactive", "teamsActive", "teamsInactive", "office365Active", "office365Inactive"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"exchangeActive", Int64.Type}, {"exchangeInactive", Int64.Type}, {"oneDriveActive", Int64.Type}, {"oneDriveInactive", Int64.Type}, {"sharePointActive", Int64.Type}, {"sharePointInactive", Int64.Type}, {"skypeForBusinessActive", Int64.Type}, {"skypeForBusinessInactive", Int64.Type}, {"yammerActive", Int64.Type}, {"yammerInactive", Int64.Type}, {"teamsActive", Int64.Type}, {"teamsInactive", Int64.Type}, {"office365Active", Int64.Type}, {"office365Inactive", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.OneDriveUsageAccountDetail = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("reports/getOneDriveUsageAccountDetail(period='D30')?$format=application/json"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"siteUrl", "ownerDisplayName", "ownerPrincipalName", "isDeleted", "lastActivityDate", "fileCount", "activeFileCount", "storageUsedInBytes", "storageAllocatedInBytes"}, {"siteUrl", "ownerDisplayName", "ownerPrincipalName", "isDeleted", "lastActivityDate", "fileCount", "activeFileCount", "storageUsedInBytes", "storageAllocatedInBytes"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"isDeleted", type logical}, {"lastActivityDate", type date}, {"fileCount", Int64.Type}, {"activeFileCount", Int64.Type}, {"storageUsedInBytes", Int64.Type}, {"storageAllocatedInBytes", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SharePointSiteUsageDetail = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("reports/getSharePointSiteUsageDetail(period='D30')?$format=application/json"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"siteId", "siteUrl", "ownerDisplayName", "ownerPrincipalName", "isDeleted", "lastActivityDate", "fileCount", "activeFileCount", "pageViewCount", "visitedPageCount", "storageUsedInBytes", "storageAllocatedInBytes", "rootWebTemplate"}, {"siteId", "siteUrl", "ownerDisplayName", "ownerPrincipalName", "isDeleted", "lastActivityDate", "fileCount", "activeFileCount", "pageViewCount", "visitedPageCount", "storageUsedInBytes", "storageAllocatedInBytes", "rootWebTemplate"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"isDeleted", type logical}, {"lastActivityDate", type date}, {"fileCount", Int64.Type}, {"activeFileCount", Int64.Type}, {"pageViewCount", Int64.Type}, {"visitedPageCount", Int64.Type}, {"storageUsedInBytes", Int64.Type}, {"storageAllocatedInBytes", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.TeamsUserActivityUserDetail = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("reports/getTeamsUserActivityUserDetail(period='D30')?$format=application/json"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"userPrincipalName", "lastActivityDate", "isDeleted", "deletedDate", "assignedProducts", "teamChatMessageCount", "privateChatMessageCount", "callCount", "meetingCount", "hasOtherAction"}, {"userPrincipalName", "lastActivityDate", "isDeleted", "deletedDate", "assignedProducts", "teamChatMessageCount", "privateChatMessageCount", "callCount", "meetingCount", "hasOtherAction"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"lastActivityDate", type date}, {"isDeleted", type logical}, {"deletedDate", type date}, {"teamChatMessageCount", Int64.Type}, {"privateChatMessageCount", Int64.Type}, {"callCount", Int64.Type}, {"meetingCount", Int64.Type}, {"hasOtherAction", type logical}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.YammerActivityUserDetail = () =>
    let
        data = Helper.GetPagedDataForAllCustomers("reports/getYammerActivityUserDetail(period='D30')?$format=application/json"),
        expandedRecord = Table.ExpandRecordColumn(data, "Custom", {"userPrincipalName", "displayName", "userState", "stateChangeDate", "lastActivityDate", "postedCount", "readCount", "likedCount", "assignedProducts"}, {"userPrincipalName", "displayName", "userState", "stateChangeDate", "lastActivityDate", "postedCount", "readCount", "likedCount", "assignedProducts"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"stateChangeDate", type date}, {"lastActivityDate", type date}, {"postedCount", Int64.Type}, {"readCount", Int64.Type}, {"likedCount", Int64.Type}})
    in 
        changedType;
