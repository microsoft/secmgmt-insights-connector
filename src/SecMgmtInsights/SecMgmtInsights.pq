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
        data = Request.GetPagedData("identity/conditionalAccess/policies", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "displayName", "createdDateTime", "modifiedDateTime", "state", "sessionControls", "conditions", "grantControls"}, {"id", "displayName", "createdDateTime", "modifiedDateTime", "state", "sessionControls", "conditions", "grantControls"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"createdDateTime", type datetimezone}, {"modifiedDateTime", type datetimezone}}),
        expandedConditions = Table.ExpandRecordColumn(changeType, "conditions", {"signInRiskLevels", "clientAppTypes", "platforms", "locations", "deviceStates", "devices", "applications", "users"}, {"conditions.signInRiskLevels", "conditions.clientAppTypes", "conditions.platforms", "conditions.locations", "conditions.deviceStates", "conditions.devices", "conditions.applications", "conditions.users"}),
        expandedGrantControls = Table.ExpandRecordColumn(expandedConditions, "grantControls", {"operator", "builtInControls", "customAuthenticationFactors", "termsOfUse"}, {"grantControls.operator", "grantControls.builtInControls", "grantControls.customAuthenticationFactors", "grantControls.termsOfUse"})
    in 
        expandedGrantControls;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Contracts = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("contracts", tenants),
        removeColumn = Table.RemoveColumns(data, "tenantId"),
        expandRecord = Table.ExpandRecordColumn(removeColumn, "Column1", {"id", "deletedDateTime", "contractType", "customerId", "defaultDomainName", "displayName"}, {"id", "deletedDateTime", "contractType", "tenantId", "defaultDomainName", "displayName"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"deletedDateTime", type datetime}})
    in
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.CredentialUserRegistrationDetails = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("reports/credentialUserRegistrationDetails", tenants),
        expandedCustom = Table.ExpandRecordColumn(data, "Column1", {"id", "userPrincipalName", "userDisplayName", "isRegistered", "isEnabled", "isCapable", "isMfaRegistered", "authMethods"}, {"id", "userPrincipalName", "userDisplayName", "isRegistered", "isEnabled", "isCapable", "isMfaRegistered", "authMethods"}),
        expandedAuthMethods = Table.ExpandListColumn(expandedCustom, "authMethods"),
        changeType = Table.TransformColumnTypes(expandedAuthMethods, {{"isRegistered", type logical}, {"isEnabled", type logical}, {"isCapable", type logical}, {"isMfaRegistered", type logical}})
    in
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Devices = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("devices", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "deletedDateTime", "accountEnabled", "approximateLastSignInDateTime", "complianceExpirationDateTime", "deviceId", "deviceMetadata", "deviceVersion", "displayName", "isCompliant", "isManaged", "Manufacturer", "mdmAppId", "Model", "onPremisesLastSyncDateTime", "onPremisesSyncEnabled", "operatingSystem", "operatingSystemVersion", "physicalIds", "profileType", "systemLabels", "trustType", "alternativeSecurityIds"}, {"id", "deletedDateTime", "accountEnabled", "approximateLastSignInDateTime", "complianceExpirationDateTime", "deviceId", "deviceMetadata", "deviceVersion", "displayName", "isCompliant", "isManaged", "Manufacturer", "mdmAppId", "Model", "onPremisesLastSyncDateTime", "onPremisesSyncEnabled", "operatingSystem", "operatingSystemVersion", "physicalIds", "profileType", "systemLabels", "trustType", "alternativeSecurityIds"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"deletedDateTime", type datetimezone}, {"accountEnabled", type logical}, {"approximateLastSignInDateTime", type datetimezone}, {"complianceExpirationDateTime", type datetimezone}, {"deviceVersion", Int64.Type}, {"isCompliant", type logical}, {"isManaged", type logical}, {"onPremisesLastSyncDateTime", type datetimezone}, {"onPremisesSyncEnabled", type logical}})
    in
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.IdentitySecurityDefaultsEnforcementPolicy = (optional tenants as list) as table =>
    let
       data = Request.GetPagedData("policies/identitySecurityDefaultsEnforcementPolicy", tenants),
       expandedCustom = Table.ExpandRecordColumn(data, "Column1", {"id", "displayName", "description", "isEnabled"}, {"id", "displayName", "description", "isEnabled"}),
       changeType = Table.TransformColumnTypes(expandedCustom, {{"isEnabled", type logical}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.RiskyUsers = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("riskyUsers", tenants),
        expandedCustom = Table.ExpandRecordColumn(data, "Column1", {"id", "riskLastUpdatedDateTime", "isGuest", "isProcessing", "isDeleted", "riskDetail", "riskLevel", "riskState", "userDisplayName", "userPrincipalName"}, {"id", "riskLastUpdatedDateTime", "isGuest", "isProcessing", "isDeleted", "riskDetail", "riskLevel", "riskState", "userDisplayName", "userPrincipalName"}),
        changeType = Table.TransformColumnTypes(expandedCustom, {{"riskLastUpdatedDateTime", type datetimezone}, {"isGuest", type logical}, {"isProcessing", type logical}, {"isDeleted", type logical}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SignIns = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("auditLogs/signIns", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "createdDateTime", "userDisplayName", "userPrincipalName", "userId", "appId", "appDisplayName", "ipAddress", "clientAppUsed", "userAgent", "correlationId", "conditionalAccessStatus", "originalRequestId", "isInteractive", "tokenIssuerName", "tokenIssuerType", "processingTimeInMilliseconds", "riskDetail", "riskLevelAggregated", "riskLevelDuringSignIn", "riskState", "riskEventTypes", "riskEventTypes_v2", "resourceDisplayName", "resourceId", "authenticationMethodsUsed", "authenticationRequirement", "alternateSignInName", "servicePrincipalName", "servicePrincipalId", "mfaDetail", "status", "deviceDetail", "location", "appliedConditionalAccessPolicies", "authenticationProcessingDetails", "networkLocationDetails", "authenticationDetails", "authenticationRequirementPolicies"}, {"id", "createdDateTime", "userDisplayName", "userPrincipalName", "userId", "appId", "appDisplayName", "ipAddress", "clientAppUsed", "userAgent", "correlationId", "conditionalAccessStatus", "originalRequestId", "isInteractive", "tokenIssuerName", "tokenIssuerType", "processingTimeInMilliseconds", "riskDetail", "riskLevelAggregated", "riskLevelDuringSignIn", "riskState", "riskEventTypes", "riskEventTypes_v2", "resourceDisplayName", "resourceId", "authenticationMethodsUsed", "authenticationRequirement", "alternateSignInName", "servicePrincipalName", "servicePrincipalId", "mfaDetail", "status", "deviceDetail", "location", "appliedConditionalAccessPolicies", "authenticationProcessingDetails", "networkLocationDetails", "authenticationDetails", "authenticationRequirementPolicies"}),
        expandedAuthMethodList = Table.ExpandListColumn(expandRecord, "authenticationDetails"),
        expandedAuthMethodRecord = Table.ExpandRecordColumn(expandedAuthMethodList, "authenticationDetails", {"authenticationStepDateTime", "authenticationMethod", "authenticationMethodDetail", "succeeded", "authenticationStepResultDetail", "authenticationStepRequirement"}, {"authenticationStepDateTime", "authenticationMethod", "authenticationMethodDetail", "succeeded", "authenticationStepResultDetail", "authenticationStepRequirement"}),
        changeType = Table.TransformColumnTypes(expandedAuthMethodRecord, {{"createdDateTime", type datetime}, {"isInteractive", type logical}, {"processingTimeInMilliseconds", Int64.Type}, {"authenticationStepDateTime", type datetimezone}, {"succeeded", type logical}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Users = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("users", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "deletedDateTime", "accountEnabled", "ageGroup", "businessPhones", "city", "createdDateTime", "creationType", "companyName", "consentProvidedForMinor", "country", "department", "displayName", "employeeId", "faxNumber", "givenName", "imAddresses", "infoCatalogs", "isResourceAccount", "jobTitle", "legalAgeGroupClassification", "mail", "mailNickname", "mobilePhone", "onPremisesDistinguishedName", "officeLocation", "onPremisesDomainName", "onPremisesImmutableId", "onPremisesLastSyncDateTime", "onPremisesSecurityIdentifier", "onPremisesSamAccountName", "onPremisesSyncEnabled", "onPremisesUserPrincipalName", "otherMails", "passwordPolicies", "passwordProfile", "postalCode", "preferredDataLocation", "preferredLanguage", "proxyAddresses", "refreshTokensValidFromDateTime", "showInAddressList", "signInSessionsValidFromDateTime", "state", "streetAddress", "surname", "usageLocation", "userPrincipalName", "externalUserState", "externalUserStateChangeDateTime", "userType", "assignedLicenses", "assignedPlans", "deviceKeys", "identities", "onPremisesExtensionAttributes", "onPremisesProvisioningErrors", "provisionedPlans"}, {"id", "deletedDateTime", "accountEnabled", "ageGroup", "businessPhones", "city", "createdDateTime", "creationType", "companyName", "consentProvidedForMinor", "country", "department", "displayName", "employeeId", "faxNumber", "givenName", "imAddresses", "infoCatalogs", "isResourceAccount", "jobTitle", "legalAgeGroupClassification", "mail", "mailNickname", "mobilePhone", "onPremisesDistinguishedName", "officeLocation", "onPremisesDomainName", "onPremisesImmutableId", "onPremisesLastSyncDateTime", "onPremisesSecurityIdentifier", "onPremisesSamAccountName", "onPremisesSyncEnabled", "onPremisesUserPrincipalName", "otherMails", "passwordPolicies", "passwordProfile", "postalCode", "preferredDataLocation", "preferredLanguage", "proxyAddresses", "refreshTokensValidFromDateTime", "showInAddressList", "signInSessionsValidFromDateTime", "state", "streetAddress", "surname", "usageLocation", "userPrincipalName", "externalUserState", "externalUserStateChangeDateTime", "userType", "assignedLicenses", "assignedPlans", "deviceKeys", "identities", "onPremisesExtensionAttributes", "onPremisesProvisioningErrors", "provisionedPlans"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"accountEnabled", type logical}, {"createdDateTime", type datetimezone}, {"onPremisesLastSyncDateTime", type datetimezone}, {"onPremisesSyncEnabled", type logical}, {"postalCode", Int64.Type}, {"refreshTokensValidFromDateTime", type datetimezone}, {"signInSessionsValidFromDateTime", type datetimezone}})
    in
        changeType;

// Device Management

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedApps= (optional tenants as list) as table =>
    let 
        source = SecMgmtInsights.ManagedDevices(tenants),
        managedDevices = Table.SelectColumns(source, {"tenantId", "id"}),
        renameColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renameColumn, "Custom", each try Request.GetPagedData("deviceManagement/managedDevices/" & [deviceId]  & "/detectedApps", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "displayName", "version", "sizeInByte", "deviceCount"}, {"id", "displayName", "version", "sizeInByte", "deviceCount"}),
        changedType = Table.TransformColumnTypes(expandRecord, {{"sizeInByte", Int64.Type}, {"deviceCount", Int64.Type}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DetectedMalwareState = (optional tenants as list) as table =>
    let 
        source = SecMgmtInsights.ManagedDevices(tenants),
        managedDevices = Table.SelectColumns(source, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState/detectedMalwareState", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "displayName", "additionalInformationUrl", "severity", "catetgory", "executionState", "state", "threatState", "initialDetectionDateTime", "lastStateChangeDateTime", "detectionCount"}, {"id", "displayName", "additionalInformationUrl", "severity", "catetgory", "executionState", "state", "threatState", "initialDetectionDateTime", "lastStateChangeDateTime", "detectionCount"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"initialDetectionDateTime", type datetimezone}, {"lastStateChangeDateTime", type datetimezone}, {"detectionCount", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicySettingStates = (optional tenants as list) as table => 
    let
        source = SecMgmtInsights.DeviceCompliancePolicyStates(tenants),
        policyStates = Table.SelectColumns(source, {"tenantId", "deviceId", "id"}),
        renamedColumn =  Table.RenameColumns(policyStates, {{"id", "policyId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates/" & [policyId] & "/settingStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}, {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}),
        expandedSources = Table.ExpandListColumn(expandedRecord, "sources"),
        expandedSourcesRecord = Table.ExpandRecordColumn(expandedSources, "sources", {"id", "displayName"}, {"sources.id", "sources.displayName"})
    in 
        expandedSourcesRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicies = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("deviceManagement/deviceCompliancePolicies", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"roleScopeTagIds", "id", "createdDateTime", "description", "lastModifiedDateTime", "displayName", "version", "passwordRequired", "passwordMinimumLength", "passwordRequiredType", "passwordMinutesOfInactivityBeforeLock", "passwordExpirationDays", "passwordPreviousPasswordBlockCount", "passwordSignInFailureCountBeforeFactoryReset", "securityPreventInstallAppsFromUnknownSources", "securityDisableUsbDebugging", "securityRequireVerifyApps", "deviceThreatProtectionEnabled", "deviceThreatProtectionRequiredSecurityLevel", "advancedThreatProtectionRequiredSecurityLevel", "securityBlockJailbrokenDevices", "securityBlockDeviceAdministratorManagedDevices", "osMinimumVersion", "osMaximumVersion", "minAndroidSecurityPatchLevel", "storageRequireEncryption", "securityRequireSafetyNetAttestationBasicIntegrity", "securityRequireSafetyNetAttestationCertifiedDevice", "securityRequireGooglePlayServices", "securityRequireUpToDateSecurityProviders", "securityRequireCompanyPortalAppIntegrity", "conditionStatementId", "restrictedApps", "passwordBlockSimple", "passwordRequiredToUnlockFromIdle", "passwordMinimumCharacterSetCount", "requireHealthyDeviceReport", "mobileOsMinimumVersion", "mobileOsMaximumVersion", "earlyLaunchAntiMalwareDriverEnabled", "bitLockerEnabled", "secureBootEnabled", "codeIntegrityEnabled", "activeFirewallRequired", "defenderEnabled", "defenderVersion", "signatureOutOfDate", "rtpEnabled", "antivirusRequired", "antiSpywareRequired", "configurationManagerComplianceRequired", "tpmRequired", "validOperatingSystemBuildRanges"}, {"roleScopeTagIds", "id", "createdDateTime", "description", "lastModifiedDateTime", "displayName", "version", "passwordRequired", "passwordMinimumLength", "passwordRequiredType", "passwordMinutesOfInactivityBeforeLock", "passwordExpirationDays", "passwordPreviousPasswordBlockCount", "passwordSignInFailureCountBeforeFactoryReset", "securityPreventInstallAppsFromUnknownSources", "securityDisableUsbDebugging", "securityRequireVerifyApps", "deviceThreatProtectionEnabled", "deviceThreatProtectionRequiredSecurityLevel", "advancedThreatProtectionRequiredSecurityLevel", "securityBlockJailbrokenDevices", "securityBlockDeviceAdministratorManagedDevices", "osMinimumVersion", "osMaximumVersion", "minAndroidSecurityPatchLevel", "storageRequireEncryption", "securityRequireSafetyNetAttestationBasicIntegrity", "securityRequireSafetyNetAttestationCertifiedDevice", "securityRequireGooglePlayServices", "securityRequireUpToDateSecurityProviders", "securityRequireCompanyPortalAppIntegrity", "conditionStatementId", "restrictedApps", "passwordBlockSimple", "passwordRequiredToUnlockFromIdle", "passwordMinimumCharacterSetCount", "requireHealthyDeviceReport", "mobileOsMinimumVersion", "mobileOsMaximumVersion", "earlyLaunchAntiMalwareDriverEnabled", "bitLockerEnabled", "secureBootEnabled", "codeIntegrityEnabled", "activeFirewallRequired", "defenderEnabled", "defenderVersion", "signatureOutOfDate", "rtpEnabled", "antivirusRequired", "antiSpywareRequired", "configurationManagerComplianceRequired", "tpmRequired", "validOperatingSystemBuildRanges"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"createdDateTime", type datetimezone}, {"lastModifiedDateTime", type datetimezone}, {"version", Int64.Type}, {"passwordRequired", type logical}, {"securityDisableUsbDebugging", type logical}, {"securityPreventInstallAppsFromUnknownSources", type logical}, {"securityRequireVerifyApps", type logical}, {"deviceThreatProtectionEnabled", type logical}, {"securityBlockJailbrokenDevices", type logical}, {"securityBlockDeviceAdministratorManagedDevices", type logical}, {"storageRequireEncryption", type logical}, {"securityRequireSafetyNetAttestationBasicIntegrity", type logical}, {"securityRequireSafetyNetAttestationCertifiedDevice", type logical}, {"securityRequireGooglePlayServices", type logical}, {"securityRequireUpToDateSecurityProviders", type logical}, {"securityRequireCompanyPortalAppIntegrity", type logical}, {"passwordBlockSimple", type logical}, {"passwordRequiredToUnlockFromIdle", type logical}, {"requireHealthyDeviceReport", type logical}, {"earlyLaunchAntiMalwareDriverEnabled", type logical}, {"bitLockerEnabled", type logical}, {"secureBootEnabled", type logical}, {"codeIntegrityEnabled", type logical}, {"activeFirewallRequired", type logical}, {"defenderEnabled", type logical}, {"signatureOutOfDate", type logical}, {"rtpEnabled", type logical}, {"antivirusRequired", type logical}, {"antiSpywareRequired", type logical}, {"configurationManagerComplianceRequired", type logical}, {"tpmRequired", type logical}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceCompliancePolicyStates = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.ManagedDevices(tenants),
        managedDevices = Table.SelectColumns(source, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceManagement/managedDevices/" & [deviceId] & "/deviceCompliancePolicyStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "displayName", "version", "platformType", "state", "settingCount", "userId", "userPrincipalName", "settingStates"}, {"id", "displayName", "version", "platformType", "state", "settingCount", "userId", "userPrincipalName", "settingStates"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicies = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("deviceManagement/deviceConfigurations", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "lastModifiedDateTime", "roleScopeTagIds", "supportsScopeTags", "deviceManagementApplicabilityRuleOsEdition", "deviceManagementApplicabilityRuleOsVersion", "deviceManagementApplicabilityRuleDeviceMode", "createdDateTime", "description", "displayName", "version", "dmaGuardDeviceEnumerationPolicy", "userRightsAccessCredentialManagerAsTrustedCaller", "userRightsAllowAccessFromNetwork", "userRightsBlockAccessFromNetwork", "userRightsActAsPartOfTheOperatingSystem", "userRightsLocalLogOn", "userRightsDenyLocalLogOn", "userRightsBackupData", "userRightsChangeSystemTime", "userRightsCreateGlobalObjects", "userRightsCreatePageFile", "userRightsCreatePermanentSharedObjects", "userRightsCreateSymbolicLinks", "userRightsCreateToken", "userRightsDebugPrograms", "userRightsRemoteDesktopServicesLogOn", "userRightsDelegation", "userRightsGenerateSecurityAudits", "userRightsImpersonateClient", "userRightsIncreaseSchedulingPriority", "userRightsLoadUnloadDrivers", "userRightsLockMemory", "userRightsManageAuditingAndSecurityLogs", "userRightsManageVolumes", "userRightsModifyFirmwareEnvironment", "userRightsModifyObjectLabels", "userRightsProfileSingleProcess", "userRightsRemoteShutdown", "userRightsRestoreData", "userRightsTakeOwnership", "xboxServicesEnableXboxGameSaveTask", "xboxServicesAccessoryManagementServiceStartupMode", "xboxServicesLiveAuthManagerServiceStartupMode", "xboxServicesLiveGameSaveServiceStartupMode", "xboxServicesLiveNetworkingServiceStartupMode", "localSecurityOptionsBlockMicrosoftAccounts", "localSecurityOptionsBlockRemoteLogonWithBlankPassword", "localSecurityOptionsDisableAdministratorAccount", "localSecurityOptionsAdministratorAccountName", "localSecurityOptionsDisableGuestAccount", "localSecurityOptionsGuestAccountName", "localSecurityOptionsAllowUndockWithoutHavingToLogon", "localSecurityOptionsBlockUsersInstallingPrinterDrivers", "localSecurityOptionsBlockRemoteOpticalDriveAccess", "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser", "localSecurityOptionsMachineInactivityLimit", "localSecurityOptionsMachineInactivityLimitInMinutes", "localSecurityOptionsDoNotRequireCtrlAltDel", "localSecurityOptionsHideLastSignedInUser", "localSecurityOptionsHideUsernameAtSignIn", "localSecurityOptionsLogOnMessageTitle", "localSecurityOptionsLogOnMessageText", "localSecurityOptionsAllowPKU2UAuthenticationRequests", "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool", "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager", "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients", "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers", "lanManagerAuthenticationLevel", "lanManagerWorkstationDisableInsecureGuestLogons", "localSecurityOptionsClearVirtualMemoryPageFile", "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn", "localSecurityOptionsAllowUIAccessApplicationElevation", "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations", "localSecurityOptionsOnlyElevateSignedExecutables", "localSecurityOptionsAdministratorElevationPromptBehavior", "localSecurityOptionsStandardUserElevationPromptBehavior", "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation", "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation", "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations", "localSecurityOptionsUseAdminApprovalMode", "localSecurityOptionsUseAdminApprovalModeForAdministrators", "localSecurityOptionsInformationShownOnLockScreen", "localSecurityOptionsInformationDisplayedOnLockScreen", "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees", "localSecurityOptionsClientDigitallySignCommunicationsAlways", "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers", "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways", "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees", "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares", "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts", "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares", "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange", "localSecurityOptionsSmartCardRemovalBehavior", "defenderSecurityCenterDisableAppBrowserUI", "defenderSecurityCenterDisableFamilyUI", "defenderSecurityCenterDisableHealthUI", "defenderSecurityCenterDisableNetworkUI", "defenderSecurityCenterDisableVirusUI", "defenderSecurityCenterDisableAccountUI", "defenderSecurityCenterDisableClearTpmUI", "defenderSecurityCenterDisableHardwareUI", "defenderSecurityCenterDisableNotificationAreaUI", "defenderSecurityCenterDisableRansomwareUI", "defenderSecurityCenterDisableSecureBootUI", "defenderSecurityCenterDisableTroubleshootingUI", "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI", "defenderSecurityCenterOrganizationDisplayName", "defenderSecurityCenterHelpEmail", "defenderSecurityCenterHelpPhone", "defenderSecurityCenterHelpURL", "defenderSecurityCenterNotificationsFromApp", "defenderSecurityCenterITContactDisplay", "windowsDefenderTamperProtection", "firewallBlockStatefulFTP", "firewallIdleTimeoutForSecurityAssociationInSeconds", "firewallPreSharedKeyEncodingMethod", "firewallIPSecExemptionsAllowNeighborDiscovery", "firewallIPSecExemptionsAllowICMP", "firewallIPSecExemptionsAllowRouterDiscovery", "firewallIPSecExemptionsAllowDHCP", "firewallCertificateRevocationListCheckMethod", "firewallMergeKeyingModuleSettings", "firewallPacketQueueingMethod", "firewallProfileDomain", "firewallProfilePublic", "firewallProfilePrivate", "defenderAdobeReaderLaunchChildProcess", "defenderAttackSurfaceReductionExcludedPaths", "defenderOfficeAppsOtherProcessInjectionType", "defenderOfficeAppsOtherProcessInjection", "defenderOfficeCommunicationAppsLaunchChildProcess", "defenderOfficeAppsExecutableContentCreationOrLaunchType", "defenderOfficeAppsExecutableContentCreationOrLaunch", "defenderOfficeAppsLaunchChildProcessType", "defenderOfficeAppsLaunchChildProcess", "defenderOfficeMacroCodeAllowWin32ImportsType", "defenderOfficeMacroCodeAllowWin32Imports", "defenderScriptObfuscatedMacroCodeType", "defenderScriptObfuscatedMacroCode", "defenderScriptDownloadedPayloadExecutionType", "defenderScriptDownloadedPayloadExecution", "defenderPreventCredentialStealingType", "defenderProcessCreationType", "defenderProcessCreation", "defenderUntrustedUSBProcessType", "defenderUntrustedUSBProcess", "defenderUntrustedExecutableType", "defenderUntrustedExecutable", "defenderEmailContentExecutionType", "defenderEmailContentExecution", "defenderAdvancedRansomewareProtectionType", "defenderGuardMyFoldersType", "defenderGuardedFoldersAllowedAppPaths", "defenderAdditionalGuardedFolders", "defenderNetworkProtectionType", "defenderExploitProtectionXml", "defenderExploitProtectionXmlFileName", "defenderSecurityCenterBlockExploitProtectionOverride", "appLockerApplicationControl", "deviceGuardLocalSystemAuthorityCredentialGuardSettings", "deviceGuardEnableVirtualizationBasedSecurity", "deviceGuardEnableSecureBootWithDMA", "deviceGuardSecureBootWithDMA", "deviceGuardLaunchSystemGuard", "smartScreenEnableInShell", "smartScreenBlockOverrideForFiles", "applicationGuardEnabled", "applicationGuardEnabledOptions", "applicationGuardBlockFileTransfer", "applicationGuardBlockNonEnterpriseContent", "applicationGuardAllowPersistence", "applicationGuardForceAuditing", "applicationGuardBlockClipboardSharing", "applicationGuardAllowPrintToPDF", "applicationGuardAllowPrintToXPS", "applicationGuardAllowPrintToLocalPrinters", "applicationGuardAllowPrintToNetworkPrinters", "applicationGuardAllowVirtualGPU", "applicationGuardAllowFileSaveOnHost", "bitLockerAllowStandardUserEncryption", "bitLockerDisableWarningForOtherDiskEncryption", "bitLockerEnableStorageCardEncryptionOnMobile", "bitLockerEncryptDevice", "bitLockerSystemDrivePolicy", "bitLockerFixedDrivePolicy", "bitLockerRemovableDrivePolicy", "bitLockerRecoveryPasswordRotation", "defenderDisableScanArchiveFiles", "defenderAllowScanArchiveFiles", "defenderDisableBehaviorMonitoring", "defenderAllowBehaviorMonitoring", "defenderDisableCloudProtection", "defenderAllowCloudProtection", "defenderEnableScanIncomingMail", "defenderEnableScanMappedNetworkDrivesDuringFullScan", "defenderDisableScanRemovableDrivesDuringFullScan", "defenderAllowScanRemovableDrivesDuringFullScan", "defenderDisableScanDownloads", "defenderAllowScanDownloads", "defenderDisableIntrusionPreventionSystem", "defenderAllowIntrusionPreventionSystem", "defenderDisableOnAccessProtection", "defenderAllowOnAccessProtection", "defenderDisableRealTimeMonitoring", "defenderAllowRealTimeMonitoring", "defenderDisableScanNetworkFiles", "defenderAllowScanNetworkFiles", "defenderDisableScanScriptsLoadedInInternetExplorer", "defenderAllowScanScriptsLoadedInInternetExplorer", "defenderBlockEndUserAccess", "defenderAllowEndUserAccess", "defenderScanMaxCpuPercentage", "defenderCheckForSignaturesBeforeRunningScan", "defenderCloudBlockLevel", "defenderCloudExtendedTimeoutInSeconds", "defenderDaysBeforeDeletingQuarantinedMalware", "defenderDisableCatchupFullScan", "defenderDisableCatchupQuickScan", "defenderEnableLowCpuPriority", "defenderFileExtensionsToExclude", "defenderFilesAndFoldersToExclude", "defenderProcessesToExclude", "defenderPotentiallyUnwantedAppAction", "defenderScanDirection", "defenderScanType", "defenderScheduledQuickScanTime", "defenderScheduledScanDay", "defenderScheduledScanTime", "defenderSignatureUpdateIntervalInHours", "defenderSubmitSamplesConsentType", "defenderDetectedMalwareActions", "firewallRules", "taskManagerBlockEndTask", "energySaverOnBatteryThresholdPercentage", "energySaverPluggedInThresholdPercentage", "powerLidCloseActionOnBattery", "powerLidCloseActionPluggedIn", "powerButtonActionOnBattery", "powerButtonActionPluggedIn", "powerSleepButtonActionOnBattery", "powerSleepButtonActionPluggedIn", "powerHybridSleepOnBattery", "powerHybridSleepPluggedIn", "windows10AppsForceUpdateSchedule", "enableAutomaticRedeployment", "microsoftAccountSignInAssistantSettings", "authenticationAllowSecondaryDevice", "authenticationWebSignIn", "authenticationPreferredAzureADTenantDomainName", "cryptographyAllowFipsAlgorithmPolicy", "displayAppListWithGdiDPIScalingTurnedOn", "displayAppListWithGdiDPIScalingTurnedOff", "enterpriseCloudPrintDiscoveryEndPoint", "enterpriseCloudPrintOAuthAuthority", "enterpriseCloudPrintOAuthClientIdentifier", "enterpriseCloudPrintResourceIdentifier", "enterpriseCloudPrintDiscoveryMaxLimit", "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier", "experienceDoNotSyncBrowserSettings", "messagingBlockSync", "messagingBlockMMS", "messagingBlockRichCommunicationServices", "printerNames", "printerDefaultName", "printerBlockAddition", "searchBlockDiacritics", "searchDisableAutoLanguageDetection", "searchDisableIndexingEncryptedItems", "searchEnableRemoteQueries", "searchDisableUseLocation", "searchDisableLocation", "searchDisableIndexerBackoff", "searchDisableIndexingRemovableDrive", "searchEnableAutomaticIndexSizeManangement", "searchBlockWebResults", "findMyFiles", "securityBlockAzureADJoinedDevicesAutoEncryption", "diagnosticsDataSubmissionMode", "oneDriveDisableFileSync", "systemTelemetryProxyServer", "edgeTelemetryForMicrosoft365Analytics", "inkWorkspaceAccess", "inkWorkspaceAccessState", "inkWorkspaceBlockSuggestedApps", "smartScreenEnableAppInstallControl", "smartScreenAppInstallControl", "personalizationDesktopImageUrl", "personalizationLockScreenImageUrl", "bluetoothAllowedServices", "bluetoothBlockAdvertising", "bluetoothBlockPromptedProximalConnections", "bluetoothBlockDiscoverableMode", "bluetoothBlockPrePairing", "edgeBlockAutofill", "edgeBlocked", "edgeCookiePolicy", "edgeBlockDeveloperTools", "edgeBlockSendingDoNotTrackHeader", "edgeBlockExtensions", "edgeBlockInPrivateBrowsing", "edgeBlockJavaScript", "edgeBlockPasswordManager", "edgeBlockAddressBarDropdown", "edgeBlockCompatibilityList", "edgeClearBrowsingDataOnExit", "edgeAllowStartPagesModification", "edgeDisableFirstRunPage", "edgeBlockLiveTileDataCollection", "edgeSyncFavoritesWithInternetExplorer", "edgeFavoritesListLocation", "edgeBlockEditFavorites", "edgeNewTabPageURL", "edgeHomeButtonConfiguration", "edgeHomeButtonConfigurationEnabled", "edgeOpensWith", "edgeBlockSideloadingExtensions", "edgeRequiredExtensionPackageFamilyNames", "edgeBlockPrinting", "edgeFavoritesBarVisibility", "edgeBlockSavingHistory", "edgeBlockFullScreenMode", "edgeBlockWebContentOnNewTabPage", "edgeBlockTabPreloading", "edgeBlockPrelaunch", "edgeShowMessageWhenOpeningInternetExplorerSites", "edgePreventCertificateErrorOverride", "edgeKioskModeRestriction", "edgeKioskResetAfterIdleTimeInMinutes", "cellularBlockDataWhenRoaming", "cellularBlockVpn", "cellularBlockVpnWhenRoaming", "cellularData", "defenderRequireRealTimeMonitoring", "defenderRequireBehaviorMonitoring", "defenderRequireNetworkInspectionSystem", "defenderScanDownloads", "defenderScheduleScanEnableLowCpuPriority", "defenderScanScriptsLoadedInInternetExplorer", "defenderMonitorFileActivity", "defenderScanMaxCpu", "defenderScanArchiveFiles", "defenderScanIncomingMail", "defenderScanRemovableDrivesDuringFullScan", "defenderScanMappedNetworkDrivesDuringFullScan", "defenderScanNetworkFiles", "defenderRequireCloudProtection", "defenderCloudExtendedTimeout", "defenderPromptForSampleSubmission", "defenderSystemScanSchedule", "defenderPotentiallyUnwantedAppActionSetting", "defenderBlockOnAccessProtection", "lockScreenAllowTimeoutConfiguration", "lockScreenBlockActionCenterNotifications", "lockScreenBlockCortana", "lockScreenBlockToastNotifications", "lockScreenTimeoutInSeconds", "lockScreenActivateAppsWithVoice", "passwordBlockSimple", "passwordExpirationDays", "passwordMinimumLength", "passwordMinutesOfInactivityBeforeScreenTimeout", "passwordMinimumCharacterSetCount", "passwordPreviousPasswordBlockCount", "passwordRequired", "passwordRequireWhenResumeFromIdleState", "passwordRequiredType", "passwordSignInFailureCountBeforeFactoryReset", "passwordMinimumAgeInDays", "privacyAdvertisingId", "privacyAutoAcceptPairingAndConsentPrompts", "privacyDisableLaunchExperience", "privacyBlockInputPersonalization", "privacyBlockPublishUserActivities", "privacyBlockActivityFeed", "activateAppsWithVoice", "startBlockUnpinningAppsFromTaskbar", "startMenuAppListVisibility", "startMenuHideChangeAccountSettings", "startMenuHideFrequentlyUsedApps", "startMenuHideHibernate", "startMenuHideLock", "startMenuHidePowerButton", "startMenuHideRecentJumpLists", "startMenuHideRecentlyAddedApps", "startMenuHideRestartOptions", "startMenuHideShutDown", "startMenuHideSignOut", "startMenuHideSleep", "startMenuHideSwitchAccount", "startMenuHideUserTile", "startMenuLayoutEdgeAssetsXml", "startMenuLayoutXml", "startMenuMode", "startMenuPinnedFolderDocuments", "startMenuPinnedFolderDownloads", "startMenuPinnedFolderFileExplorer", "startMenuPinnedFolderHomeGroup", "startMenuPinnedFolderMusic", "startMenuPinnedFolderNetwork", "startMenuPinnedFolderPersonalFolder", "startMenuPinnedFolderPictures", "startMenuPinnedFolderSettings", "startMenuPinnedFolderVideos", "settingsBlockSettingsApp", "settingsBlockSystemPage", "settingsBlockDevicesPage", "settingsBlockNetworkInternetPage", "settingsBlockPersonalizationPage", "settingsBlockAccountsPage", "settingsBlockTimeLanguagePage", "settingsBlockEaseOfAccessPage", "settingsBlockPrivacyPage", "settingsBlockUpdateSecurityPage", "settingsBlockAppsPage", "settingsBlockGamingPage", "windowsSpotlightBlockConsumerSpecificFeatures", "windowsSpotlightBlocked", "windowsSpotlightBlockOnActionCenter", "windowsSpotlightBlockTailoredExperiences", "windowsSpotlightBlockThirdPartyNotifications", "windowsSpotlightBlockWelcomeExperience", "windowsSpotlightBlockWindowsTips", "windowsSpotlightConfigureOnLockScreen", "networkProxyApplySettingsDeviceWide", "networkProxyDisableAutoDetect", "networkProxyAutomaticConfigurationUrl", "networkProxyServer", "accountsBlockAddingNonMicrosoftAccountEmail", "antiTheftModeBlocked", "bluetoothBlocked", "cameraBlocked", "connectedDevicesServiceBlocked", "certificatesBlockManualRootCertificateInstallation", "copyPasteBlocked", "cortanaBlocked", "deviceManagementBlockFactoryResetOnMobile", "deviceManagementBlockManualUnenroll", "safeSearchFilter", "edgeBlockPopups", "edgeBlockSearchSuggestions", "edgeBlockSearchEngineCustomization", "edgeBlockSendingIntranetTrafficToInternetExplorer", "edgeSendIntranetTrafficToInternetExplorer", "edgeRequireSmartScreen", "edgeEnterpriseModeSiteListLocation", "edgeFirstRunUrl", "edgeSearchEngine", "edgeHomepageUrls", "edgeBlockAccessToAboutFlags", "smartScreenBlockPromptOverride", "smartScreenBlockPromptOverrideForFiles", "webRtcBlockLocalhostIpAddress", "internetSharingBlocked", "settingsBlockAddProvisioningPackage", "settingsBlockRemoveProvisioningPackage", "settingsBlockChangeSystemTime", "settingsBlockEditDeviceName", "settingsBlockChangeRegion", "settingsBlockChangeLanguage", "settingsBlockChangePowerSleep", "locationServicesBlocked", "microsoftAccountBlocked", "microsoftAccountBlockSettingsSync", "nfcBlocked", "resetProtectionModeBlocked", "screenCaptureBlocked", "storageBlockRemovableStorage", "storageRequireMobileDeviceEncryption", "usbBlocked", "voiceRecordingBlocked", "wiFiBlockAutomaticConnectHotspots", "wiFiBlocked", "wiFiBlockManualConfiguration", "wiFiScanInterval", "wirelessDisplayBlockProjectionToThisDevice", "wirelessDisplayBlockUserInputFromReceiver", "wirelessDisplayRequirePinForPairing", "windowsStoreBlocked", "appsAllowTrustedAppsSideloading", "windowsStoreBlockAutoUpdate", "developerUnlockSetting", "sharedUserAppDataAllowed", "appsBlockWindowsStoreOriginatedApps", "windowsStoreEnablePrivateStoreOnly", "storageRestrictAppDataToSystemVolume", "storageRestrictAppInstallToSystemVolume", "gameDvrBlocked", "experienceBlockDeviceDiscovery", "experienceBlockErrorDialogWhenNoSIM", "experienceBlockTaskSwitcher", "logonBlockFastUserSwitching", "tenantLockdownRequireNetworkDuringOutOfBoxExperience", "appManagementMSIAllowUserControlOverInstall", "appManagementMSIAlwaysInstallWithElevatedPrivileges", "dataProtectionBlockDirectMemoryAccess", "appManagementPackageFamilyNamesToLaunchAfterLogOn", "uninstallBuiltInApps", "configureTimeZone", "deliveryOptimizationMode", "prereleaseFeatures", "automaticUpdateMode", "microsoftUpdateServiceAllowed", "driversExcluded", "installationSchedule", "qualityUpdatesDeferralPeriodInDays", "featureUpdatesDeferralPeriodInDays", "qualityUpdatesPaused", "featureUpdatesPaused", "qualityUpdatesPauseExpiryDateTime", "featureUpdatesPauseExpiryDateTime", "businessReadyUpdatesOnly", "skipChecksBeforeRestart", "updateWeeks", "qualityUpdatesPauseStartDate", "featureUpdatesPauseStartDate", "featureUpdatesRollbackWindowInDays", "qualityUpdatesWillBeRolledBack", "featureUpdatesWillBeRolledBack", "qualityUpdatesRollbackStartDateTime", "featureUpdatesRollbackStartDateTime", "engagedRestartDeadlineInDays", "engagedRestartSnoozeScheduleInDays", "engagedRestartTransitionScheduleInDays", "deadlineForFeatureUpdatesInDays", "deadlineForQualityUpdatesInDays", "deadlineGracePeriodInDays", "postponeRebootUntilAfterDeadline", "autoRestartNotificationDismissal", "scheduleRestartWarningInHours", "scheduleImminentRestartWarningInMinutes", "userPauseAccess", "userWindowsUpdateScanAccess", "updateNotificationLevel"}, {"id", "lastModifiedDateTime", "roleScopeTagIds", "supportsScopeTags", "deviceManagementApplicabilityRuleOsEdition", "deviceManagementApplicabilityRuleOsVersion", "deviceManagementApplicabilityRuleDeviceMode", "createdDateTime", "description", "displayName", "version", "dmaGuardDeviceEnumerationPolicy", "userRightsAccessCredentialManagerAsTrustedCaller", "userRightsAllowAccessFromNetwork", "userRightsBlockAccessFromNetwork", "userRightsActAsPartOfTheOperatingSystem", "userRightsLocalLogOn", "userRightsDenyLocalLogOn", "userRightsBackupData", "userRightsChangeSystemTime", "userRightsCreateGlobalObjects", "userRightsCreatePageFile", "userRightsCreatePermanentSharedObjects", "userRightsCreateSymbolicLinks", "userRightsCreateToken", "userRightsDebugPrograms", "userRightsRemoteDesktopServicesLogOn", "userRightsDelegation", "userRightsGenerateSecurityAudits", "userRightsImpersonateClient", "userRightsIncreaseSchedulingPriority", "userRightsLoadUnloadDrivers", "userRightsLockMemory", "userRightsManageAuditingAndSecurityLogs", "userRightsManageVolumes", "userRightsModifyFirmwareEnvironment", "userRightsModifyObjectLabels", "userRightsProfileSingleProcess", "userRightsRemoteShutdown", "userRightsRestoreData", "userRightsTakeOwnership", "xboxServicesEnableXboxGameSaveTask", "xboxServicesAccessoryManagementServiceStartupMode", "xboxServicesLiveAuthManagerServiceStartupMode", "xboxServicesLiveGameSaveServiceStartupMode", "xboxServicesLiveNetworkingServiceStartupMode", "localSecurityOptionsBlockMicrosoftAccounts", "localSecurityOptionsBlockRemoteLogonWithBlankPassword", "localSecurityOptionsDisableAdministratorAccount", "localSecurityOptionsAdministratorAccountName", "localSecurityOptionsDisableGuestAccount", "localSecurityOptionsGuestAccountName", "localSecurityOptionsAllowUndockWithoutHavingToLogon", "localSecurityOptionsBlockUsersInstallingPrinterDrivers", "localSecurityOptionsBlockRemoteOpticalDriveAccess", "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser", "localSecurityOptionsMachineInactivityLimit", "localSecurityOptionsMachineInactivityLimitInMinutes", "localSecurityOptionsDoNotRequireCtrlAltDel", "localSecurityOptionsHideLastSignedInUser", "localSecurityOptionsHideUsernameAtSignIn", "localSecurityOptionsLogOnMessageTitle", "localSecurityOptionsLogOnMessageText", "localSecurityOptionsAllowPKU2UAuthenticationRequests", "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool", "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager", "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients", "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers", "lanManagerAuthenticationLevel", "lanManagerWorkstationDisableInsecureGuestLogons", "localSecurityOptionsClearVirtualMemoryPageFile", "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn", "localSecurityOptionsAllowUIAccessApplicationElevation", "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations", "localSecurityOptionsOnlyElevateSignedExecutables", "localSecurityOptionsAdministratorElevationPromptBehavior", "localSecurityOptionsStandardUserElevationPromptBehavior", "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation", "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation", "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations", "localSecurityOptionsUseAdminApprovalMode", "localSecurityOptionsUseAdminApprovalModeForAdministrators", "localSecurityOptionsInformationShownOnLockScreen", "localSecurityOptionsInformationDisplayedOnLockScreen", "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees", "localSecurityOptionsClientDigitallySignCommunicationsAlways", "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers", "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways", "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees", "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares", "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts", "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares", "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange", "localSecurityOptionsSmartCardRemovalBehavior", "defenderSecurityCenterDisableAppBrowserUI", "defenderSecurityCenterDisableFamilyUI", "defenderSecurityCenterDisableHealthUI", "defenderSecurityCenterDisableNetworkUI", "defenderSecurityCenterDisableVirusUI", "defenderSecurityCenterDisableAccountUI", "defenderSecurityCenterDisableClearTpmUI", "defenderSecurityCenterDisableHardwareUI", "defenderSecurityCenterDisableNotificationAreaUI", "defenderSecurityCenterDisableRansomwareUI", "defenderSecurityCenterDisableSecureBootUI", "defenderSecurityCenterDisableTroubleshootingUI", "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI", "defenderSecurityCenterOrganizationDisplayName", "defenderSecurityCenterHelpEmail", "defenderSecurityCenterHelpPhone", "defenderSecurityCenterHelpURL", "defenderSecurityCenterNotificationsFromApp", "defenderSecurityCenterITContactDisplay", "windowsDefenderTamperProtection", "firewallBlockStatefulFTP", "firewallIdleTimeoutForSecurityAssociationInSeconds", "firewallPreSharedKeyEncodingMethod", "firewallIPSecExemptionsAllowNeighborDiscovery", "firewallIPSecExemptionsAllowICMP", "firewallIPSecExemptionsAllowRouterDiscovery", "firewallIPSecExemptionsAllowDHCP", "firewallCertificateRevocationListCheckMethod", "firewallMergeKeyingModuleSettings", "firewallPacketQueueingMethod", "firewallProfileDomain", "firewallProfilePublic", "firewallProfilePrivate", "defenderAdobeReaderLaunchChildProcess", "defenderAttackSurfaceReductionExcludedPaths", "defenderOfficeAppsOtherProcessInjectionType", "defenderOfficeAppsOtherProcessInjection", "defenderOfficeCommunicationAppsLaunchChildProcess", "defenderOfficeAppsExecutableContentCreationOrLaunchType", "defenderOfficeAppsExecutableContentCreationOrLaunch", "defenderOfficeAppsLaunchChildProcessType", "defenderOfficeAppsLaunchChildProcess", "defenderOfficeMacroCodeAllowWin32ImportsType", "defenderOfficeMacroCodeAllowWin32Imports", "defenderScriptObfuscatedMacroCodeType", "defenderScriptObfuscatedMacroCode", "defenderScriptDownloadedPayloadExecutionType", "defenderScriptDownloadedPayloadExecution", "defenderPreventCredentialStealingType", "defenderProcessCreationType", "defenderProcessCreation", "defenderUntrustedUSBProcessType", "defenderUntrustedUSBProcess", "defenderUntrustedExecutableType", "defenderUntrustedExecutable", "defenderEmailContentExecutionType", "defenderEmailContentExecution", "defenderAdvancedRansomewareProtectionType", "defenderGuardMyFoldersType", "defenderGuardedFoldersAllowedAppPaths", "defenderAdditionalGuardedFolders", "defenderNetworkProtectionType", "defenderExploitProtectionXml", "defenderExploitProtectionXmlFileName", "defenderSecurityCenterBlockExploitProtectionOverride", "appLockerApplicationControl", "deviceGuardLocalSystemAuthorityCredentialGuardSettings", "deviceGuardEnableVirtualizationBasedSecurity", "deviceGuardEnableSecureBootWithDMA", "deviceGuardSecureBootWithDMA", "deviceGuardLaunchSystemGuard", "smartScreenEnableInShell", "smartScreenBlockOverrideForFiles", "applicationGuardEnabled", "applicationGuardEnabledOptions", "applicationGuardBlockFileTransfer", "applicationGuardBlockNonEnterpriseContent", "applicationGuardAllowPersistence", "applicationGuardForceAuditing", "applicationGuardBlockClipboardSharing", "applicationGuardAllowPrintToPDF", "applicationGuardAllowPrintToXPS", "applicationGuardAllowPrintToLocalPrinters", "applicationGuardAllowPrintToNetworkPrinters", "applicationGuardAllowVirtualGPU", "applicationGuardAllowFileSaveOnHost", "bitLockerAllowStandardUserEncryption", "bitLockerDisableWarningForOtherDiskEncryption", "bitLockerEnableStorageCardEncryptionOnMobile", "bitLockerEncryptDevice", "bitLockerSystemDrivePolicy", "bitLockerFixedDrivePolicy", "bitLockerRemovableDrivePolicy", "bitLockerRecoveryPasswordRotation", "defenderDisableScanArchiveFiles", "defenderAllowScanArchiveFiles", "defenderDisableBehaviorMonitoring", "defenderAllowBehaviorMonitoring", "defenderDisableCloudProtection", "defenderAllowCloudProtection", "defenderEnableScanIncomingMail", "defenderEnableScanMappedNetworkDrivesDuringFullScan", "defenderDisableScanRemovableDrivesDuringFullScan", "defenderAllowScanRemovableDrivesDuringFullScan", "defenderDisableScanDownloads", "defenderAllowScanDownloads", "defenderDisableIntrusionPreventionSystem", "defenderAllowIntrusionPreventionSystem", "defenderDisableOnAccessProtection", "defenderAllowOnAccessProtection", "defenderDisableRealTimeMonitoring", "defenderAllowRealTimeMonitoring", "defenderDisableScanNetworkFiles", "defenderAllowScanNetworkFiles", "defenderDisableScanScriptsLoadedInInternetExplorer", "defenderAllowScanScriptsLoadedInInternetExplorer", "defenderBlockEndUserAccess", "defenderAllowEndUserAccess", "defenderScanMaxCpuPercentage", "defenderCheckForSignaturesBeforeRunningScan", "defenderCloudBlockLevel", "defenderCloudExtendedTimeoutInSeconds", "defenderDaysBeforeDeletingQuarantinedMalware", "defenderDisableCatchupFullScan", "defenderDisableCatchupQuickScan", "defenderEnableLowCpuPriority", "defenderFileExtensionsToExclude", "defenderFilesAndFoldersToExclude", "defenderProcessesToExclude", "defenderPotentiallyUnwantedAppAction", "defenderScanDirection", "defenderScanType", "defenderScheduledQuickScanTime", "defenderScheduledScanDay", "defenderScheduledScanTime", "defenderSignatureUpdateIntervalInHours", "defenderSubmitSamplesConsentType", "defenderDetectedMalwareActions", "firewallRules", "taskManagerBlockEndTask", "energySaverOnBatteryThresholdPercentage", "energySaverPluggedInThresholdPercentage", "powerLidCloseActionOnBattery", "powerLidCloseActionPluggedIn", "powerButtonActionOnBattery", "powerButtonActionPluggedIn", "powerSleepButtonActionOnBattery", "powerSleepButtonActionPluggedIn", "powerHybridSleepOnBattery", "powerHybridSleepPluggedIn", "windows10AppsForceUpdateSchedule", "enableAutomaticRedeployment", "microsoftAccountSignInAssistantSettings", "authenticationAllowSecondaryDevice", "authenticationWebSignIn", "authenticationPreferredAzureADTenantDomainName", "cryptographyAllowFipsAlgorithmPolicy", "displayAppListWithGdiDPIScalingTurnedOn", "displayAppListWithGdiDPIScalingTurnedOff", "enterpriseCloudPrintDiscoveryEndPoint", "enterpriseCloudPrintOAuthAuthority", "enterpriseCloudPrintOAuthClientIdentifier", "enterpriseCloudPrintResourceIdentifier", "enterpriseCloudPrintDiscoveryMaxLimit", "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier", "experienceDoNotSyncBrowserSettings", "messagingBlockSync", "messagingBlockMMS", "messagingBlockRichCommunicationServices", "printerNames", "printerDefaultName", "printerBlockAddition", "searchBlockDiacritics", "searchDisableAutoLanguageDetection", "searchDisableIndexingEncryptedItems", "searchEnableRemoteQueries", "searchDisableUseLocation", "searchDisableLocation", "searchDisableIndexerBackoff", "searchDisableIndexingRemovableDrive", "searchEnableAutomaticIndexSizeManangement", "searchBlockWebResults", "findMyFiles", "securityBlockAzureADJoinedDevicesAutoEncryption", "diagnosticsDataSubmissionMode", "oneDriveDisableFileSync", "systemTelemetryProxyServer", "edgeTelemetryForMicrosoft365Analytics", "inkWorkspaceAccess", "inkWorkspaceAccessState", "inkWorkspaceBlockSuggestedApps", "smartScreenEnableAppInstallControl", "smartScreenAppInstallControl", "personalizationDesktopImageUrl", "personalizationLockScreenImageUrl", "bluetoothAllowedServices", "bluetoothBlockAdvertising", "bluetoothBlockPromptedProximalConnections", "bluetoothBlockDiscoverableMode", "bluetoothBlockPrePairing", "edgeBlockAutofill", "edgeBlocked", "edgeCookiePolicy", "edgeBlockDeveloperTools", "edgeBlockSendingDoNotTrackHeader", "edgeBlockExtensions", "edgeBlockInPrivateBrowsing", "edgeBlockJavaScript", "edgeBlockPasswordManager", "edgeBlockAddressBarDropdown", "edgeBlockCompatibilityList", "edgeClearBrowsingDataOnExit", "edgeAllowStartPagesModification", "edgeDisableFirstRunPage", "edgeBlockLiveTileDataCollection", "edgeSyncFavoritesWithInternetExplorer", "edgeFavoritesListLocation", "edgeBlockEditFavorites", "edgeNewTabPageURL", "edgeHomeButtonConfiguration", "edgeHomeButtonConfigurationEnabled", "edgeOpensWith", "edgeBlockSideloadingExtensions", "edgeRequiredExtensionPackageFamilyNames", "edgeBlockPrinting", "edgeFavoritesBarVisibility", "edgeBlockSavingHistory", "edgeBlockFullScreenMode", "edgeBlockWebContentOnNewTabPage", "edgeBlockTabPreloading", "edgeBlockPrelaunch", "edgeShowMessageWhenOpeningInternetExplorerSites", "edgePreventCertificateErrorOverride", "edgeKioskModeRestriction", "edgeKioskResetAfterIdleTimeInMinutes", "cellularBlockDataWhenRoaming", "cellularBlockVpn", "cellularBlockVpnWhenRoaming", "cellularData", "defenderRequireRealTimeMonitoring", "defenderRequireBehaviorMonitoring", "defenderRequireNetworkInspectionSystem", "defenderScanDownloads", "defenderScheduleScanEnableLowCpuPriority", "defenderScanScriptsLoadedInInternetExplorer", "defenderMonitorFileActivity", "defenderScanMaxCpu", "defenderScanArchiveFiles", "defenderScanIncomingMail", "defenderScanRemovableDrivesDuringFullScan", "defenderScanMappedNetworkDrivesDuringFullScan", "defenderScanNetworkFiles", "defenderRequireCloudProtection", "defenderCloudExtendedTimeout", "defenderPromptForSampleSubmission", "defenderSystemScanSchedule", "defenderPotentiallyUnwantedAppActionSetting", "defenderBlockOnAccessProtection", "lockScreenAllowTimeoutConfiguration", "lockScreenBlockActionCenterNotifications", "lockScreenBlockCortana", "lockScreenBlockToastNotifications", "lockScreenTimeoutInSeconds", "lockScreenActivateAppsWithVoice", "passwordBlockSimple", "passwordExpirationDays", "passwordMinimumLength", "passwordMinutesOfInactivityBeforeScreenTimeout", "passwordMinimumCharacterSetCount", "passwordPreviousPasswordBlockCount", "passwordRequired", "passwordRequireWhenResumeFromIdleState", "passwordRequiredType", "passwordSignInFailureCountBeforeFactoryReset", "passwordMinimumAgeInDays", "privacyAdvertisingId", "privacyAutoAcceptPairingAndConsentPrompts", "privacyDisableLaunchExperience", "privacyBlockInputPersonalization", "privacyBlockPublishUserActivities", "privacyBlockActivityFeed", "activateAppsWithVoice", "startBlockUnpinningAppsFromTaskbar", "startMenuAppListVisibility", "startMenuHideChangeAccountSettings", "startMenuHideFrequentlyUsedApps", "startMenuHideHibernate", "startMenuHideLock", "startMenuHidePowerButton", "startMenuHideRecentJumpLists", "startMenuHideRecentlyAddedApps", "startMenuHideRestartOptions", "startMenuHideShutDown", "startMenuHideSignOut", "startMenuHideSleep", "startMenuHideSwitchAccount", "startMenuHideUserTile", "startMenuLayoutEdgeAssetsXml", "startMenuLayoutXml", "startMenuMode", "startMenuPinnedFolderDocuments", "startMenuPinnedFolderDownloads", "startMenuPinnedFolderFileExplorer", "startMenuPinnedFolderHomeGroup", "startMenuPinnedFolderMusic", "startMenuPinnedFolderNetwork", "startMenuPinnedFolderPersonalFolder", "startMenuPinnedFolderPictures", "startMenuPinnedFolderSettings", "startMenuPinnedFolderVideos", "settingsBlockSettingsApp", "settingsBlockSystemPage", "settingsBlockDevicesPage", "settingsBlockNetworkInternetPage", "settingsBlockPersonalizationPage", "settingsBlockAccountsPage", "settingsBlockTimeLanguagePage", "settingsBlockEaseOfAccessPage", "settingsBlockPrivacyPage", "settingsBlockUpdateSecurityPage", "settingsBlockAppsPage", "settingsBlockGamingPage", "windowsSpotlightBlockConsumerSpecificFeatures", "windowsSpotlightBlocked", "windowsSpotlightBlockOnActionCenter", "windowsSpotlightBlockTailoredExperiences", "windowsSpotlightBlockThirdPartyNotifications", "windowsSpotlightBlockWelcomeExperience", "windowsSpotlightBlockWindowsTips", "windowsSpotlightConfigureOnLockScreen", "networkProxyApplySettingsDeviceWide", "networkProxyDisableAutoDetect", "networkProxyAutomaticConfigurationUrl", "networkProxyServer", "accountsBlockAddingNonMicrosoftAccountEmail", "antiTheftModeBlocked", "bluetoothBlocked", "cameraBlocked", "connectedDevicesServiceBlocked", "certificatesBlockManualRootCertificateInstallation", "copyPasteBlocked", "cortanaBlocked", "deviceManagementBlockFactoryResetOnMobile", "deviceManagementBlockManualUnenroll", "safeSearchFilter", "edgeBlockPopups", "edgeBlockSearchSuggestions", "edgeBlockSearchEngineCustomization", "edgeBlockSendingIntranetTrafficToInternetExplorer", "edgeSendIntranetTrafficToInternetExplorer", "edgeRequireSmartScreen", "edgeEnterpriseModeSiteListLocation", "edgeFirstRunUrl", "edgeSearchEngine", "edgeHomepageUrls", "edgeBlockAccessToAboutFlags", "smartScreenBlockPromptOverride", "smartScreenBlockPromptOverrideForFiles", "webRtcBlockLocalhostIpAddress", "internetSharingBlocked", "settingsBlockAddProvisioningPackage", "settingsBlockRemoveProvisioningPackage", "settingsBlockChangeSystemTime", "settingsBlockEditDeviceName", "settingsBlockChangeRegion", "settingsBlockChangeLanguage", "settingsBlockChangePowerSleep", "locationServicesBlocked", "microsoftAccountBlocked", "microsoftAccountBlockSettingsSync", "nfcBlocked", "resetProtectionModeBlocked", "screenCaptureBlocked", "storageBlockRemovableStorage", "storageRequireMobileDeviceEncryption", "usbBlocked", "voiceRecordingBlocked", "wiFiBlockAutomaticConnectHotspots", "wiFiBlocked", "wiFiBlockManualConfiguration", "wiFiScanInterval", "wirelessDisplayBlockProjectionToThisDevice", "wirelessDisplayBlockUserInputFromReceiver", "wirelessDisplayRequirePinForPairing", "windowsStoreBlocked", "appsAllowTrustedAppsSideloading", "windowsStoreBlockAutoUpdate", "developerUnlockSetting", "sharedUserAppDataAllowed", "appsBlockWindowsStoreOriginatedApps", "windowsStoreEnablePrivateStoreOnly", "storageRestrictAppDataToSystemVolume", "storageRestrictAppInstallToSystemVolume", "gameDvrBlocked", "experienceBlockDeviceDiscovery", "experienceBlockErrorDialogWhenNoSIM", "experienceBlockTaskSwitcher", "logonBlockFastUserSwitching", "tenantLockdownRequireNetworkDuringOutOfBoxExperience", "appManagementMSIAllowUserControlOverInstall", "appManagementMSIAlwaysInstallWithElevatedPrivileges", "dataProtectionBlockDirectMemoryAccess", "appManagementPackageFamilyNamesToLaunchAfterLogOn", "uninstallBuiltInApps", "configureTimeZone", "deliveryOptimizationMode", "prereleaseFeatures", "automaticUpdateMode", "microsoftUpdateServiceAllowed", "driversExcluded", "installationSchedule", "qualityUpdatesDeferralPeriodInDays", "featureUpdatesDeferralPeriodInDays", "qualityUpdatesPaused", "featureUpdatesPaused", "qualityUpdatesPauseExpiryDateTime", "featureUpdatesPauseExpiryDateTime", "businessReadyUpdatesOnly", "skipChecksBeforeRestart", "updateWeeks", "qualityUpdatesPauseStartDate", "featureUpdatesPauseStartDate", "featureUpdatesRollbackWindowInDays", "qualityUpdatesWillBeRolledBack", "featureUpdatesWillBeRolledBack", "qualityUpdatesRollbackStartDateTime", "featureUpdatesRollbackStartDateTime", "engagedRestartDeadlineInDays", "engagedRestartSnoozeScheduleInDays", "engagedRestartTransitionScheduleInDays", "deadlineForFeatureUpdatesInDays", "deadlineForQualityUpdatesInDays", "deadlineGracePeriodInDays", "postponeRebootUntilAfterDeadline", "autoRestartNotificationDismissal", "scheduleRestartWarningInHours", "scheduleImminentRestartWarningInMinutes", "userPauseAccess", "userWindowsUpdateScanAccess", "updateNotificationLevel"})
    in
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicySettingStates = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.DeviceConfigurationPolicyStates(tenants),
        policyStates = Table.SelectColumns(source, {"tenantId", "deviceId", "id"}),
        renamedColumn =  Table.RenameColumns(policyStates, {{"id", "policyId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates/" & [policyId] & "/settingStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}, {"setting", "settingName", "instanceDisplayName", "state", "errorCode", "errorDescription", "userId", "userName", "userEmail", "userPrincipalName", "currentValue", "settingInstanceId", "sources"}),
        expandedSourcesList = Table.ExpandListColumn(expandedRecord, "sources"),
        expandedSourcesRecord = Table.ExpandRecordColumn(expandedSourcesList, "sources", {"id", "displayName"}, {"sources.id", "sources.displayName"})
    in 
        expandedSourcesRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.DeviceConfigurationPolicyStates = (optional tenants as list) as table =>
    let        
        source = SecMgmtInsights.ManagedDevices(tenants),
        managedDevices = Table.SelectColumns(source, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceManagement/managedDevices/" & [deviceId] & "/deviceConfigurationStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "displayName", "version", "platformType", "state", "settingCount", "userId", "userPrincipalName", "settingStates"}, {"id", "displayName", "version", "platformType", "state", "settingCount", "userId", "userPrincipalName", "settingStates"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Intents = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("deviceManagement/intents", tenants),
        expandedCustom = Table.ExpandRecordColumn(data, "Column1", {"id", "displayName", "description", "isAssigned", "lastModifiedDateTime", "templateId", "roleScopeTagIds"}, {"id", "displayName", "description", "isAssigned", "lastModifiedDateTime", "templateId", "roleScopeTagIds"}),
        changedType = Table.TransformColumnTypes(expandedCustom, {{"isAssigned", type logical}, {"lastModifiedDateTime", type datetimezone}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ManagedDevices = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("deviceManagement/managedDevices", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "userId", "deviceName", "ownerType", "managedDeviceOwnerType", "managementState", "enrolledDateTime", "lastSyncDateTime", "chassisType", "operatingSystem", "deviceType", "complianceState", "jailBroken", "managementAgent", "osVersion", "easActivated", "easDeviceId", "easActivationDateTime", "aadRegistered", "azureADRegistered", "deviceEnrollmentType", "lostModeState", "activationLockBypassCode", "emailAddress", "azureActiveDirectoryDeviceId", "azureADDeviceId", "deviceRegistrationState", "deviceCategoryDisplayName", "isSupervised", "exchangeLastSuccessfulSyncDateTime", "exchangeAccessState", "exchangeAccessStateReason", "remoteAssistanceSessionUrl", "remoteAssistanceSessionErrorDetails", "isEncrypted", "userPrincipalName", "model", "manufacturer", "imei", "complianceGracePeriodExpirationDateTime", "serialNumber", "phoneNumber", "androidSecurityPatchLevel", "userDisplayName", "configurationManagerClientEnabledFeatures", "wiFiMacAddress", "deviceHealthAttestationState", "subscriberCarrier", "meid", "totalStorageSpaceInBytes", "freeStorageSpaceInBytes", "managedDeviceName", "partnerReportedThreatState", "retireAfterDateTime", "preferMdmOverGroupPolicyAppliedDateTime", "autopilotEnrolled", "requireUserEnrollmentApproval", "managementCertificateExpirationDate", "iccid", "udid", "roleScopeTagIds", "windowsActiveMalwareCount", "windowsRemediatedMalwareCount", "notes", "configurationManagerClientHealthState", "configurationManagerClientInformation", "ethernetMacAddress", "physicalMemoryInBytes", "processorArchitecture", "specificationVersion", "hardwareInformation", "deviceActionResults", "usersLoggedOn"}, {"id", "userId", "deviceName", "ownerType", "managedDeviceOwnerType", "managementState", "enrolledDateTime", "lastSyncDateTime", "chassisType", "operatingSystem", "deviceType", "complianceState", "jailBroken", "managementAgent", "osVersion", "easActivated", "easDeviceId", "easActivationDateTime", "aadRegistered", "azureADRegistered", "deviceEnrollmentType", "lostModeState", "activationLockBypassCode", "emailAddress", "azureActiveDirectoryDeviceId", "azureADDeviceId", "deviceRegistrationState", "deviceCategoryDisplayName", "isSupervised", "exchangeLastSuccessfulSyncDateTime", "exchangeAccessState", "exchangeAccessStateReason", "remoteAssistanceSessionUrl", "remoteAssistanceSessionErrorDetails", "isEncrypted", "userPrincipalName", "model", "manufacturer", "imei", "complianceGracePeriodExpirationDateTime", "serialNumber", "phoneNumber", "androidSecurityPatchLevel", "userDisplayName", "configurationManagerClientEnabledFeatures", "wiFiMacAddress", "deviceHealthAttestationState", "subscriberCarrier", "meid", "totalStorageSpaceInBytes", "freeStorageSpaceInBytes", "managedDeviceName", "partnerReportedThreatState", "retireAfterDateTime", "preferMdmOverGroupPolicyAppliedDateTime", "autopilotEnrolled", "requireUserEnrollmentApproval", "managementCertificateExpirationDate", "iccid", "udid", "roleScopeTagIds", "windowsActiveMalwareCount", "windowsRemediatedMalwareCount", "notes", "configurationManagerClientHealthState", "configurationManagerClientInformation", "ethernetMacAddress", "physicalMemoryInBytes", "processorArchitecture", "specificationVersion", "hardwareInformation", "deviceActionResults", "usersLoggedOn"}),
        changedType = Table.TransformColumnTypes(expandedRecord,{{"enrolledDateTime", type datetimezone}, {"lastSyncDateTime", type datetimezone}, {"easActivated", type logical}, {"easActivationDateTime", type datetimezone}, {"aadRegistered", type logical}, {"azureADRegistered", type logical}, {"exchangeLastSuccessfulSyncDateTime", type datetimezone}, {"isEncrypted", type logical}, {"complianceGracePeriodExpirationDateTime", type datetimezone}, {"retireAfterDateTime", type datetimezone}, {"preferMdmOverGroupPolicyAppliedDateTime", type datetimezone}, {"autopilotEnrolled", type logical}, {"managementCertificateExpirationDate", type datetimezone}, {"windowsActiveMalwareCount", Int64.Type}, {"windowsRemediatedMalwareCount", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileAppDeviceStatuses = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.MobileApps(tenants),
        filteredRows = Table.SelectRows(source, each [isAssigned] = true),
        mobileApps = Table.SelectColumns(filteredRows, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(mobileApps, {{"id", "mobileAppId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceAppManagement/mobileApps/" & [mobileAppId] & "/deviceStatuses", {[tenantId]}) otherwise null),
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
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetData("deviceAppManagement/mobileApps/" & [mobileAppId] & "/installSummary", {[tenantId]}) otherwise null),
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
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceAppManagement/mobileApps/" & [mobileAppId] & "/userStatuses", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "userName", "userPrincipalName", "installedDeviceCount", "failedDeviceCount", "notInstalledDeviceCount"}, {"id", "userName", "userPrincipalName", "installedDeviceCount", "failedDeviceCount", "notInstalledDeviceCount"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"installedDeviceCount", Int64.Type}, {"failedDeviceCount", Int64.Type}, {"notInstalledDeviceCount", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MobileApps = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("deviceAppManagement/mobileApps", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "displayName", "description", "publisher", "largeIcon", "createdDateTime", "lastModifiedDateTime", "isFeatured", "privacyInformationUrl", "informationUrl", "owner", "developer", "notes", "uploadState", "publishingState", "isAssigned", "roleScopeTagIds", "dependentAppCount", "appAvailability", "version", "packageId", "appStoreUrl", "minimumSupportedOperatingSystem", "bundleId", "applicableDeviceType", "committedContentVersion", "fileName", "size", "commandLine", "productCode", "productVersion", "ignoreVersionDetection", "identityVersion", "useDeviceContext"}, {"id", "displayName", "description", "publisher", "largeIcon", "createdDateTime", "lastModifiedDateTime", "isFeatured", "privacyInformationUrl", "informationUrl", "owner", "developer", "notes", "uploadState", "publishingState", "isAssigned", "roleScopeTagIds", "dependentAppCount", "appAvailability", "version", "packageId", "appStoreUrl", "minimumSupportedOperatingSystem", "bundleId", "applicableDeviceType", "committedContentVersion", "fileName", "size", "commandLine", "productCode", "productVersion", "ignoreVersionDetection", "identityVersion", "useDeviceContext"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"createdDateTime", type datetimezone}, {"lastModifiedDateTime", type datetimezone}, {"isFeatured", type logical}, {"uploadState", Int64.Type}, {"isAssigned", type logical}, {"dependentAppCount", Int64.Type}, {"size", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineSettingStates = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.SecurityBaselineStates(tenants),
        filterColumns = Table.SelectColumns(source, {"tenantId", "deviceId", "id"}),
        renamedColumn =  Table.RenameColumns(filterColumns, {{"id", "templateId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates/" & [templateId] & "/settingStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "settingName", "state", "settingCategoryId"}, {"id", "settingName", "state", "settingCategoryId"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecurityBaselineStates = (optional tenants as list) as table =>
    let        
        source = SecMgmtInsights.ManagedDevices(tenants),
        managedDevices = Table.SelectColumns(source, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetPagedData("deviceManagement/managedDevices/" & [deviceId] & "/securityBaselineStates", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"id", "securityBaselineTemplateId", "displayName"}, {"id", "securityBaselineTemplateId", "displayName"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SoftwareUpdateStatusSummary = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("deviceManagement/softwareUpdateStatusSummary", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "displayName", "compliantDeviceCount", "nonCompliantDeviceCount", "remediatedDeviceCount", "errorDeviceCount", "unknownDeviceCount", "conflictDeviceCount", "notApplicableDeviceCount", "compliantUserCount", "nonCompliantUserCount", "remediatedUserCount", "errorUserCount", "unknownUserCount", "conflictUserCount", "notApplicableUserCount"}, {"id", "displayName", "compliantDeviceCount", "nonCompliantDeviceCount", "remediatedDeviceCount", "errorDeviceCount", "unknownDeviceCount", "conflictDeviceCount", "notApplicableDeviceCount", "compliantUserCount", "nonCompliantUserCount", "remediatedUserCount", "errorUserCount", "unknownUserCount", "conflictUserCount", "notApplicableUserCount"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"compliantDeviceCount", Int64.Type}, {"nonCompliantDeviceCount", Int64.Type}, {"remediatedDeviceCount", Int64.Type}, {"errorDeviceCount", Int64.Type}, {"unknownDeviceCount", Int64.Type}, {"conflictDeviceCount", Int64.Type}, {"notApplicableDeviceCount", Int64.Type}, {"compliantUserCount", Int64.Type}, {"nonCompliantUserCount", Int64.Type}, {"remediatedUserCount", Int64.Type}, {"errorUserCount", Int64.Type}, {"unknownUserCount", Int64.Type}, {"conflictUserCount", Int64.Type}, {"notApplicableUserCount", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserExperienceAnalyticsDevicePerformance = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("deviceManagement/userExperienceAnalyticsDevicePerformance", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "deviceName", "model", "manufacturer", "diskType", "operatingSystemVersion", "bootScore", "coreBootTimeInMs", "groupPolicyBootTimeInMs", "operatingSystem", "healthStatus", "complianceState", "loginScore", "coreLoginTimeInMs", "groupPolicyLoginTimeInMs", "deviceCount", "responsiveDesktopTimeInMs"}, {"id", "deviceName", "model", "manufacturer", "diskType", "operatingSystemVersion", "bootScore", "coreBootTimeInMs", "groupPolicyBootTimeInMs", "operatingSystem", "healthStatus", "complianceState", "loginScore", "coreLoginTimeInMs", "groupPolicyLoginTimeInMs", "deviceCount", "responsiveDesktopTimeInMs"})
    in 
        expandedRecord;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotDeviceIdentities = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("deviceManagement/windowsAutopilotDeviceIdentities", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "deploymentProfileAssignmentStatus", "deploymentProfileAssignmentDetailedStatus", "deploymentProfileAssignedDateTime", "orderIdentifier", "groupTag", "purchaseOrderIdentifier", "serialNumber", "productKey", "manufacturer", "model", "enrollmentState", "lastContactedDateTime", "addressableUserName", "userPrincipalName", "resourceName", "skuNumber", "systemFamily", "azureActiveDirectoryDeviceId", "managedDeviceId", "displayName"}, {"id", "deploymentProfileAssignmentStatus", "deploymentProfileAssignmentDetailedStatus", "deploymentProfileAssignedDateTime", "orderIdentifier", "groupTag", "purchaseOrderIdentifier", "serialNumber", "productKey", "manufacturer", "model", "enrollmentState", "lastContactedDateTime", "addressableUserName", "userPrincipalName", "resourceName", "skuNumber", "systemFamily", "azureActiveDirectoryDeviceId", "managedDeviceId", "displayName"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"deploymentProfileAssignedDateTime", type datetimezone}, {"lastContactedDateTime", type datetimezone}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotProfiles = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("deviceManagement/windowsAutopilotDeploymentProfiles", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "displayName", "description", "language", "createdDateTime", "lastModifiedDateTime", "enrollmentStatusScreenSettings", "extractHardwareHash", "deviceNameTemplate", "deviceType", "enableWhiteGlove", "roleScopeTagIds", "outOfBoxExperienceSettings"}, {"id", "displayName", "description", "language", "createdDateTime", "lastModifiedDateTime", "enrollmentStatusScreenSettings", "extractHardwareHash", "deviceNameTemplate", "deviceType", "enableWhiteGlove", "roleScopeTagIds", "outOfBoxExperienceSettings"}),
        expandedOobe = Table.ExpandRecordColumn(expandedRecord, "outOfBoxExperienceSettings", {"hidePrivacySettings", "hideEULA", "userType", "deviceUsageType", "skipKeyboardSelectionPage", "hideEscapeLink"}, {"outOfBoxExperienceSettings.hidePrivacySettings", "outOfBoxExperienceSettings.hideEULA", "outOfBoxExperienceSettings.userType", "outOfBoxExperienceSettings.deviceUsageType", "outOfBoxExperienceSettings.skipKeyboardSelectionPage", "outOfBoxExperienceSettings.hideEscapeLink"}),
        changedType = Table.TransformColumnTypes(expandedOobe, {{"createdDateTime", type datetimezone}, {"lastModifiedDateTime", type datetimezone}, {"extractHardwareHash", type logical}, {"enableWhiteGlove", type logical}, {"outOfBoxExperienceSettings.hidePrivacySettings", type logical}, {"outOfBoxExperienceSettings.hideEULA", type logical}, {"outOfBoxExperienceSettings.skipKeyboardSelectionPage", type logical}, {"outOfBoxExperienceSettings.hideEscapeLink", type logical}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsAutopilotSettings = (optional tenants as list) as table =>
    let 
        data = Request.GetData("deviceManagement/windowsAutopilotSettings", tenants),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandedCustom = Table.ExpandRecordColumn(data, "Column1", {"id", "lastSyncDateTime", "lastManualSyncTriggerDateTime", "syncStatus"}, {"id", "lastSyncDateTime", "lastManualSyncTriggerDateTime", "syncStatus"}),
        changedType = Table.TransformColumnTypes(expandedCustom, {{"lastSyncDateTime", type datetimezone}, {"lastManualSyncTriggerDateTime", type datetimezone}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsMalwareInformation = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("deviceManagement/windowsMalwareInformation", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "displayName", "additionalInformationUrl", "severity", "category", "lastDetectionDateTime"}, {"id", "displayName", "additionalInformationUrl", "severity", "category", "lastDetectionDateTime"}),
        changedType = Table.TransformColumnTypes(expandedRecord,{{"lastDetectionDateTime", type datetimezone}})
    in
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.WindowsProtectionState = (optional tenants as list) as table =>
    let 
        source = SecMgmtInsights.ManagedDevices(tenants),
        managedDevices = Table.SelectColumns(source, {"tenantId", "id"}),
        renamedColumn = Table.RenameColumns(managedDevices, {{"id", "deviceId"}}),
        data = Table.AddColumn(renamedColumn, "Custom", each try Request.GetData("deviceManagement/managedDevices/" & [deviceId] & "/windowsProtectionState", {[tenantId]}) otherwise null),
        expandCustom = Table.ExpandTableColumn(data, "Custom", {"Column1"}, {"Column1"}),
        expandRecord = Table.ExpandRecordColumn(expandCustom, "Column1", {"malwareProtectionEnabled", "deviceState", "realTimeProtectionEnabled", "networkInspectionSystemEnabled", "quickScanOverdue", "fullScanOverdue", "signatureUpdateOverdue", "rebootRequired", "fullScanRequired", "engineVersion", "signatureVersion", "antiMalwareVersion", "lastQuickScanDateTime", "lastFullScanDateTime", "lastQuickScanSignatureVersion", "lastFullScanSignatureVersion", "lastReportedDateTime"}, {"malwareProtectionEnabled", "deviceState", "realTimeProtectionEnabled", "networkInspectionSystemEnabled", "quickScanOverdue", "fullScanOverdue", "signatureUpdateOverdue", "rebootRequired", "fullScanRequired", "engineVersion", "signatureVersion", "antiMalwareVersion", "lastQuickScanDateTime", "lastFullScanDateTime", "lastQuickScanSignatureVersion", "lastFullScanSignatureVersion", "lastReportedDateTime"}),
        changedType = Table.TransformColumnTypes(expandRecord, {{"malwareProtectionEnabled", type logical}, {"realTimeProtectionEnabled", type logical}, {"networkInspectionSystemEnabled", type logical}, {"quickScanOverdue", type logical}, {"fullScanOverdue", type logical}, {"signatureUpdateOverdue", type logical}, {"rebootRequired", type logical}, {"fullScanRequired", type logical}, {"lastQuickScanDateTime", type datetimezone}, {"lastFullScanDateTime", type datetimezone}, {"lastReportedDateTime", type datetimezone}})
    in 
        changedType;

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

Request.GetData = (relativeUrl as text, optional tenants as list) as table =>
    let
        GetData = (tenantId as text) =>
            let
                data = Microsoft.GetContent(graph_endpoint & "/" & relativeUrl, Token.GetAccessToken(tenantId)),
                record = Record.FromTable(data)
            in 
                record,

        source = if(tenants = null or tenants = "") then Request.GetTenant() else Table.FromList(tenants, Splitter.SplitByNothing(), {"tenantId"}),
        data = Table.AddColumn(source, "Column1", each try GetData([tenantId]) otherwise null)
    in
        data;

Request.GetPagedData = (relativeUrl as text, optional tenants as list) as table =>
    let      
        GetData = (tenantId as text) =>
            let
                data = Microsoft.GetPagedContent(graph_endpoint & "/" & relativeUrl, Token.GetAccessToken(tenantId)),
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

// Information Protection 

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.UserInformationProtectionLabels = (optional tenants as list) as table =>
    let
        source = SecMgmtInsights.Users(tenants), 
        filterColumns = Table.SelectColumns(source, {"tenantId", "id"}), 
        renameColumn = Table.RenameColumns(filterColumns, {{"id", "userId"}}),
        data = Table.AddColumn(renameColumn, "Custom", each try Request.GetPagedData("users/" & [userId] & "/informationProtection/policy/labels", {[tenantId]}) otherwise null)
    in 
        data;

// Intelligent Security Graph

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Alerts = (optional tenants as list) as table =>
    let 
        // TODO - Need to get a customer with test data
        data = Request.GetPagedData("security/alerts", tenants)
    in 
        data;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScore = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("security/secureScores", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "azureTenantId", "activeUserCount", "createdDateTime", "currentScore", "enabledServices", "licensedUserCount", "maxScore", "vendorInformation", "averageComparativeScores", "controlScores"}, {"id", "azureTenantId", "activeUserCount", "createdDateTime", "currentScore", "enabledServices", "licensedUserCount", "maxScore", "vendorInformation", "averageComparativeScores", "controlScores"}),
        changedType = Table.TransformColumnTypes(expandedRecord, {{"activeUserCount", Int64.Type}, {"createdDateTime", type datetimezone}, {"currentScore", Int64.Type}, {"licensedUserCount", Int64.Type}, {"maxScore", Int64.Type}})
    in 
        changedType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SecureScoreControlProfiles = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("security/secureScoreControlProfiles", tenants),
        expandedRecord = Table.ExpandRecordColumn(data, "Column1", {"id", "azureTenantId", "actionType", "actionUrl", "controlCategory", "title", "deprecated", "implementationCost", "lastModifiedDateTime", "maxScore", "rank", "remediation", "remediationImpact", "service", "threats", "tier", "userImpact", "vendorInformation", "complianceInformation", "controlStateUpdates"}, {"id", "azureTenantId", "actionType", "actionUrl", "controlCategory", "title", "deprecated", "implementationCost", "lastModifiedDateTime", "maxScore", "rank", "remediation", "remediationImpact", "service", "threats", "tier", "userImpact", "vendorInformation", "complianceInformation", "controlStateUpdates"})
    in
        expandedRecord;

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
            { "TeamsUserActivityUserDetail", SecMgmtInsights.TeamsUserActivityUserDetail(tenants) },
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

Microsoft.GetContent = (url as text, token as text) =>
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
        Record.ToTable(result) meta [Next=link];

Microsoft.GetPagedContent = (url as text, token as text) => Table.GenerateByPage((previous) =>
    let
        // If we have a previous page, get its Next link from metadata on the page.
        next = if (previous <> null) then try Value.Metadata(previous)[Next] otherwise null else null,
        // If we have a next link, use it, otherwise use the original URL that was passed in.
        urlToUse = if (next <> null) then next else url,
        // If we have a previous page, but don't have a next link, then we're done paging.
        // Otherwise retrieve the next page.
        current = if (previous <> null and next = null) then null else Microsoft.GetContent(urlToUse, token),
        // If we got data back from the current page, get the link for the next page
        link = if (current <> null) then Value.Metadata(current)[Next] else null,
        // Microsoft Graph utilizes OData, so the value needs to be extracted
        data = if(current <> null) then Table.FromList(Table.SelectRows(current, each ([Name] = "value"))[Value], Splitter.SplitByNothing()) else null
    in
        data meta [Next=link]);

// Office 365

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.MailboxUsageDetail = (optional tenants as list) as table =>
    let 
        data = Request.GetPagedData("reports/getMailboxUsageDetail(period='D30')?$format=application/json", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"userPrincipalName", "displayName", "isDeleted", "deletedDate", "createdDate", "lastActivityDate", "itemCount", "storageUsedInBytes", "deletedItemCount", "deletedItemSizeInBytes", "issueWarningQuotaInBytes", "prohibitSendQuotaInBytes", "prohibitSendReceiveQuotaInBytes"}, {"userPrincipalName", "displayName", "isDeleted", "deletedDate", "createdDate", "lastActivityDate", "itemCount", "storageUsedInBytes", "deletedItemCount", "deletedItemSizeInBytes", "issueWarningQuotaInBytes", "prohibitSendQuotaInBytes", "prohibitSendReceiveQuotaInBytes"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"isDeleted", type logical}, {"deletedDate", type date}, {"createdDate", type date}, {"lastActivityDate", type date}, {"itemCount", Int64.Type}, {"storageUsedInBytes", Int64.Type}, {"deletedItemCount", Int64.Type}, {"deletedItemSizeInBytes", Int64.Type}, {"issueWarningQuotaInBytes", Int64.Type}, {"prohibitSendQuotaInBytes", Int64.Type}, {"prohibitSendReceiveQuotaInBytes", Int64.Type}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ActiveUserDetails = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"userPrincipalName", "displayName", "isDeleted", "deletedDate", "hasExchangeLicense", "hasOneDriveLicense", "hasSharePointLicense", "hasSkypeForBusinessLicense", "hasYammerLicense", "hasTeamsLicense", "exchangeLastActivityDate", "oneDriveLastActivityDate", "sharePointLastActivityDate", "skypeForBusinessLastActivityDate", "yammerLastActivityDate", "teamsLastActivityDate", "exchangeLicenseAssignDate", "oneDriveLicenseAssignDate", "sharePointLicenseAssignDate", "skypeForBusinessLicenseAssignDate", "yammerLicenseAssignDate", "teamsLicenseAssignDate", "assignedProducts"}, {"userPrincipalName", "displayName", "isDeleted", "deletedDate", "hasExchangeLicense", "hasOneDriveLicense", "hasSharePointLicense", "hasSkypeForBusinessLicense", "hasYammerLicense", "hasTeamsLicense", "exchangeLastActivityDate", "oneDriveLastActivityDate", "sharePointLastActivityDate", "skypeForBusinessLastActivityDate", "yammerLastActivityDate", "teamsLastActivityDate", "exchangeLicenseAssignDate", "oneDriveLicenseAssignDate", "sharePointLicenseAssignDate", "skypeForBusinessLicenseAssignDate", "yammerLicenseAssignDate", "teamsLicenseAssignDate", "assignedProducts"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"isDeleted", type logical}, {"deletedDate", type date}, {"hasExchangeLicense", type logical}, {"hasOneDriveLicense", type logical}, {"hasSharePointLicense", type logical}, {"hasSkypeForBusinessLicense", type logical}, {"hasYammerLicense", type logical}, {"hasTeamsLicense", type logical}, {"exchangeLastActivityDate", type date}, {"oneDriveLastActivityDate", type date}, {"sharePointLastActivityDate", type date}, {"skypeForBusinessLastActivityDate", type date}, {"yammerLastActivityDate", type date}, {"teamsLastActivityDate", type date}, {"exchangeLicenseAssignDate", type date}, {"oneDriveLicenseAssignDate", type date}, {"sharePointLicenseAssignDate", type date}, {"skypeForBusinessLicenseAssignDate", type date}, {"yammerLicenseAssignDate", type date}, {"teamsLicenseAssignDate", type date}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.Office365ServicesUserCounts = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("reports/getOffice365ServicesUserCounts(period='D30')?$format=application/json", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"exchangeActive", "exchangeInactive", "oneDriveActive", "oneDriveInactive", "sharePointActive", "sharePointInactive", "skypeForBusinessActive", "skypeForBusinessInactive", "yammerActive", "yammerInactive", "teamsActive", "teamsInactive", "office365Active", "office365Inactive"}, {"exchangeActive", "exchangeInactive", "oneDriveActive", "oneDriveInactive", "sharePointActive", "sharePointInactive", "skypeForBusinessActive", "skypeForBusinessInactive", "yammerActive", "yammerInactive", "teamsActive", "teamsInactive", "office365Active", "office365Inactive"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"exchangeActive", Int64.Type}, {"exchangeInactive", Int64.Type}, {"oneDriveActive", Int64.Type}, {"oneDriveInactive", Int64.Type}, {"sharePointActive", Int64.Type}, {"sharePointInactive", Int64.Type}, {"skypeForBusinessActive", Int64.Type}, {"skypeForBusinessInactive", Int64.Type}, {"yammerActive", Int64.Type}, {"yammerInactive", Int64.Type}, {"teamsActive", Int64.Type}, {"teamsInactive", Int64.Type}, {"office365Active", Int64.Type}, {"office365Inactive", Int64.Type}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.OneDriveUsageAccountDetail = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("reports/getOneDriveUsageAccountDetail(period='D30')?$format=application/json", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"siteUrl", "ownerDisplayName", "ownerPrincipalName", "isDeleted", "lastActivityDate", "fileCount", "activeFileCount", "storageUsedInBytes", "storageAllocatedInBytes"}, {"siteUrl", "ownerDisplayName", "ownerPrincipalName", "isDeleted", "lastActivityDate", "fileCount", "activeFileCount", "storageUsedInBytes", "storageAllocatedInBytes"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"isDeleted", type logical}, {"lastActivityDate", type date}, {"fileCount", Int64.Type}, {"activeFileCount", Int64.Type}, {"storageUsedInBytes", Int64.Type}, {"storageAllocatedInBytes", Int64.Type}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.SharePointSiteUsageDetail = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("reports/getSharePointSiteUsageDetail(period='D30')?$format=application/json", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"siteId", "siteUrl", "ownerDisplayName", "ownerPrincipalName", "isDeleted", "lastActivityDate", "fileCount", "activeFileCount", "pageViewCount", "visitedPageCount", "storageUsedInBytes", "storageAllocatedInBytes", "rootWebTemplate"}, {"siteId", "siteUrl", "ownerDisplayName", "ownerPrincipalName", "isDeleted", "lastActivityDate", "fileCount", "activeFileCount", "pageViewCount", "visitedPageCount", "storageUsedInBytes", "storageAllocatedInBytes", "rootWebTemplate"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"isDeleted", type logical}, {"lastActivityDate", type date}, {"fileCount", Int64.Type}, {"activeFileCount", Int64.Type}, {"pageViewCount", Int64.Type}, {"visitedPageCount", Int64.Type}, {"storageUsedInBytes", Int64.Type}, {"storageAllocatedInBytes", Int64.Type}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.TeamsUserActivityUserDetail = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("reports/getTeamsUserActivityUserDetail(period='D30')?$format=application/json", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"userPrincipalName", "lastActivityDate", "isDeleted", "deletedDate", "assignedProducts", "teamChatMessageCount", "privateChatMessageCount", "callCount", "meetingCount", "hasOtherAction"}, {"userPrincipalName", "lastActivityDate", "isDeleted", "deletedDate", "assignedProducts", "teamChatMessageCount", "privateChatMessageCount", "callCount", "meetingCount", "hasOtherAction"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"lastActivityDate", type date}, {"isDeleted", type logical}, {"deletedDate", type date}, {"teamChatMessageCount", Int64.Type}, {"privateChatMessageCount", Int64.Type}, {"callCount", Int64.Type}, {"meetingCount", Int64.Type}, {"hasOtherAction", type logical}})
    in 
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.YammerActivityUserDetail = (optional tenants as list) as table =>
    let
        data = Request.GetPagedData("reports/getYammerActivityUserDetail(period='D30')?$format=application/json", tenants),
        expandRecord = Table.ExpandRecordColumn(data, "Column1", {"userPrincipalName", "displayName", "userState", "stateChangeDate", "lastActivityDate", "postedCount", "readCount", "likedCount", "assignedProducts"}, {"userPrincipalName", "displayName", "userState", "stateChangeDate", "lastActivityDate", "postedCount", "readCount", "likedCount", "assignedProducts"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"stateChangeDate", type date}, {"lastActivityDate", type date}, {"postedCount", Int64.Type}, {"readCount", Int64.Type}, {"likedCount", Int64.Type}})
    in 
        changeType;

// Office 365 Service Communication

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ServiceCurrentStatus = (optional tenants as list) as table =>
    let
        source = Request.GetServiceCommData("ServiceComms/CurrentStatus", tenants),
        expandRecord = Table.ExpandRecordColumn(source, "Column1", {"FeatureStatus", "Id", "IncidentIds", "Status", "StatusDisplayName", "StatusTime", "Workload", "WorkloadDisplayName"}, {"FeatureStatus", "Id", "IncidentIds", "Status", "StatusDisplayName", "StatusTime", "Workload", "WorkloadDisplayName"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"StatusTime", type datetimezone}})
    in
        changeType;

[DataSource.Kind="SecMgmtInsights"]
shared SecMgmtInsights.ServiceHistoricalStatus = (optional tenants as list) as table =>
    let
        source = Request.GetServiceCommData("ServiceComms/HistoricalStatus", tenants),
        expandRecord = Table.ExpandRecordColumn(source, "Column1", {"FeatureStatus", "Id", "IncidentIds", "Status", "StatusDisplayName", "StatusTime", "Workload", "WorkloadDisplayName"}, {"FeatureStatus", "Id", "IncidentIds", "Status", "StatusDisplayName", "StatusTime", "Workload", "WorkloadDisplayName"}),
        changeType = Table.TransformColumnTypes(expandRecord, {{"StatusTime", type datetimezone}})
    in
        changeType;
