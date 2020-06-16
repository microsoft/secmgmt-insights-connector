# Security and Management Insights Connector

This connector is still under development, which mean function signatures could change without notice. As work continues additional documentation and features will be added. 

## Getting Started

### Deploying the connector

## Prerequisite

This connector utilizes Microsoft Graph and the Office 365 Management API to surface management and security insights for Microsoft 365. Interacting with these APIs requires a native Azure Active Directory application configured with the following permissions

| API | Permissions | Type | Description |
|-----|-------------|------|-------------|
| Microsoft Graph | AuditLog.Read.All | Delegated | Read audit log data |
| Microsoft Graph | DeviceManagementApps.Read.All | Delegated | Read Microsoft Intune apps |
| Microsoft Graph | DeviceManagementConfiguration.Read.All | Delegated | Read Microsoft Intune Device Configuration and Policies |
| Microsoft Graph | DeviceManagementManagedDevices.Read.All | Delegated | Read Microsoft Intune devices |
| Microsoft Graph | DeviceManagementServiceConfig.Read.All | Delegated | Read Microsoft Intune configuration |
| Microsoft Graph | Directory.Read.All | Delegated | Read directory data |
| Microsoft Graph | IdentityRiskyUser.Read.All | Delegated | Read identity risky user information |
| Microsoft Graph | InformationProtectionPolicy.Read | Delegated | Read user sensitivity labels and label policies |
| Microsoft Graph | Policy.Read.All | Delegated | Read your organization's policies |
| Microsoft Graph | Reports.Read.All | Delegated | Read all usage reports |
| Microsoft Graph | SecurityEvents.Read.All | Delegated | Read your organization’s security events |
| Microsoft Graph | User.Read | Delegated |  Sign in and read user profile |
| Office 365 Management API | ActivityFeed.Read | Delegated | Read activity data for your organization |
| Office 365 Management API | ActivityFeed.ReadDlp | Delegated | Read DLP policy events including detected sensitive data |
| Office 365 Management API | ServiceHealth.Read | Delegated | Read service health information for your organization |

You can use the [Create-AzureAdApplication.ps1](scripts/Create-AzureAdApplication.ps1) to create and configure the application. The following is an example of how the script can be invoked

```powershell
PS C:\> .\Create-AzureAdApplication.ps1 -DisplayName 'Security and Management Insights'
```

If you are involved with the Cloud Solution Provider program, and you are looking to get insights for your customers, then you will want to create the Azure Active Directory application and configure it for pre-consent. This can be accomplished by running [Create-AzureAdApplication.ps1](scripts/Create-AzureAdApplication.ps1) as follows

```powershell
PS C:\> .\Create-AzureAdApplication.ps1 -ConfigurePreconsent:$true -DisplayName 'Security and Management Insights'
```

## Extension configuration

Prior to using the connector you will need to modify the client identifier used for authentication. Perform the following to update the value

1. Download the latest release available [here](https://github.com/microsoft/secmgmt-insights-connector/releases/download/1.0/secmgmt-insights-connector.zip)
2. Unblock the zip file and extract the contents
3. Replace the GUID in the *client_id* with the application identifier
4. Add the *client_id* file to the *SecMgmtInsights.zip* archive
5. Rename the *SecMgmtInsights.zip* file to *SecMgmtInsights.mez*
6. Copy the *SecMgmtInsights.mez* into the *[Documents]\Microsoft Power BI Desktop\Custom Connectors* directory


The extension provided through the [releases](https://github.com/microsoft/secmgmt-insights-connector/releases) page, is not signed because you will need to insert the client identifier for the Azure Active Directory application create using the above process. To perform this process start Power BI Desktop and then perform the following

1. Click file -> options and settings -> options
2. Click security under the global section
3. Click *(Not Recommended) Allow any extension to load without validation or warning*

Once you have finished testing you can sign the extension and reset this configuration. See [handling Power Query connector signing](https://docs.microsoft.com/power-query/HandlingConnectorSigning) for more information.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
