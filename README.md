# Security and Management Insights Connector

Microsoft 365 provides several advanced security and management features that empower you to improve your, or your customers, security posture. Knowing what features are configured and whether they adhere to the recommended configurations is challenging. Using this connector, you will be able gain insights what components have been adopted and how they are configured.  

To get started with this connect check out the [getting started](https://github.com/microsoft/secmgmt-insights-connector/wiki/getting-started) section of the wiki.

## Architecture

Most of the information required to understand what is configured and the current settings is obtained using Microsoft Graph. However, there is some data that is currently only available through Exchange Online PowerShell. Considering this two Power BI connectors were built for this solution. The `SecMgmtInsights` connector communicates directly with Microsoft Graph and can gather configuration and usage information. Through the `SecMgmtInsights.PowerShell` connector Office 365 ATP information from Exchange Online PowerShell is exposed through an Azure Functions app.

<p align="center">
    <img alt="solution architecture" src="docs/media/architecture.png" />
</p>

## Azure AD App Permissions

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

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
