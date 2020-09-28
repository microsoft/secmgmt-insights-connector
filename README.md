# Security and Management Insights Connector

Microsoft 365 provides several advanced security and management features that empower you to improve your, or your customers, security posture. Knowing what features are configured and whether they adhere to the recommended configurations is challenging. Using this connector, you will be able gain insights what components have been adopted and how they are configured.  

## Bug Bash

As enhancements are made to the connector and new features added it can be difficult to test for every scenario. While we strive to ensure the solution is free of any complications and issues, there is a chance something might make it through testing. This means there is a possbility that the connector might not behave as expected. With this in mind from time to time we will have a virtual bug bash where everyone is encouraged to create bugs for any unexpected behavior. Often these events will happen when significant changes are made to the connector. See our [bug bash](BUG_BASH.md) guide for more details.  

## Getting Started

Prior to utilizing this connector to gain insights from your, or your customers, environment there are some required actions that need to be taken. The remaining sections of this article will guide you through fulfilling the prerequisites, installing the connector, and how to leverage on the templates. If you have any questions about this process please open an [issue](https://github.com/microsoft/secmgmt-insights-connector/issues/new/choose) for help.

### Prerequisites

If you do not already have Power BI Desktop installed, then [download](https://powerbi.microsoft.com/downloads/) and install it. Once installed you will want to perform the perform the following

1. Start Power BI Desktop on the device where you plan to install the connector
2. Click file -> options and settings -> options
3. Click security under the global section
4. Click (Not Recommended) Allow any extension to load without validation or warning

> This step is required because by default the connector that will be installed is not digitally signed. It is not signed because during the installation process an application identifier value will be injected that is unique for your environment. See [handling Power Query Connector signing](https://docs.microsoft.com/power-query/HandlingConnectorSigning) for details on the signing the connector if you are interested.

### Installation

To simplify the process of creating and configuring the dependent resources for the connect, the [Install-SecMgmtInsightsConnector](https://github.com/microsoft/secmgmt-open-powershell/blob/master/docs/help/Install-SecMgmtInsightsConnector.md) cmdlet has been added to the [Security and Management Open PowerShell module](https://www.powershellgallery.com/packages/SecMgmt). You can leverage the following PowerShell to install the connector on the device invoking the command

```powershell
Install-Module SecMgmt

# When prompt for credentials you will need to specify an account that has the ability to create an Azure Active Directory application.
Connect-SecMgmtAccount

# Use the following if you are planning to gain insights for a single tenant.
Install-SecMgmtInsightsConnector -ApplicationDisplayName 'Security and Management Insights'

# Use the following line if you plan to use the connector to gain insights for customers you have through the Cloud Solution Provider program.
Install-SecMgmtInsightsConnector -ApplicationDisplayName 'Security and Management Insights' -ConfigurePreconsent:$true
```

> When you invoke the above a new Azure Active Directory application will be created, for use with the connector. Then the latest version of the connector is downloaded, configured, and installed on the local device.

### Template

Once the prerequisites have been fulfilled and the connector has be installed, you can start building reports that incorporate functionality from the connector. You can start from scratch or leverage one of the following templates

| Name | Description |
|------|-------------|
| [Customer template](https://github.com/microsoft/secmgmt-insights-connector/raw/master/templates/secmgmt-insights-customer.pbit) |Template that is intended to be used if you are looking to get insights for your own tenant |
| [Partner template](https://github.com/microsoft/secmgmt-insights-connector/raw/master/templates/secmgmt-insights-partner.pbit) | Template that is intended to be used by partners to gain insights for their customers |

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
