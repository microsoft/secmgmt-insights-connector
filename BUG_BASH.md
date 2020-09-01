# Security and Management Insights Connector

As enhancements are made to the connector and new features added it can be difficult to test for every scenario. While we strive to ensure the solution is free of any complications and issues, there is a chance something might make it through testing. This means there is a possbility that the connector might not behave as expected. With this in mind from time to time we will have a virtual bug bash where everyone is encouraged to create bugs for any unexpected behavior. Often these events will happen when significant changes are made to the connector.    

## Bug Bash August 2020

Starting on August 1, 2020 will be starting our first bug bash for the connector. During this time we will be hunting for bugs, issues, and unexpected behavior with the recent change to dynamically detect the table schema. It is important to note that these changes have not been officially released, so anyone who wants to test this new feature will need to compile the module. You can compile the module by following the process below

1. Install the [Power Query SDK](https://marketplace.visualstudio.com/items?itemName=Dakahn.PowerQuerySDK) extension for Visual Studio
2. Clone this repository and then open the *SecMgmt-Insights-Connector.sln* solution
3. Replace the GUID in the *client_id* with the application identifier
4. Build the solution and then copy *src\secmgmt-insights-connector\artifacts\SecMgmtInsights.mez* to the *[Documents]\Microsoft Power BI Desktop\Custom Connectors* directory

After performing the above process it is recommend that you restart Power BI Desktop if you had it open. Now you will be able to test all the latest features that have been recently added to the module. 
 
 During this time there were a number of general updates, fixes, and new features added to the connector. The following sections provide a snapshot of what was accomplished during the August 2020 event

### Breaking Changes

- Query folding is one of the new features, and when it was implemented the way functions are called needed to be changed.

    ```powerquery-m
    // Old way to invoke 
    SecMgmtInsights.ManagedDevices()

    // New way to invoke 
    source = SecMgmtInsights.Contents("Partner"),
    managedDevices = source{[Name="ManagedDevices"]}[Data]
    ```

- You will need to add the `IdentityRiskEvent.Read.All` permission to the Azure AD application registration to utilize the `RiskDetections` function

### General Updates

- Performance has been improved by only selecting the fields, from the API, that are needed ([#76](https://github.com/microsoft/secmgmt-insights-connector/issues/76))
- The device actions function has been refactored to optimize the request

### Fixes

- Access tokens should no longer expire ([#92](https://github.com/microsoft/secmgmt-insights-connector/issues/92))
- Column types are no longer lost by the connector when it expands tables ([#70](https://github.com/microsoft/secmgmt-insights-connector/issues/70))
- Device actions will now show configuration actions as expected ([#97](https://github.com/microsoft/secmgmt-insights-connector/issues/97]))
- Device compliance policies functions have been updated to account for the new dynamic schema feature ([#79](https://github.com/microsoft/secmgmt-insights-connector/issues/79))
- Device configuration profiles functions have been updated and renamed to account for the new dynamic schema feature ([#82](https://github.com/microsoft/secmgmt-insights-connector/issues/82))
- Functions that require a dependency (e.g. Microsoft Intune) will now return null if the customer has not fulfilled the dependency. Also, additional diagnostics have been added to provide insight to when this is happening ([#88](https://github.com/microsoft/secmgmt-insights-connector/issues/88) [#90](https://github.com/microsoft/secmgmt-insights-connector/issues/90) [#91](https://github.com/microsoft/secmgmt-insights-connector/issues/91))
- Get data feature now loads each functions without error, if at least once tenant in the request has data ([#89](https://github.com/microsoft/secmgmt-insights-connector/issues/89))
- Errors are no longer replaced by null ([#67](https://github.com/microsoft/secmgmt-insights-connector/issues/67))
- Network requests are no longer being duplicated ([#96](https://github.com/microsoft/secmgmt-insights-connector/issues/96))
- Mobile applications function now load data as expected ([#77](https://github.com/microsoft/secmgmt-insights-connector/issues/77))
- Office 365 usage reports now loads with a dynamic schema ([#94](https://github.com/microsoft/secmgmt-insights-connector/issues/94))
- Risk detection information for users is now available ([#72](https://github.com/microsoft/secmgmt-insights-connector/issues/72))
- Security baseline setting states function no longer encounters an error if no customers are utilizing security baselines ([#106](https://github.com/microsoft/secmgmt-insights-connector/issues/106))
- Service status information now loads with a dynamic schema ([#84](https://github.com/microsoft/secmgmt-insights-connector/issues/84))
- Software update summary information now loads as expected ([#104](https://github.com/microsoft/secmgmt-insights-connector/issues/104))
- Subscribed SKUs function now loads correctly with a dynamic schema ([#85](https://github.com/microsoft/secmgmt-insights-connector/issues/85))
- When the API only returns an enumeration, the response will now load correctly ([#103](https://github.com/microsoft/secmgmt-insights-connector/issues/103))
- Windows Autopilot settings now load as expected ([#101](https://github.com/microsoft/secmgmt-insights-connector/issues/101))

### New Features

- License detail for each user is now available through the `LicenseDetails` function
- Query folding support has been enabled ([#65](https://github.com/microsoft/secmgmt-insights-connector/issues/65))