# Security and Management Insights Connector

As enhancements are made to the connector and new features added it can be difficult to test for every scenario. While we strive to ensure the solution is free of any complications and issues, there is a chance something might make it through testing. This means there is a possbility that the connector might not behave as expected. With this in mind from time to time we will have a virtual bug bash where everyone is encouraged to create bugs for any unexpected behavior. Often these events will happen when significant changes are made to the connector.    

## Bug Bash August 2020

Starting on August 1, 2020 will be starting our first bug bash for the connector. During this time we will be hunting for bugs, issues, and unexpected behavior with the recent change to dynamically detect the table schema. It is important to note that these changes have not been officially released, so anyone who wants to test this new feature will need to compile the module. You can compile the module by following the process below

1. Install the [Power Query SDK](https://marketplace.visualstudio.com/items?itemName=Dakahn.PowerQuerySDK) extension for Visual Studio
2. Clone this repository and then open the *SecMgmt-Insights-Connector.sln* solution
3. Replace the GUID in the *client_id* with the application identifier
4. Build the solution and then copy *src\secmgmt-insights-connector\artifacts\SecMgmtInsights.mez* to the *[Documents]\Microsoft Power BI Desktop\Custom Connectors* directory

After performing the above process it is recommend that you restart Power BI Desktop if you had it open. Now you will be able to test all the latest features that have been recently added to the module. 
 