<#
    .SYNOPSIS
        This script will create the require Azure AD application.
    .EXAMPLE
        .\Create-AzureADApplication.ps1 -DisplayName "Security and Management Insights"

        .\Create-AzureADApplication.ps1 -ConfigurePreconsent -DisplayName "Security and Management Insights" -TenantId eb210c1e-b697-4c06-b4e3-8b104c226b9a

        .\Create-AzureADApplication.ps1 -ConfigurePreconsent -DisplayName "Security and Management Insights" -TenantId tenant01.onmicrosoft.com
    .PARAMETER ConfigurePreconsent
        Flag indicating whether or not the Azure AD application should be configured for preconsent.
    .PARAMETER DisplayName
        Display name for the Azure AD application that will be created.
    .PARAMETER TenantId
        [OPTIONAL] The domain or tenant identifier for the Azure AD tenant that should be utilized to create the various resources.
#>

Param
(
    [Parameter(Mandatory = $true)]
    [switch]$ConfigurePreconsent,
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,
    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

$ErrorActionPreference = "Stop"

# Check if the Azure AD PowerShell module has already been loaded.
if ( ! ( Get-Module AzureAD ) ) {
    # Check if the Azure AD PowerShell module is installed.
    if ( Get-Module -ListAvailable -Name AzureAD ) {
        # The Azure AD PowerShell module is not load and it is installed. This module
        # must be loaded for other operations performed by this script.
        Write-Host -ForegroundColor Green "Loading the Azure AD PowerShell module..."
        Import-Module AzureAD
    } else {
        Install-Module AzureAD
    }
}

try {
    Write-Host -ForegroundColor Green "When prompted please enter the appropriate credentials..."

    if([string]::IsNullOrEmpty($TenantId)) {
        Connect-AzureAD | Out-Null

        $TenantId = $(Get-AzureADTenantDetail).ObjectId
    } else {
        Connect-AzureAD -TenantId $TenantId | Out-Null
    }
} catch [Microsoft.Azure.Common.Authentication.AadAuthenticationCanceledException] {
    # The authentication attempt was canceled by the end-user. Execution of the script should be halted.
    Write-Host -ForegroundColor Yellow "The authentication attempt was canceled. Execution of the script will be halted..."
    Exit
} catch {
    # An unexpected error has occurred. The end-user should be notified so that the appropriate action can be taken.
    Write-Error "An unexpected error has occurred. Please review the following error message and try again." `
        "$($Error[0].Exception)"
}

$graphAppAccess = [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]@{
    ResourceAppId = "00000003-0000-0000-c000-000000000000";
    ResourceAccess =
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "4edf5f54-4666-44af-9de9-0144fb4b6e8c";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "f1493658-876a-4c87-8fa7-edb559b3476a";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "314874da-47d6-4978-88dc-cf0d37f0bb82";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "8696daa5-bce5-4b2e-83f9-51b6defc4e1e";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "06da0dbc-49e2-44d2-8312-53f166ab848a";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "d04bb851-cb7c-4146-97c7-ca3e71baf56c";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "4ad84827-5578-4e18-ad7a-86530b12f884";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "572fea84-0151-49b2-9301-11cb16974376";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "02e97553-ed7b-43d0-ab3c-f8bace0d040c";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "64733abd-851e-478a-bffb-e47a14b18235";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d";
            Type = "Scope"}
}

$oscAppAccess = [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]@{
    ResourceAppId = "c5393580-f805-4401-95e8-94b7a6ef2fc2";
    ResourceAccess =
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "594c1fb6-4f81-4475-ae41-0c394909246c";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "4807a72c-ad38-4250-94c9-4eabfe26cd55";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "e2cea78f-e743-4d8f-a16a-75b629a038ae";
            Type = "Scope"}
}

$SessionInfo = Get-AzureADCurrentSessionInfo

Write-Host -ForegroundColor Green "Creating the Azure AD application and related resources..."

$app = New-AzureADApplication -AvailableToOtherTenants $true -DisplayName $DisplayName -RequiredResourceAccess $graphAppAccess, $oscAppAccess -PublicClient:$true -ReplyUrls "https://oauth.powerbi.com/views/oauthredirect.html"

if($ConfigurePreconsent) {
    $adminAgentsGroup = Get-AzureADGroup -Filter "DisplayName eq 'AdminAgents'"
    Add-AzureADGroupMember -ObjectId $adminAgentsGroup.ObjectId -RefObjectId $spn.ObjectId
}

Write-Host "ApplicationId       = $($app.AppId)"
