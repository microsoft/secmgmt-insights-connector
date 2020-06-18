using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

$tenant = $Request.Params.Tenant

if ($null -eq $tenantId) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Body = "The tenant must be specified."
    })

    exit
}

$refreshToken = ''
$upn = ''

$token = New-PartnerAccessToken -Module ExchangeOnline -RefreshToken $refreshToken -Tenant $tenant

$tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)

$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid?DelegatedOrg=$($tenant)&BasicAuthToOAuthConversion=true" -Credential $credential -Authentication Basic -AllowRedirection
$data = $null

if($session)
{
    Import-PSSession $session -AllowClobber | Out-Null

    $data = New-Object System.Collections.Hashtable   

    try 
    {
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-30)

        $data['AdminAuditLogConfig'] = Get-AdminAuditLogConfig
        $data['AntiPhishPolicy'] = @(Get-AntiPhishPolicy) 
        $data['AtpPolicyForO365'] = Get-AtpPolicyForO365
        $data['MailDetailAtpReport'] = @(Get-MailDetailATPReport -StartDate $startDate.ToString('MM/dd/yyyy') -EndDate $endDate.ToString('MM/dd/yyyy'))
        $data['MailTrafficAtpReport'] = @(Get-MailTrafficATPReport -StartDate $startDate.ToString('MM/dd/yyyy') -EndDate $endDate.ToString('MM/dd/yyyy'))
        $data['MalwareFilterPolicy'] = @(Get-MalwareFilterPolicy)
    } 
    finally 
    {
        Remove-PSSession $session
    }
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = ConvertTo-Json $data
})
