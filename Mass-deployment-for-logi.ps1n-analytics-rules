param (
    [string]$WorkspaceId = "98286be1-b72f-44f4-bde5-41729c85e67f",
    [string]$ResourceGroup = "sentinel-rg",
    [string]$SubscriptionId = "24f0dbbe-4816-46ec-a042-b62301e6eac1"
)

Connect-AzAccount
Select-AzSubscription -SubscriptionId $SubscriptionId

function New-SentinelRule {
    param (
        [string]$Name,
        [string]$Query,
        [string]$DisplayName,
        [string[]]$Tactics,
        [string]$Description
    )

    $ruleId = (New-Guid).Guid
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceId/providers/Microsoft.SecurityInsights/alertRules/$ruleId?api-version=2023-11-01-preview"

    $body = @{
        properties = @{
            displayName = $DisplayName
            description = $Description
            severity = "Medium"
            enabled = $true
            alertRuleTemplateName = ""
            query = $Query
            queryFrequency = "PT5M"
            queryPeriod = "PT5M"
            triggerOperator = "GreaterThan"
            triggerThreshold = 0
            tactics = $Tactics
            alertDetailsOverride = @{
                alertDescriptionFormat = $Description
            }
            incidentConfiguration = @{
                createIncident = "true"
                groupingConfiguration = @{
                    enabled = $true
                    regroupWithinDuration = "PT5M"
                    lookbackDuration = "PT1H"
                    matchingMethod = "Selected"
                    groupByEntities = @("Account", "IP", "Host")
                    reopenClosedIncident = $true
                }
            }
            kind = "Scheduled"
        }
        location = "Global"
    }

    Invoke-RestMethod -Method PUT -Uri $uri -Headers @{
        Authorization = "Bearer $(Get-AzAccessToken -ResourceUrl https://management.azure.com/ | Select-Object -ExpandProperty Token)"
    } -Body ($body | ConvertTo-Json -Depth 10) -ContentType "application/json"
}

# ----------- Define Rule Templates -----------

$rules = @(
    @{
        Name = "SuspiciousIPLogin"
        Query = @"
SigninLogs
| where IPAddress in~ ('<list_of_suspicious_ips>')
| summarize count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
"@
        DisplayName = "Suspicious IP Login"
        Tactics = @("InitialAccess")
        Description = "Logins from suspicious IP addresses."
    },
    @{
        Name = "ExcessiveAdminLogin"
        Query = @"
SigninLogs
| where UserType == 'Member' and AccountType == 'Admin'
| summarize loginCount = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where loginCount > 5
"@
        DisplayName = "Excessive Admin Logins"
        Tactics = @("Persistence", "PrivilegeEscalation")
        Description = "Multiple admin logins detected in short time."
    },
    @{
        Name = "NonCompliantDeviceLogin"
        Query = @"
DeviceEvents
| where ComplianceState !~ 'Compliant'
| join kind=inner (SigninLogs) on DeviceId
"@
        DisplayName = "Non-Compliant Device Logins"
        Tactics = @("DefenseEvasion")
        Description = "Users logging in from non-compliant devices."
    },
    @{
        Name = "UnusualUserLogin"
        Query = @"
SigninLogs
| summarize Count = count() by UserPrincipalName, Location, bin(TimeGenerated, 1d)
| join kind=inner (
    SigninLogs
    | summarize Current = count() by UserPrincipalName, Location, bin(TimeGenerated, 5m)
) on UserPrincipalName
| where Current > Count * 2
"@
        DisplayName = "Unusual User Login"
        Tactics = @("Reconnaissance", "InitialAccess")
        Description = "Unusual login behavior detected for user."
    },
    @{
        Name = "PIMActivation"
        Query = @"
AuditLogs
| where ActivityDisplayName contains 'Activate eligible role'
"@
        DisplayName = "PIM Activation Detected"
        Tactics = @("PrivilegeEscalation")
        Description = "PIM role activation detected."
    },
    @{
        Name = "TorLoginDetection"
        Query = @"
SigninLogs
| where IPAddress in~ ('Tor Exit Nodes - Set 1')
"@
        DisplayName = "TOR Login Detection"
        Tactics = @("DefenseEvasion", "InitialAccess")
        Description = "Login detected from known TOR network exit node."
    }
)

# ----------- Deploy All Rules -----------
foreach ($rule in $rules) {
    Write-Host "Deploying rule: $($rule.DisplayName)..."
    New-SentinelRule @rule
}
