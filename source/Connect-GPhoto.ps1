[CmdletBinding()]
Param (
    $GoogleApiJSONCredentialsFilePath = 'C:\temp\creds\google-api\client_secret_898082732201-dpic0sj9s55mud5m711sul0itb63ap89.apps.googleusercontent.com.json'
)

# API Console
# https://console.cloud.google.com/apis/dashboard?authuser=1&project=organizer-1541878040962&pli=1

Begin {
    Write-Host "START" -ForegroundColor Blue
    function Get-GoogleApiCredentials
    {
        Param (
            $JsonCredentialsFilePath
        )

        if(Test-Path -Path $JsonCredentialsFilePath)
        {
            Write-Host "JSON file found"

            $jsonCreds = Get-Content -Path $JsonCredentialsFilePath
        
            $credsJson = $jsonCreds | ConvertFrom-Json

            $creds = $credsJson.web

            $credsObject = [PSCustomObject]@{
                ClientId = $creds.client_id
                ProjectId = $creds.project_id
                AuthUri = $creds.auth_uri
                TokenUri = $creds.token_uri
                AuthProdviderUrl = $creds.auth_provider_x509_cert_url
                ClientSecret = $creds.client_secret
                RedirectUris = $creds.redirect_uris
                JavascriptOrigins = $creds.javascript_origins
            }
        
            return $credsObject
        }
        else
        {
            throw "JSON file not found: $($JsonCredentialsFilePath)"
        }
    }
    
    function asdf {
        # https://lazyadmin.nl/it/connect-to-google-api-with-powershell/
    
        # Replace <CLIENT_ID_HERE> with your client id
        "https://accounts.google.com/o/oauth2/auth?redirect_uri=<CLIENT_ID_HERE>&scope=https://www.googleapis.com/auth/analytics.readonly&approval_prompt=force&access_type=offline"
    
        # In the comments below, Phani mentioned that the above url is wrong and should be:
        "https://accounts.google.com/o/oauth2/auth?client_id=<replacemewithclientid>&scope=https://www.googleapis.com/auth/analytics.readonly&response_type=code&redirect_uri=<replacemewithredirecturi>&access_type=offline&approval_prompt=force"
    
        # I have no time to test it, but if you get an error with the original URL, then check the one mentioned by Phani.
    
    
        $requestUri = "https://www.googleapis.com/oauth2/v4/token"
        $body = @{
          code=<authcode>;
          client_id=<clientId>;
          client_secret=<clientSecret>;
          redirect_uri=<redirectUrl>;
          grant_type="authorization_code"; # Fixed value
        };
        $tokens = Invoke-RestMethod -Uri $requestUri -Method POST -Body $body;
        # Store refreshToken
        Set-Content $PSScriptRoot"\refreshToken.txt" $tokens.refresh_token
        # Store accessToken
        Set-Content $PSScriptRoot"\accessToken.txt" $tokens.access_token
    }
}

Process {
    Write-Host "----" -ForegroundColor Blue

    $creds = (Get-GoogleApiCredentials -JsonCredentialsFilePath $GoogleApiJSONCredentialsFilePath)

    Write-Host "-ClientId $($creds.ClientId)"
    Write-Host "-ProjectId $($creds.ProjectId)"
    Write-Host "-AuthUri$($creds.AuthUri)"
    Write-Host "-TokenUri $($creds.TokenUri)"
    Write-Host "-AuthProdviderUrl $($creds.AuthProdviderUrl)"
    Write-Host "-ClientSecret $($creds.ClientSecret)"
    Write-Host "-RedirectUris $($creds.RedirectUris)"
    Write-Host "-JavascriptOrigins $($creds.JavascriptOrigins)"

    Write-Host "----" -ForegroundColor Blue
}

End {
    Write-Host "DONE" -ForegroundColor Blue
}