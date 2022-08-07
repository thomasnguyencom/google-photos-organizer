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
            $JsonCredentialsFilePath,
            [switch] $Output
        )

        if(Test-Path -Path $JsonCredentialsFilePath)
        {
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

            if($Output)
            {
                Write-Host "JSON file found"
                Write-Host "  ClientId $($credsObject.ClientId)"
                Write-Host "  ProjectId $($credsObject.ProjectId)"
                Write-Host "  AuthUri$($credsObject.AuthUri)"
                Write-Host "  TokenUri $($credsObject.TokenUri)"
                Write-Host "  AuthProdviderUrl $($credsObject.AuthProdviderUrl)"
                Write-Host "  ClientSecret $($credsObject.ClientSecret)"
                Write-Host "  RedirectUris $($credsObject.RedirectUris)"
                Write-Host "  JavascriptOrigins $($credsObject.JavascriptOrigins)"
            }
        
            return $credsObject
        }
        else
        {
            throw "JSON file not found: $($JsonCredentialsFilePath)"
        }
    }
    
    function Get-GoogleAuthCode {
        Param (
            $Creds,
            [switch] $Output
        )
        # https://lazyadmin.nl/it/connect-to-google-api-with-powershell/
    
        # Replace <CLIENT_ID_HERE> with your client id
        #"https://accounts.google.com/o/oauth2/auth?redirect_uri=$($Creds.ClientId)&scope=https://www.googleapis.com/auth/analytics.readonly&approval_prompt=force&access_type=offline"
    
        # In the comments below, Phani mentioned that the above url is wrong and should be:
        $url = "https://accounts.google.com/o/oauth2/auth?client_id=$($Creds.ClientId)&scope=https://www.googleapis.com/auth/analytics.readonly&response_type=code&redirect_uri=$($Creds.RedirectUris)&access_type=offline&approval_prompt=force"
    
        Write-Host "$($url)"

        # I have no time to test it, but if you get an error with the original URL, then check the one mentioned by Phani.

        $url = Read-Host -Prompt "Open Browser to URL above and copy/paste the returned URL after logging in."

        $authCode = $url.Replace('http://localhost/auth/google/callback?code=', '').Replace('&scope=https://www.googleapis.com/auth/analytics.readonly', '')

        if($Output) {
            Write-Host "URL: $($url)"
            Write-Host "code: $($authCode)"
        }

        return $authCode
    }
    
    function Connect-GooglePhotosApi {
        Param (
            $Creds,
            [switch] $Output
        )

        $authCode = Get-GoogleAuthCode -Creds $Creds -Output:$Output
    
        $requestUri = "https://www.googleapis.com/oauth2/v4/token"
        $body = @{
            code = $authCode;
            client_id = $Creds.ClientId;
            client_secret = $Creds.ClientSecret;
            redirect_uri = $Creds.RedirectUris;
            grant_type = "authorization_code"; # Fixed value
        };

        $body

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

    $authCode = Connect-GooglePhotosApi -Creds $creds -AuthCode $authCode -Output

    Write-Host "----" -ForegroundColor Blue
}

End {
    Write-Host "DONE" -ForegroundColor Blue
}