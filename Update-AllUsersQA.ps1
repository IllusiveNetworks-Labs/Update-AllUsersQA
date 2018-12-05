param ([string]$answer = "")
Set-Variable QATemplate -option Constant -value "{{`"version`":1,`"questions`":[{{`"question`":`"{0}`",`"answer`":`"{1}`"}},{{`"question`":`"`",`"answer`":`"{1}`"}},{{`"question`":`"`",`"answer`":`"{1}`"}}]}}"
Set-Variable AdminQuestion -option Constant -value "This feature is disabled. To reset password, contact administrator."
Set-Variable writeAccess -option Constant -value 1
Set-Variable QASecretPrefix -option Constant -value "L`$_SQSA"
Set-Variable QASecretPrefixWithUnderScore -option Constant -value "L`$_SQSA_"
$functionsSignaturesToLoad = @"
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING
    {
      public UInt16 Length;
      public UInt16 MaximumLength;
      public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
      public int Length;
      public IntPtr RootDirectory;
      public LSA_UNICODE_STRING ObjectName;
      public uint Attributes;
      public IntPtr SecurityDescriptor;
      public IntPtr SecurityQualityOfService;
    }
    public enum LSA_AccessPolicy : long
    {
      POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
      POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
      POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
      POLICY_TRUST_ADMIN = 0x00000008L,
      POLICY_CREATE_ACCOUNT = 0x00000010L,
      POLICY_CREATE_SECRET = 0x00000020L,
      POLICY_CREATE_PRIVILEGE = 0x00000040L,
      POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
      POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
      POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
      POLICY_SERVER_ADMIN = 0x00000400L,
      POLICY_LOOKUP_NAMES = 0x00000800L,
      POLICY_NOTIFICATION = 0x00001000L
    }
	[DllImport("advapi32.dll")]
    public static extern uint LsaSetSecret(
            [In] IntPtr SecretHandle,
            [In] [Optional] ref LSA_UNICODE_STRING CurrentValue,
            [In] [Optional] ref LSA_UNICODE_STRING OldValue
    );
	[DllImport("advapi32.dll")]
        public static extern uint LsaOpenSecret(
            [In] IntPtr PolicyHandle,
            [In] ref LSA_UNICODE_STRING SecretName,
            [In] uint DesiredAccess,
            [Out] out IntPtr SecretHandle
    );
    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaOpenPolicy(
      ref LSA_UNICODE_STRING SystemName,
      ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
      uint DesiredAccess,
      out IntPtr PolicyHandle
    );

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaNtStatusToWinError(
      uint status
    );
    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaClose(
      IntPtr policyHandle
    );
"@

function Get-PolicyHandle {
    <#
    .SYNOPSIS
    Returns an LSA Policy handle which can be used by API's such as LsaOpenSecret and LsaSetSecret

    .NOTES
        Author: Nikhil "SamratAshok" Mittal as part of https://github.com/samratashok/nishang 

    #>
        
    # Attributes
    $objectAttributes = New-Object LSAUtil.LSAUtil+LSA_OBJECT_ATTRIBUTES
    $objectAttributes.Length = 0
    $objectAttributes.RootDirectory = [IntPtr]::Zero
    $objectAttributes.Attributes = 0
    $objectAttributes.SecurityDescriptor = [IntPtr]::Zero
    $objectAttributes.SecurityQualityOfService = [IntPtr]::Zero

    # localSystem
    $localsystem = New-Object LSAUtil.LSAUtil+LSA_UNICODE_STRING
    $localsystem.Buffer = [IntPtr]::Zero
    $localsystem.Length = 0
    $localsystem.MaximumLength = 0

    # Get LSA PolicyHandle
    $lsaPolicyHandle = [IntPtr]::Zero
    [LSAUtil.LSAUtil+LSA_AccessPolicy]$access = [LSAUtil.LSAUtil+LSA_AccessPolicy]::POLICY_GET_PRIVATE_INFORMATION
    $lsaOpenPolicyHandle = [LSAUtil.LSAUtil]::LSAOpenPolicy([ref]$localSystem, [ref]$objectAttributes, $access, [ref]$lsaPolicyHandle)
    if ($lsaOpenPolicyHandle -ne 0) {
        Write-Warning "lsaOpenPolicyHandle Windows Error Code: $lsaOpenPolicyHandle"
        Continue
    }
    return $lsaPolicyHandle
}

function Test-AdminPrivilege {

    <#
    .SYNOPSIS
        Check if running as administrator
    #>

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
    return ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $false)
        
}

function Update-UsersQA($targetQASecret, $answer) {
    <#
    .SYNOPSIS
    Locally update a Q&A secret acording to data provided in Answer argument

    .DESCRIPTION
    Formats a Q&A string according to the input provided in argument "Answer"

    .PARAMETER targetQASecret
    Specifies the name of the LSA secret that is to be updated. Keep in mind that it assumes this is an existing Q&A secret, so validation should be performed before calling!

    .PARAMETER answer
    Specifies the string that is to be set as the Answer for all 3 security questions. If not provided, user's Q&A will be disabled.
    #>

    Add-Type -MemberDefinition $functionsSignaturesToLoad -Name LSAUtil -Namespace LSAUtil

	# Create the Q&A string to be loaded to the user, in case "answer" argument was provided
	$questionsAndAnswersJson = [string]::Format($QATemplate, $AdminQuestion, $Answer)

    # Get policy handle required for APIs LSAOpenSecret and LSASetSecret
    $lsaPolicyHandle = Get-PolicyHandle

    # Secret Name
    $secretName = New-Object LSAUtil.LSAUtil+LSA_UNICODE_STRING
    $secretName.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($targetQASecret)
    $secretName.Length = [Uint16]($targetQASecret.Length * [System.Text.UnicodeEncoding]::CharSize)
    $secretName.MaximumLength = [Uint16](($targetQASecret.Length + 1) * [System.Text.UnicodeEncoding]::CharSize)
    
    # Retrieve a handle to the Q&A secret
    $secretHandle = [IntPtr]::Zero    
    $ntsResult = [LSAUtil.LSAUtil]::LsaOpenSecret($lsaPolicyHandle, [ref]$secretName, $writeAccess, [ref]$secretHandle)
	$lsaNtStatusToWinError = [LSAUtil.LSAUtil]::LsaNtStatusToWinError($ntsResult)
    
	# Null Old Value
    $NullPTR = [IntPtr]::Zero
    $nullUnicodeValue = New-Object LSAUtil.LSAUtil+LSA_UNICODE_STRING
    $nullUnicodeValue.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($NullPTR)
    $nullUnicodeValue.Length = [Uint16]($NullPTR.Length * [System.Text.UnicodeEncoding]::CharSize)
    $nullUnicodeValue.MaximumLength = [Uint16](($NullPTR.Length + 1) * [System.Text.UnicodeEncoding]::CharSize)
	
	if (!$answer) {
		# To disable the option to reset the passwrod, input null values to the security questions unicode strings
        $ntsResult = [LSAUtil.LSAUtil]::LsaSetSecret($secretHandle, [ref]$nullUnicodeValue, [ref]$nullUnicodeValue)
        Write-Output "Disabing security questions"
		return
    }
    
    # Create Lsa Unicode String with the new question and answers to be setted by LSASetSecret	
    $secretNewValue = New-Object LSAUtil.LSAUtil+LSA_UNICODE_STRING
    $secretNewValue.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($questionsAndAnswersJson)
    $secretNewValue.Length = [Uint16]($questionsAndAnswersJson.Length * [System.Text.UnicodeEncoding]::CharSize)
    $secretNewValue.MaximumLength = [Uint16](($questionsAndAnswersJson.Length + 1) * [System.Text.UnicodeEncoding]::CharSize)

	$ntsResult = [LSAUtil.LSAUtil]::LsaSetSecret($secretHandle, [ref]$secretNewValue, [ref]$nullUnicodeValue)
    Write-Output "Changing security Answer to s:" $answer
   
    $lsaNtStatusToWinError = [LSAUtil.LSAUtil]::LsaNtStatusToWinError($ntsResult)
    if ($lsaNtStatusToWinError -ne 0) {
        Write-Warning "LsaSetSecret: $lsaNtStatusToWinError"
    }
    else {
        Write-Output "Success!"
    }

    [LSAUtil.LSAUtil]::LsaClose($lsaPolicyHandle)
}

function Update-AllUsersQA($answer){
    
    <#
	.SYNOPSIS
	For each local user in the machine, update or disable the Q&A feature

	.DESCRIPTION
	Itterates of exisiting secrets in the registry.
	For each secret which is a Q&A, update or disable according to provided argumentss.

	.PARAMETER Answer
	Specifies the string that is to be set as the Answer for all 3 security questions. If not provided, user's Q&A will be disabled.

	.EXAMPLE
	C:\PS> Update-AllUsersQA -answer "MySecretAdminPassword"

	.EXAMPLE
	C:\PS> Update-AllUsersQA
	#>

    $IsAdmin = Test-AdminPrivilege
	if (! $IsAdmin){
		Write-Warning "User is not an administrator"
	}

    # Find all existing LSA secrets inside the Secrets registry key
    $LSASecretsList = (Split-Path (Get-ChildItem HKLM:\SECURITY\Policy\Secrets) -Leaf)
        
    foreach ($secretKeyName in $LSASecretsList) {
        
        # Skip LSA Secrets which are not Security Questions and Answers
        if (! $secretKeyName.StartsWith($QASecretPrefix)) {
            continue
        }
		
        # Extract the user's SID from the secret name and translates into username for console print only.
		$userSID = $secretKeyName.Replace($QASecretPrefixWithUnderScore, "")
        $objSID = New-Object System.Security.Principal.SecurityIdentifier $userSID
        $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
        Write-Output "Updating Security Q&A for:" $objUser.Value

		# Update user's Q&A
        Update-UsersQA $secretKeyName $answer
    }
}

Update-AllUsersQA $answer