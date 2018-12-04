########################################################################################################################################
#<Description>                                                                                                                         #
#This script will do the following things:                                                                                             #
#>Get input from XML and register folders and fiilter files.                                                                           #
#>Perform log search for event id 8005, source EventTracker for specified duration.                                                    #
#>Extract useful fields from logs and get VirusTotal score for all hashes.                                                             #
#>Generate consolidated report of output with scores.                                                                                  #
#>Truncate temporary/old files.                                                                                                        #
#                                                                                                                                      #
#<Input>                                                                                                                               #
#>Run .\Input\Integrator_VT.ps1, provide VT API Key and evaluation duration.                                                           #
#>Add process names and hashes to to filtered in .\Filters\Filter_File.txt and .\Filters\Filter_Hash.txt                               #
#                                                                                                                                      #
#<Output>                                                                                                                              #
#>HTML and CSV reports will be generated in .\Output folder.                                                                           #
#                                                                                                                                      #
#CreatedBy:kumarnitesh@eventtracker.com                                                                                                #
#Created On:04/12/18                                                                                                                   #
########################################################################################################################################
########################################################################################################################################

#Assign folder paths#
$etpath = (Get-ItemProperty -Path 'registry::hklm\SOFTWARE\Wow6432Node\Prism Microsystems\EventTracker\Manager').INSTALLPATH
$scriptdir = Split-Path $SCRIPT:MyInvocation.MyCommand.Path -parent
$inputpath = "$scriptdir\Input"
$outputpath = "$scriptdir\Output"
$temppath = "$scriptdir\Temp"
$filterpath = "$scriptdir\Filters"
$backuppath = "$scriptdir\Backup"
########################################################################################################################################
#Get input from config and filter files#
$input = Import-Clixml -Path "$inputpath\Conf.xml"
  $PW1 = $input.SQLPW | ConvertTo-SecureString -AsPlainText -Force 
  $PW2 = $input.SMTPPW | ConvertTo-SecureString -AsPlainText -Force
$NState = $input.NINEX
$EState = $input.EIGHTX
$ETDBState = $input.ETDB
$ETSState = $input.ETSEARCH
$SQLAState = $input.SQLAUTH
$WINAState = $input.WAUTH
$SMTPEState = $input.SMTEN
$SMTPAState = $input.SMTPAU
$WLState = $input.WLHASH
$SFREQ = ("-{0}" -f $input.SFREQ).Replace("Hour","").Replace("Hours","")
$VTSCORE = $input.VTSCORE
$VTAPI = $input.VTAPI
$SQLUN = $input.SQLUN
$SQLPW =  New-Object System.Management.Automation.PSCredential -ArgumentList $env:USERNAME, $PW1
$SQLIN = $input.SQLINS
$SMTPIP = $input.SMTPIP
$SMTPPP = $input.SMTPPO
$SMTPF = $input.SMTPFROM
$SMTPT = $input.SMTPTO
$SMTPUN = $input.SMTPUN
$SMTPPW = New-Object System.Management.Automation.PSCredential -ArgumentList $env:USERNAME, $PW2
$CNAME = $input.CNAME
$Subject = "Hourly VirusTotal Report({0})" -f $CNAME

$w1 = Get-Content -Path "$filterpath\Filter_File.txt"
[array]$we1 = $w1 -split "\n"
$w2 = Get-Content -Path "$filterpath\Filter_Hash.txt"
[array]$we2 = $w2 -split "\n"
########################################################################################################################################

#Get score and permalink for queried hash value from VirusTotal#
Function Get-VTReport {
    [CmdletBinding()]
    Param( 
    [String] $VTApiKey,
    [Parameter(ParameterSetName="hash", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/report'
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = @{}

        switch ($PSCmdlet.ParameterSetName) {
        "hash" {            
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $hash; apikey = $VTApiKey}
            }
        }        

       $q = (Invoke-RestMethod -Method $method -Uri $u -Body $body)
       Start-Sleep -Seconds 15
       If($q.response_code -eq 1){
	$obj = New-Object PSObject -Property @{
		"md5" = $q.resource;
		"score" = ("{0}/{1}" -f $q.positives,$q.total);
        "details" = $q.permalink
	}}
elseIf($q.response_code -eq 0){
	$obj = New-Object PSObject -Property @{
		"md5" = $q.resource;
		"score" = "NotFound";
        "details" = 'N/A'
	}}
Write-Output $obj
}
       
}
########################################################################################################################################

 if ($ETSState -eq "TRUE"){
 #Load Dlls for EventTracker search and Microsoft mdb#
Function Invoke-MDBSQLCMD ($mdblocation,$sqlquery){
$dsn = "Provider=Microsoft.Jet.OLEDB.4.0; Data Source=$mdblocation;"
$objConn = New-Object System.Data.OleDb.OleDbConnection $dsn
$objCmd  = New-Object System.Data.OleDb.OleDbCommand $sqlquery,$objConn
$objConn.Open()
$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $objCmd
$dataset = New-Object System.Data.DataSet
[void] $adapter.Fill($dataSet)
$objConn.Close()
$dataSet.Tables | Select-Object -Expand Rows
$dataSet = $null
$adapter = $null
$objCmd  = $null
$objConn = $null
}
    if ($EState -eq "TRUE"){
    $logprocessdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\Prism.LogSearchProcess.dll")
    $logparmeterdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\Prism.LogSearchParameter.dll")
    $datapersist = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\Prism.Report.DataPersistance.dll")
#Perform search for event id 8005 and source Eventtracker 8#
    $logparmeter01 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logparmeter02 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logcerteria = New-Object Prism.LogSearchParameter.LogSearchParameter
$searchconfig = New-Object Prism.LogSearchParameter.SearchConfig
$searchconfig.IsParseTokens = "False"
$logcerteria.FromDate = (get-date).AddHours($SFREQ)
$logcerteria.ToDate = (get-date)
#$logcerteria.SystemGroups = "All Windows Systems"
$logcerteria.SystemIncludeType = 1
$logparmeter01.ParameterId = 0
$logparmeter01.Operator = 1
$logparmeter01.ParameterName = "event id"
$logparmeter01.ParameterType = 1
$logparmeter01.SearchValue = "8005"
$logparmeter02.ParameterId = 0
$logparmeter02.Operator = 1
$logparmeter02.ParameterName = "source"
$logparmeter02.ParameterType = 1
$logparmeter02.SearchValue = "EventTracker"
$logcerteria.AdvancedParameter = $logparmeter01
$logcerteria.AdvancedParameter += $logparmeter02
$logticks = (get-date).Ticks
$mdbname1 = "VTAnalysis_{0}" -f $logticks
$param = new-object Prism.LogSearchParameter.LogSearchParameterContext ("$mdbname1")
$param.Update($logcerteria)
$search = new-object Prism.LogSearchProcess.LogSearchProcessing ("$mdbname1")
$search.StartProcessing(4) | Out-Null
########################################################################################################################################

#Extract useful values from event_description and store in Temp folder#
$regex2 = '(?s)Hash\:\s+(.*?)System\:\s+(.*?)Time\:\s+(.*?)Image File Name\:\s+(.*?)User\:\s+(.*?)File Name\:.*?Creator Image File Name\:\s+(.*?)File Version\:'
Filter Extract2 {
"$_.event description" -match $regex2 > $null
[pscustomobject]@{  
FileHash = ($Matches[1]).trim()
HostName = ($Matches[2]).trim()
EventTime = ($Matches[3]).trim()
FileName = ($Matches[4]).trim()
UserName = ($Matches[5]).trim()
CreatorFileName = ($Matches[6]).trim()
}}

$mdblocation1 = "$etpath\Reports\LogSearch\$mdbname1.mdb"
$query1 = ((Invoke-MDBSQLCMD $mdblocation1 -sqlquery "Select event description from Events" | Extract2) | Where-Object {($we1 -notcontains $_.FileName) -and ($we2 -notcontains $_.FileHash)})
$result = ($query1 | Select-Object -Property EventTime,HostName,UserName,FileName,FileHash,CreatorFileName) 
$result | Export-Csv -Path "$temppath\o1.csv" -NoTypeInformation
    }
    elseif ($NState -eq "TRUE"){
    $logprocessdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.LogSearchProcess.dll")
    $logparmeterdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.LogSearchParameter.dll")
    $datapersist = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.Report.DataPersistance.dll")
    #Perform search for event id 8005 and source Eventtracker 9#
$logparmeter01 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logparmeter02 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logparmeter05 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logcerteria = New-Object Prism.LogSearchParameter.LogSearchParameter
$searchconfig = New-Object Prism.LogSearchParameter.SearchConfig
$searchconfig.IsParseTokens = "False"
$logcerteria.FromDate = (get-date).AddHours($SFREQ)
$logcerteria.ToDate = (get-date)
#$logcerteria.SystemGroups = "Servers"
$logcerteria.SystemIncludeType = 1
$logparmeter01.ParameterId = 0
$logparmeter01.Operator = 1
$logparmeter01.ParameterName = "event_id"
$logparmeter01.ParameterType = 1
$logparmeter01.SearchValue = "8005"
$logparmeter02.ParameterId = 0
$logparmeter02.Operator = 1
$logparmeter02.ParameterName = "event_source"
$logparmeter02.ParameterType = 1
$logparmeter02.SearchValue = "EventTracker"
$logcerteria.AdvancedParameter = $logparmeter01
$logcerteria.AdvancedParameter += $logparmeter02
$logticks = (get-date).Ticks
$mdbname1 = "VTAnalysis_{0}" -f $logticks
$param = new-object Prism.LogSearchParameter.LogSearchParameterContext ("$mdbname1")
$param.Update($logcerteria)
$search = new-object Prism.LogSearchProcess.LogSearchProcessing ("$mdbname1")
$search.StartProcessing(4) | Out-Null
########################################################################################################################################

#Extract useful values from event_description and store in Temp folder#
$regex2 = '(?s)Hash\:\s+(.*?)System\:\s+(.*?)Time\:\s+(.*?)Image File Name\:\s+(.*?)User\:\s+(.*?)File Name\:.*?Creator Image File Name\:\s+(.*?)File Version\:'
Filter Extract2 {
$_.event_description -match $regex2 > $null
[pscustomobject]@{  
FileHash = ($Matches[1]).trim()
HostName = ($Matches[2]).trim()
EventTime = ($Matches[3]).trim()
FileName = ($Matches[4]).trim()
UserName = ($Matches[5]).trim()
CreatorFileName = ($Matches[6]).trim()
}}

$mdblocation1 = "$etpath\Reports\LogSearch\$mdbname1.mdb"
$query1 = ((Invoke-MDBSQLCMD $mdblocation1 -sqlquery "Select event_description from Events" | Extract2) | Where-Object {($we1 -notcontains $_.FileName) -and ($we2 -notcontains $_.FileHash)})
$result = ($query1 | Select-Object -Property EventTime,HostName,UserName,FileName,FileHash,CreatorFileName) 
$result | Export-Csv -Path "$temppath\o1.csv" -NoTypeInformation
    }
 }
########################################################################################################################################

 elseif ($ETDBState -eq "TRUE"){
 # To check whether the module is installed.
$check = Get-Module -ListAvailable -Name Sqlps

    If ($check -eq $null) {
# Install the SQL Server Module.  
Install-Module -Name SqlServer -Scope AllUsers
    
# Import the SQL Server Module.    
Import-Module Sqlps -DisableNameChecking
}
else {write-host "module present"}

$query1 = "
SELECT        HS.MD5_Hash, FD.File_Version, FD.File_Description, FD.Product_Name, FD.Product_Version, FD.File_Size, FD.Signed_By, FD.Counter_Signed_By, FD.Counter_SignedOn, PN.Process_Name,

                         PN.Image_File_Path, PD.LogTime, PD.System_Name, PD.User_Name, PD.CommandLine, PD.Parent_Process_Name, PD.Parent_Image_File_Path, PD.FileModified_On

FROM            EAMD5HashStatus AS HS INNER JOIN

                         EAProcess_FileDetails AS FD ON HS.Hash_Id = FD.Hash_Id INNER JOIN

                         EAProcess_Names AS PN ON FD.Id = PN.File_Id INNER JOIN

                         EAProcess_Details AS PD ON PN.Id = PD.Process_Id
WHERE LogTime > DATEADD(HOUR, $SFREQ, GETDATE())
ORDER BY LogTime Desc
                         "
       If($WINAState -eq "TRUE"){
       $table = Invoke-Sqlcmd -ServerInstance "$SQLIN" -Database "EventTrackerData" -Query $query1}
       If($SQLAState -eq "TRUE"){
       $table = Invoke-Sqlcmd -ServerInstance "$SQLIN" -Database "EventTrackerData" -Query $query1 -Username $SQLUN -Password $SQLPW}
    $result = $table | Select-Object -Property @{name="EventTime";expression={$($_.LogTime)}},@{name="HostName";expression={$($_.System_Name)}},@{name="UserName";expression={$($_.User_Name)}},@{name="FileName";expression={$($_.Image_File_Path)}},@{name="FileHash";expression={$($_.MD5_Hash)}},@{name="CreatorFileName";expression={$($_.Parent_Image_File_Path)}}
    $result | Export-Csv -Path "$temppath\o1.csv" -NoTypeInformation
 }
########################################################################################################################################

#Perform VT checks on the exported hashes and store in Temp folder#
$result1 = ($result).filehash | foreach{$e = Get-VTReport -VTApiKey $apikey -hash $_ 
[pscustomobject]@{  
MD5Hash = $e.md5
VTScore = $e.score
VTDetails = $e.details
}}
$result1 | Export-Csv -Path "$temppath\o2.csv" -NoTypeInformation
########################################################################################################################################

#Join outputs of Temp folder to create consolidated csv report#
$dt = Get-Date -Format MMddyyy_HHmmss
$fname= "VTReport_{0}_{1}" -f $dt,$CNAME

$f1= Import-Csv -Path "$temppath\o1.csv" | select *,VTScore,VTDetails
$f2= Import-Csv -Path "$temppath\o2.csv"
$f1 | %{
      $samname=$_.FileHash
      $m=$f2|?{$_.MD5Hash -eq $samname}
      $_.VTScore=$m.VTScore
      $_.VTDetails=$m.VTDetails
       }

(($f1 | Sort-Object EventTime -Descending) | Select-Object EventTime,HostName,UserName,FileName,CreatorFileName,FileHash,VTScore,VTDetails) | Export-Csv -Path "$backuppath\$fname.csv" -NoTypeInformation
########################################################################################################################################

#Convert consolidated csv report to HTML#
$final = Import-csv -Path "$backuppath\$fname.csv"
$df = Get-Date -Format G
$evcount =  ($final|Measure-Object).count

If ($evcount -ge 1){
$Head = @'
<link href="http://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css" rel="stylesheet">   
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
<link rel="stylesheet" 
href="http://cdn.datatables.net/1.10.2/css/jquery.dataTables.min.css"></style>
<script type="text/javascript" 
src="http://cdn.datatables.net/1.10.2/js/jquery.dataTables.min.js"></script>
<script type="text/javascript" 
src="http://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/js/bootstrap.min.js"></script>
<script>
$(document).ready(function(){
    $('#myTable').dataTable();
});
</script>
<style type="text/css">
  html,
   .caption {
  padding: 10px 10px;
  color: black;
  font-weight: bold;
  text-align: left;
  font-size:x-large;  
   }
table {
  width: 800px;
  overflow: hidden;
  box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
  white-space: nowrap;
  border:none;
  border-collapse: collapse;
}

th {
    border-left: 1px solid #000;
    border-right: 1px solid #000;
    color: black;
    font-size:large;
}

td {
    border-left: 1px solid #000;
    border-right: 1px solid #000;
    font-size:medium;
    font-weight: normal;
}
.button {
width: 2px;
padding: 7px;
cursor: pointer;
font-weight: bold;
font-size: 70%;
background: #3366cc;
color: #fff;
border: 1px solid #3366cc;
border-radius: 10px;
-moz-box-shadow:: 6px 6px 5px #999;
-webkit-box-shadow:: 6px 6px 5px #999;
box-shadow:: 6px 6px 5px #999;
position: center
}
.button:hover {
color: #f90000;
background: #3366cc;
border: 1px solid #fff;
}
</style>
'@
$Title = @"
<div class="caption"><font size="20">VT Report $df</font></div>
"@

$body = $final | select *,@{name="VTURL";Expression={If ($_.VTDetails -ne "-"){'<a href="{0}" class="button" style="text-decoration: none;">VTLink</a>' -f $_.VTDetails} else {'N/A'}}} -ExcludeProperty VTDetails

((($body | ConvertTo-Html -Head $Head -PreContent $Title).replace('<colgroup><col/><col/><col/><col/><col/><col/><col/><col/></colgroup>',"").replace('<tr><th>EventTime','<thead><tr><th>EventTime').replace('VTURL</th></tr>','VTURL</th></tr></thead><tbody>').replace('<table>','<div class="table-responsive"><table id="myTable" class="display table" width="100%" >').replace('</table>','</tbody></table></div>')) | foreach {$_.replace("&lt;","<").replace("&gt;",">").replace("&quot;",'"')})| Out-File "$outputpath\$fname.html"
########################################################################################################################################

#Send email for HTML reports#
If ($SMTPEState -eq "TRUE"){
$body1    =  @"
<p><strong><span style="font-family: Verdana, Geneva, sans-serif; font-size: 24px;">Hourly VirusTotal Report</span></strong></p>
<hr>
<table style="width: 100%;">
    <tbody>
        <tr>
            <td style="width: 33.6553%; background-color: rgb(84, 172, 210);"><span style="font-size: 18px;">Company Name</span><br></td>
            <td style="width: 66.0226%; background-color: rgb(235, 107, 86);"><span style="font-size: 24px;">$company</span><br></td>
        </tr>
        <tr>
            <td style="width: 33.6553%; background-color: rgb(84, 172, 210);"><span style="font-size: 18px;">System Name</span><br></td>
            <td style="width: 66.0226%; background-color: rgb(235, 107, 86);"><span style="font-size: 24px;">$env:computername</span><br></td>
        </tr>
        <tr>
            <td style="width: 33.6553%; background-color: rgb(84, 172, 210);"><span style="font-size: 18px;">Generated On</span><br></td>
            <td style="width: 66.0226%; background-color: rgb(235, 107, 86);"><span style="font-size: 24px;">$df<br></span></td>
        </tr>
    </tbody>
</table>
<p><br></p>
"@
    If ($SMTPAState -eq "TRUE"){
    $SMTPCRED = New-Object System.Management.Automation.PSCredential -ArgumentList $SMTPUN, $SMTPPW
    Send-MailMessage -From $SMTPF -to $SMTPT -Subject $Subject -Body $Body1 -SmtpServer $SMTPIP -port $SMTPPP -Credential $SMTPCRED -UseSsl -BodyAsHtml -Attachments "$outputpath\$fname.html"
        }
    else {
    Send-MailMessage -From $SMTPF -to $SMTPT -Subject $Subject -Body $Body1 -SmtpServer $SMTPIP -port $SMTPPP -UseSsl -BodyAsHtml -Attachments "$outputpath\$fname.html"
        }

    }

}
########################################################################################################################################

#Generate alert for VTScore >= #
$computer = $env:COMPUTERNAME
($final | Where-Object {([int](($_.VTScore).split("/")[0])) -ge $VTSCORE}) | ForEach-Object {
$rt = (($_| Out-String).trim()).Replace("\","\\")
& "$etpath\ScheduledActionScripts\sendtrap.exe" ET $env:COMPUTERNAME $computer 3 2 "EventTracker" 0 8027 "Bad hash detected\n\nDetails:\n$rt" N/A N/A " " 14505
}
########################################################################################################################################

#White-list hashes with VTScore >= 1#
If ($WLState -eq "TRUE"){
($final | Where-Object {([int](($_.VTScore).split("/")[0])) -eq 0}) | ForEach-Object {
$tr = $_.FileHash
$query2 = "UPDATE EAMD5HashStatus
SET Status = 1
WHERE MD5_Hash = '$tr'
"
       If($WINAState -eq "TRUE"){
       Invoke-Sqlcmd -ServerInstance "$SQLIN" -Database "EventTrackerData" -Query $query2
       }
       If($SQLAState -eq "TRUE"){
       Invoke-Sqlcmd -ServerInstance "$SQLIN" -Database "EventTrackerData" -Query $query2 -Username $SQLUN -Password $SQLPW}
       }

    # Example of a PowerShell registry change
    $RegKey ="HKLM:\SOFTWARE\WOW6432Node\Prism Microsystems\EventTracker\Manager"
    Set-ItemProperty -Path $RegKey -Name EA_ReloadLocalHashSafeList -Value 1
    }
########################################################################################################################################

#Truncate Temp, Backup and Output folder contents#
$fname1= "VTReport_{0}" -f $CNAME
Get-ChildItem -Path "$temppath" -Filter "*.csv" | Remove-Item
Get-ChildItem "$backuppath\VTReport*.csv" |
  ForEach-Object { Import-Csv $_ } |
  Export-Csv "$outputpath\$fname1.csv" -NoTypeInformation
(Get-ChildItem -Path "$backuppath" -Filter "VTReport*.csv"| Where-Object{$_.LastWriteTime -lt ((get-date).AddDays(-7))}) | Remove-Item
(Get-ChildItem -Path "$outputpath" -Filter "VTReport*.html"| Where-Object{$_.LastWriteTime -lt ((get-date).AddDays(-1))}) | Remove-Item
########################################################################################################################################
########################################################################################################################################
