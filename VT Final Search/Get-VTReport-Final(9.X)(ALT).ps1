########################################################################################################################################
#<Description>                                                                                                                         #
#This script will do the following things:                                                                                             #
#>Get input from XML and register folders and fiilter files.                                                                           #
#>Perform log search for event id 8005, source EventTracker for specified duration.                                                    #
#>Extract useful fields from logs and get VirusTotal score for all hashes.                                                             #
#>Generate consolidated report of output with scores.                                                                                  #
#                                                                                                                                      # 
#<Input>                                                                                                                               #
#>Run .\Input\Integrator_VT.ps1, provide VT API Key and evaluation duration.                                                           # 
#>Add process names and hashes to to filtered in .\Filters\Filter_File.txt and .\Filters\Filter_Hash.txt                               #
#                                                                                                                                      #
#<Output>                                                                                                                              #
#>HTML and CSV reports will be generated in .\Output folder.                                                                           #                                                                                                                                   #
#                                                                                                                                      #
#CreatedBy:kumarnitesh@eventtracker.com                                                                                                #
#Created On:11/12/18                                                                                                                   #
########################################################################################################################################
########################################################################################################################################

#Assign folder paths#
$etpath = (Get-ItemProperty -Path 'registry::hklm\SOFTWARE\Wow6432Node\Prism Microsystems\EventTracker\Manager').INSTALLPATH
$scriptdir = Split-Path $SCRIPT:MyInvocation.MyCommand.Path -parent
$inputpath = "$scriptdir\Input"
$outputpath = "$scriptdir\Output"
$temppath = "$scriptdir\Temp"
$filterpath = "$scriptdir\Filters"
########################################################################################################################################

#Get input from config and filter files#
$input = Import-Clixml -Path "$inputpath\Conf.xml"
$apikey = $input.apikey
$duration = "-{0}" -f $input.duration
$company = "Netsurion"

$SMTPServer = "eventtracker-com.mail.protection.outlook.com"
$SMTPPort = "25"
$From = "kumarnitesh@eventtracker.com"
$To = "ECC-HARMONY@EventTracker.com"
$Subject = "Hourly VirusTotal Report({0})" -f $company

$w1 = Get-Content -Path "$filterpath\Filter_File.txt"
[array]$we1 = $w1 -split "\n"
$w2 = Get-Content -Path "$filterpath\Filter_Hash.txt"
[array]$we2 = $w2 -split "\n"
########################################################################################################################################

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

$logprocessdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.LogSearchProcess.dll")
$logparmeterdll = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.LogSearchParameter.dll")
$datapersist = [System.Reflection.Assembly]::LoadFrom("$etpath\AdvancedReports\EventTracker.Report.DataPersistance.dll")
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

#Perform search for event id 8005 and source Eventtracker#
$logparmeter01 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logparmeter02 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logparmeter05 = New-Object Prism.LogSearchParameter.AdvanceParameter
$logcerteria = New-Object Prism.LogSearchParameter.LogSearchParameter
$searchconfig = New-Object Prism.LogSearchParameter.SearchConfig
$searchconfig.IsParseTokens = "False"
$logcerteria.FromDate = (get-date).AddHours($duration)
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
$mdbname1 = "LogonAnalysis_{0}" -f $logticks
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
$fname= "VTReport_{0}" -f $env:COMPUTERNAME 

$f1= Import-Csv -Path "$temppath\o1.csv" | select *,VTScore,VTDetails
$f2= Import-Csv -Path "$temppath\o2.csv"
$f1 | %{
      $samname=$_.FileHash
      $m=$f2|?{$_.MD5Hash -eq $samname}
      $_.VTScore=$m.VTScore
      $_.VTDetails=$m.VTDetails
       }

(($f1 | Sort-Object EventTime -Descending) | Select-Object EventTime,HostName,UserName,FileName,CreatorFileName,FileHash,VTScore,VTDetails) | Export-Csv -Path "$outputpath\$fname.csv" -Append -NoTypeInformation
########################################################################################################################################

#Convert consolidated csv report to HTML#
$final = Import-csv -Path "$outputpath\$fname.csv"
$df = Get-Date -Format G
$evcount =  ($final|Measure-Object).count

If ($evcount -ge 1){
$Head = @"
<style>
html,
	 .caption {
  padding: 15px 15px;
  color: #fff;
  font-weight: bold;
  text-align: left;
	 }

body {
  height: 100%;
}
body {
  margin: 0;
  background: radial-gradient(circle, #49a09d, #5f2c82);
  font-family: sans-serif;
  font-weight: 100;
}
.container {
  position: absolute;
  top: 50%;
  left: 50%;
  -webkit-transform: translate(-50%, -50%);
          transform: translate(-50%, -50%);
}
table {
  width: 800px;
  border-collapse: separate;
  overflow: hidden;
  box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
  white-space: nowrap;
  cellpadding="10"
}
td {
  padding: 20px;
  background-color: rgba(255, 255, 255, 0.2);
  color: #fff;
}
th {
  padding: 10px 10px;
  font-size: large;
  color: #fff;
  text-transform: uppercase;
    font-weight: bold;
    text-align: center;
    border-collapse: separate;
border: 1px solid #3366cc;
}
thead th {
  background-color: #55608f;
}
tbody tr:hover {
  background-color: rgba(255, 255, 255, 0.3);
}
tbody td {
  position: relative;
}
tbody td:hover:before {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  top: -9999px;
  bottom: -9999px;
  background-color: rgba(255, 255, 255, 0.2);
  z-index: -1;
}

.button {
width: 6px;
padding: 15px;
cursor: pointer;
font-weight: bold;
font-size: 90%;
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
"@
$Title = @"
<div class="caption"><font size="20">$company VT Report $df $env:COMPUTERNAME</font></div>
"@

$body = $final | select *,@{name="VTURL";Expression={If ($_.VTDetails -ne "-"){'<a href="{0}" class="button" style="text-decoration: none;">VTLink</a>' -f $_.VTDetails} else {'N/A'}}} -ExcludeProperty VTDetails

(($body | ConvertTo-Html -Head $Head -PreContent $Title) | foreach {$_.replace("&lt;","<").replace("&gt;",">").replace("&quot;",'"')})| Out-File "$outputpath\$fname.html"

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

Send-MailMessage -From $From -to $To -Subject $Subject -Body $Body1 -SmtpServer $SMTPServer -port $SMTPPort -UseSsl -BodyAsHtml -Attachments "$outputpath\$fname.html"
}
########################################################################################################################################

#Generate alert for VTScore >= 1#
$computer = $env:COMPUTERNAME
($final | Where-Object {([int](($_.VTScore).split("/")[0])) -ge 1}) | ForEach-Object {
$rt = ($_ |Out-String)
& "$etpath\ScheduledActionScripts\sendtrap.exe" ET $env:COMPUTERNAME $computer 3 2 "EventTracker" 0 8027 "Bad hash detected\nDetails:$rt" N/A N/A " " 14505
}

########################################################################################################################################

#Truncate Temp folder contents#
Get-ChildItem -Path "$temppath" -Filter "*.csv" | Remove-Item
########################################################################################################################################>
########################################################################################################################################


