########################################################################################################################################
#<Description>                                                                                                                         #
#This script will generate form to take inputs for VirusTotal evaluation script.                                                       #
#                                                                                                                                      #
#<Input>                                                                                                                               #
#Enter VirusTotal API Key and evaluation duration in form.                                                                             # 
#                                                                                                                                      #
#<Output>                                                                                                                              #
#Conf.xml will be generated in .\ with entered details.                                                                                #
#                                                                                                                                      #
#CreatedBy:kumarnitesh@eventtracker.com                                                                                                #
#Created On:11/12/18                                                                                                                   #
########################################################################################################################################
########################################################################################################################################

#Assign folder#
$scriptdir = Split-Path $SCRIPT:MyInvocation.MyCommand.Path -parent
########################################################################################################################################

#Generated Form Function#
#region Import the Assemblies
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
#endregion

#region Generated Form Objects
$form1 = New-Object System.Windows.Forms.Form
$numericUpDown1 = New-Object System.Windows.Forms.NumericUpDown
$button1 = New-Object System.Windows.Forms.Button
$label2 = New-Object System.Windows.Forms.Label
$textBox1 = New-Object System.Windows.Forms.TextBox
$label1 = New-Object System.Windows.Forms.Label
$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
#endregion Generated Form Objects

#----------------------------------------------
#Generated Event Script Blocks
#----------------------------------------------
#Provide Custom Code for events specified in PrimalForms.
$button1_OnClick= 
{
#TODO: Place custom script here
$form1.Close()
}

$OnLoadForm_StateCorrection=
{#Correct the initial state of the form to prevent the .Net maximized form issue
	$form1.WindowState = $InitialFormWindowState
}

#----------------------------------------------
#region Generated Form Code
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Height = 139
$System_Drawing_Size.Width = 309
$form1.ClientSize = $System_Drawing_Size
$form1.DataBindings.DefaultDataSourceUpdateMode = 0
$form1.FormBorderStyle = 5
$form1.Name = "form1"
$form1.Text = "VT Report"

$numericUpDown1.DataBindings.DefaultDataSourceUpdateMode = 0
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 120
$System_Drawing_Point.Y = 56
$numericUpDown1.Location = $System_Drawing_Point
$numericUpDown1.Name = "numericUpDown1"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Height = 20
$System_Drawing_Size.Width = 177
$numericUpDown1.Size = $System_Drawing_Size
$numericUpDown1.TabIndex = 5

$form1.Controls.Add($numericUpDown1)


$button1.DataBindings.DefaultDataSourceUpdateMode = 0
$button1.FlatStyle = 0
$button1.Font = New-Object System.Drawing.Font("Segoe UI Symbol",8.25,0,3,0)

$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 119
$System_Drawing_Point.Y = 104
$button1.Location = $System_Drawing_Point
$button1.Name = "button1"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Height = 23
$System_Drawing_Size.Width = 75
$button1.Size = $System_Drawing_Size
$button1.TabIndex = 4
$button1.Text = "OK"
$button1.UseVisualStyleBackColor = $True
$button1.add_Click($button1_OnClick)

$form1.AcceptButton = $button1
$form1.Controls.Add($button1)

$label2.DataBindings.DefaultDataSourceUpdateMode = 0
$label2.Font = New-Object System.Drawing.Font("Segoe UI Symbol",9,0,3,0)

$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 13
$System_Drawing_Point.Y = 56
$label2.Location = $System_Drawing_Point
$label2.Name = "label2"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Height = 23
$System_Drawing_Size.Width = 100
$label2.Size = $System_Drawing_Size
$label2.TabIndex = 2
$label2.Text = "Frequency"

$form1.Controls.Add($label2)

$textBox1.DataBindings.DefaultDataSourceUpdateMode = 0
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 119
$System_Drawing_Point.Y = 13
$textBox1.Location = $System_Drawing_Point
$textBox1.Name = "textBox1"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Height = 20
$System_Drawing_Size.Width = 178
$textBox1.Size = $System_Drawing_Size
$textBox1.TabIndex = 1

$form1.Controls.Add($textBox1)

$label1.DataBindings.DefaultDataSourceUpdateMode = 0
$label1.Font = New-Object System.Drawing.Font("Segoe UI Symbol",9,0,3,0)

$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 13
$System_Drawing_Point.Y = 16
$label1.Location = $System_Drawing_Point
$label1.Name = "label1"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Height = 23
$System_Drawing_Size.Width = 100
$label1.Size = $System_Drawing_Size
$label1.TabIndex = 0
$label1.Text = "VT API Key"

$form1.Controls.Add($label1)

#endregion Generated Form Code
#----------------------------------------------

#Save the initial state of the form
$InitialFormWindowState = $form1.WindowState
#Init the OnLoad event to correct the initial state of the form
$form1.add_Load($OnLoadForm_StateCorrection)
#Show the Form
$form1.ShowDialog()| Out-Null
#End Function
########################################################################################################################################

#Export output to XML#
$input = [pscustomobject]@{  
Duration = ($numericUpDown1).Text
ApiKey = ($textBox1).Text
}

$input | Export-Clixml -Path "$scriptdir\Conf.xml"
########################################################################################################################################
########################################################################################################################################
