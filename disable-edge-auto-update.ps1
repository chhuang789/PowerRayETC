if ([Environment]::Is64BitOperatingSystem -eq "True") {
    #Write-Host "64-bit OS"
    $PF=${env:ProgramFiles(x86)}
}
else {
    #Write-Host "32-bit OS"
    $PF=$env:ProgramFiles
}

if ($(Test-Path "$PF\Microsoft\Edge\Application\msedge.exe") -eq "True") {
    # 结束进程
    taskkill /im MicrosoftEdgeUpdate.exe /f
    taskkill /im msedge.exe /f
    # Microsoft Edge 更新服务 (sysin)
    #这里也可以使用 sc.exe stop "service name"
    sc.exe stop -Name "edgeupdate"
    sc.exe stop -Name "edgeupdatem"
    sc.exe stop -Name "MicrosoftEdgeElevationService"
    # Windows 10 默认 PS 版本 5.1 没有 Remove-Service 命令
    # This cmdlet was added in PS v6. See https://docs.microsoft.com/en-us/powershell/scripting/whats-new/what-s-new-in-powershell-core-60?view=powershell-6#cmdlet-updates.
    #Remove-Service -Name "edgeupdate"
    #Remove-Service -Name "edgeupdatem"
    #Remove-Service -Name "MicrosoftEdgeElevationService"
    # sc 在 PowerShell 中是 Set-Content 别名，所以要使用 sc.exe 否则执行后无任何效果
    sc.exe delete "edgeupdate"
    sc.exe delete "edgeupdatem"
    sc.exe delete "MicrosoftEdgeElevationService"
    # 任务计划企业版
    #schtasks.exe /Delete /TN \MicrosoftEdgeUpdateBrowserReplacementTask /F
    #schtasks.exe /Delete /TN \MicrosoftEdgeUpdateTaskMachineCore /F
    #schtasks.exe /Delete /TN \MicrosoftEdgeUpdateTaskMachineUA /F
    Get-ScheduledTask -taskname MicrosoftEdgeUpdate* | Unregister-ScheduledTask -Confirm: $false
    # 移除更新程序
    Remove-Item "$PF\Microsoft\EdgeUpdate" -Recurse -Force
    Write-Output "Disable Microsoft Edge Enterprise Auto Update Successful!"
}
elseif ($(Test-Path "$env:USERPROFILE\AppData\Local\Microsoft\Edge\Application\msedge.exe") -eq "True") {
    # 结束进程
    taskkill /im MicrosoftEdgeUpdate.exe /f
    taskkill /im msedge.exe /f
    # 用户版没有创建服务
    # 获取SID方法
    function Get-CurrentUserSID {
        [CmdletBinding()]
        param(
        )
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        return ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).SID.Value
    }
    # 用户版任务计划
    schtasks.exe /Delete /TN \MicrosoftEdgeUpdateTaskUser$(Get-CurrentUserSID)Core /F
    schtasks.exe /Delete /TN \MicrosoftEdgeUpdateTaskUser$(Get-CurrentUserSID)UA /F
    #Get-ScheduledTask -taskname MicrosoftEdgeUpdate* | Unregister-ScheduledTask -Confirm: $false
    # 移除更新程序
    Remove-Item "$env:USERPROFILE\AppData\Local\Microsoft\EdgeUpdate" -Recurse -Force
    Write-Output "Disable Microsoft Edge Users Setup Auto Update Successful!"
}
else {
    Write-Output "No Microsoft Edge Installation Detected!"
}