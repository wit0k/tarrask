# License
# The TaskHunter tool is copyright (c) Witold Lawacz (wit0k)

# All rights reserved.

# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

$VERSION = "0.3"

# Global Objects
$WMI_SD = new-object System.Management.ManagementClass Win32_SecurityDescriptorHelper;

function Get-ScheduledTaskNamesFromDump {
    param (
        [string[]]$dump_file
    )

    Write-Host "----------------------------------------------------------------------------------------------------------"
    Write-Host $("[*] Parsing process dump: $dump_file")
    Write-Host "----------------------------------------------------------------------------------------------------------"
    Write-Host $("  [-] Loading dump file...")    

    # Ref: https://devblogs.microsoft.com/scripting/use-powershell-and-regular-expressions-to-search-binary-data/
    $Stream = New-Object IO.FileStream -ArgumentList (Resolve-Path $dump_file), ‘Open’, ‘Read’
    # Note: Codepage 28591 returns a 1-to-1 char to byte mapping
    $Encoding = [Text.Encoding]::GetEncoding(28591)
    $StreamReader = New-Object IO.StreamReader -ArgumentList $Stream, $Encoding
    $BinaryText = $StreamReader.ReadToEnd()
    $StreamReader.Close()
    $Stream.Close()

    Write-Host $("  [-] Searching Task names...")   
    $matches = ([regex]"\x4e\x00\x54\x00\x20\x00\x54\x00\x41\x00\x53\x00\x4b\x00\x5c\x00(.*?\x00\x00)").Matches($BinaryText);
    $MatchCount = $matches.Count
   
    $all_task_names = @();
    $task_names = @();

    $matches | ForEach-Object { $all_task_names += "$([Text.Encoding]::Unicode.GetString(([System.Text.Encoding]::UTF8.GetBytes($_.Groups[1].Value))).ToString() -replace ".{1}$")” } 
    
    $task_names = $all_task_names | Sort-Object -Unique;
    $task_names_count = $task_names.Count;
    Write-Host $("    [-] Found: $MatchCount Task entries [Unique Task Names: $task_names_count]");
    # Write-Host $()$task_names;

    return $task_names;
}

function Get-ScheduledTaskInfo {
    param (
        [string[]]$scheduled_task_path
    )

    $scheduled_task = Get-ItemProperty -Path $("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree$scheduled_task_path");

    Write-Host "----------------------------------------------------------------------------------------------------------"
    Write-Host $("Task: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree$scheduled_task_path");
    Write-Host "----------------------------------------------------------------------------------------------------------"
    Write-Host "[*] Permissions:"
    Write-Host "  [+] Registry ACL Permissions:"

    $task_acl = Get-Acl -Path  $("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree$scheduled_task_path");
    $task_acl_sddl = $task_acl.GetSecurityDescriptorSddlForm('All');
    $task_acl_readable_acl = ConvertFrom-SddlString -Sddl $task_acl_sddl -Type RegistryRights | Foreach-Object {$_.DiscretionaryAcl[0]}

    Write-Host $("   [-] $task_acl_sddl");
    Write-Host $("   [-] $task_acl_readable_acl");

    $scheduled_task_sddl = $WMI_SD.BinarySDToSDDL($scheduled_task.SD).SDDL;
    $scheduled_task_readable_acl = ConvertFrom-SddlString -Sddl $scheduled_task_sddl -Type RegistryRights | Foreach-Object {$_.DiscretionaryAcl[0]}

    Write-Host "  [+] SDDL (Tree.Task_Path.SD) Permissions:"

    Write-Host $("   [-] $scheduled_task_sddl");
    Write-Host $("   [-] $scheduled_task_readable_acl");

    # $([System.BitConverter]::ToString(SDDLToBinarySD($scheduled_task_sddl)['BinarySD'])).replace('-','')

    Write-Host "  [+] SDDL (Tasks.ID.SecurityDescriptor) Permissions:"

    $scheduled_task_item_sd = "";
    $task_id = $scheduled_task.Id;

    $ErrorOccurred = $null;
    Try {
        $scheduled_task_item_sd = Get-ItemPropertyValue -Path $("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$task_id") -Name "SecurityDescriptor" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -ErrorVariable ErrorOccurred;
    }Catch {
        # Do not show error in stdout
    }
    if (![string]::IsNullOrEmpty($scheduled_task_item_sd)) {
        $scheduled_task_item_readable_acl = ConvertFrom-SddlString -Sddl $scheduled_task_item_sd -Type RegistryRights | Foreach-Object {$_.DiscretionaryAcl[0]}
        Write-Host $("   [-] ID: $task_id");
        Write-Host $("   [-] $scheduled_task_item_sd");
        Write-Host $("   [-] $scheduled_task_item_readable_acl");
    }else{
        $scheduled_task_item_sd = "";
        $scheduled_task_item_readable_acl = "";
        Write-Host $("   [-] ID: $task_id");
        Write-Host $("   [-] SecurityDescriptor: NOT FOUND");
    }

    #Write-Host $("CSV#SDDL_STR#$task_id#$task_acl_sddl#$scheduled_task_sddl#$scheduled_task_item_sd");
    #Write-Host $("CSV#ACL#$task_id#$task_acl_readable_acl#$scheduled_task_readable_acl#$scheduled_task_item_readable_acl");

    #O:BAG:S-1-5-21-3284541240-3667107395-264196544-513D:PAI(A;CI;KA;;;WD)
    #Everyone: AccessAllowed (ChangePermissions, CreateLink, CreateSubKey, Delete, EnumerateSubKeys, ExecuteKey, FullControl, GenericExecute, GenericWrite, Notify, QueryValues, ReadPermissions, SetValue, TakeOwnership, WriteKey)
}

function Get-TaskSchedulerDump {
    param (
        [string[]]$Out_Path
    )

    # rundll32.exe comsvcs.dll MiniDump <svchost PID> <out path> full
    $dump_files = @();

    Write-Host $("[*] Search for Task Scheduler process to dump..."); 

    $file_path = [System.IO.Path]::GetDirectoryName($Out_Path)
    $file_name = [System.IO.Path]::GetFileName($Out_Path)

    $processes = Get-CimInstance win32_process | where {($_.Name -eq "svchost.exe" -and $_.commandline -like "*-k netsvcs -p -s Schedule*")}
    
    if ($processes) {        
        $processes | ForEach-Object {
            $proc_name = $_.Name.ToString()
            $process_pid = $_.ProcessId
            Write-Host $("  [-] Dumping: $proc_name [$process_pid]"); 
            $out_file = $file_path + "\" + $process_pid.ToString() + "_" + $file_name;
            $cmd_args = @('comsvcs.dll', 'MiniDump', $process_pid, $out_file, 'full')
            Write-Host $("  [-] CMD: rundll32.exe $cmd_args"); 
            $std_out = & 'rundll32.exe' $cmd_args | Out-Null;  # | Out-Null should force the wait for rundll32 to exit (It's a trick)
            Write-Host $("  [-] Dumped to $out_file"); 
            $dump_files += $out_file;
        }
      }else {
            $processes2 = Get-Process -ErrorAction SilentlyContinue | where {$_.Modules -like '*(schedsvc.dll)'}
            if ($processes2) {
                $processes2 | ForEach-Object {
                    $proc_name = $_.Name.ToString()
                    $process_pid = $_.Id
                    Write-Host $("  [-] Dumping: $proc_name [$process_pid]"); 
                    $out_file = $file_path + "\" + $process_pid.ToString() + "_" + $file_name;
                    $cmd_args = @('comsvcs.dll', 'MiniDump', $process_pid, $out_file, 'full')
                    Write-Host $("  [-] CMD: rundll32.exe $cmd_args"); 
                    $std_out = & 'rundll32.exe' $cmd_args | Out-Null;  # | Out-Null should force the wait for rundll32 to exit (It's a trick)
                    Write-Host $("  [-] Dumped to $out_file"); 
                    $dump_files += $out_file;
                } 
            }
        }

        return $dump_files;
    
} 

function Get-HiddenScheduledTasks {
    param (
        $task_names_mem
    )

    Write-Host $("[*] Search for Hidden Tasks..."); 

    #Iterate over task names taken from memory dump
    
    # Holder for hiiden task names
    $hidden_task_names = @();

    # System related Tasks
    $EXCLUDED_TASKS = @(
        "\", "\_Loading_Task_Path_"
    )

    # Users present in all SD values 
    $SD_SDDL_EXPECTED_USERS = @(
        "BUILTIN\Administrators", "NT AUTHORITY\Authenticated Users", "NT AUTHORITY\SYSTEM", "NT AUTHORITY\INTERACTIVE", "NT AUTHORITY\SERVICE", "NT AUTHORITY\NETWORK", "Everyone"
    )

    Write-Host $(" [+] Creating Microsoft-Windows-Security-Auditing CACHE [Time consuming]...");
    # Create Events Cache, Query the memory should be faster than query the Security log for each loop, especially when Sec log is Big!
    $Events4699 = Get-EventLog -LogName Security -InstanceID 4699 -Source Microsoft-Windows-Security-Auditing -ErrorAction SilentlyContinue | where {($_.Message -like $("*$task_path*"))} | select Message
    $Events141 = Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational -ErrorAction SilentlyContinue | where id -eq 141 | select Message
    
    $events_len = $Events4699.Count + $Events141.Count;

    Write-Host $("   [-] $events_len cached entries");

    Write-Host $(" [+] Scanning Windows Registry...");
    # Start the lookup
    $task_names_mem | ForEach-Object { 
        # Write-Host $(" [-] $($_)");
        $task_path = $("\$_");

        $is_task_excluded = $null;
        $is_task_excluded = $EXCLUDED_TASKS | Where-Object { $_ -ieq $task_path };
        $reg_path = $("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree$task_path")
        Try {
            
            # Exclude System related items
            if (!$is_task_excluded){
                # IF a Task was properly removed (based on Microsoft-Windows-Security-Auditing), it would still be in svchost memory, but a proper Task removal should be logged in Secuirty log (IF auditing is enabled)
                $was_properly_removed = $Events4699 | where {($_.Message -like $("*$task_path*"))}
                
                # Checking Microsoft-Windows-TaskScheduler/Operational
                if(!$was_properly_removed){
                    $was_properly_removed = $Events141 | where {($_.Message -like $("*$task_path*"))}
                }
                
                if($was_properly_removed){
                    Write-Host $("  [-] REMOVED (Task properly DELETED -> $reg_path");
                }else{
                    if(Test-Path $reg_path) {
                        $SD_value = Get-ItemPropertyValue -Path $reg_path -Name SD -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -ErrorVariable ErrorOccurred;
                        if ($task_path -like "*iWouldNeverTouchSDvalu*"){
                            $debug = ""
                        }

                        # Process SD value (Look for anomalies like SYSTEM denied access or so
                        $scheduled_task_sddl = $WMI_SD.BinarySDToSDDL($SD_value).SDDL;
                        $scheduled_task_readable_acl = ConvertFrom-SddlString -Sddl $scheduled_task_sddl -Type RegistryRights | Foreach-Object {$_.DiscretionaryAcl[0]}

                        # Suspcious - AccessAllowed not present in value's SD
                        if (!$scheduled_task_readable_acl -like "*AccessAllowed*"){
                            Write-Host $("  [-] HIDDEN (Task's SD does not contain AccessAllowed -> $reg_path");
                            $hidden_task_names += $task_path;
                        
                        }

                        $sddl_user = (([regex]"^(.*)?\:").Matches($scheduled_task_readable_acl)).Groups[1].Value;
                        $expected_user_present = $SD_SDDL_EXPECTED_USERS | where {($_ -ieq $sddl_user)}

                        if (!$expected_user_present){
                            Write-Host $("  [-] HIDDEN (Task's SD contains unexpected user: [$sddl_user] -> $reg_path");
                            $hidden_task_names += $task_path;
                        }

                    }else{
                        Write-Host $("  [-] HIDDEN (Task's Key NOT FOUND -> $reg_path");
                        $hidden_task_names += $task_path;
                    }
                }   
            }
        }Catch {
            Write-Host $("  [-] HIDDEN (Task's SD Value NOT FOUND -> $reg_path\SD");
            $hidden_task_names += $task_path;
        }
    
    } 

    # "  [-] HIDDEN (Task's Key NOT FOUND -> $reg_path"
    # "  [-] HIDDEN (Task's SD Value NOT FOUND -> $reg_path\SD"
    # "  [-] HIDDEN (Task's SD contains unexpected user: [$sddl_user] -> $reg_path"
    # "  [-] HIDDEN (Task's SD does not contain AccessAllowed -> $reg_path"
    # "  [-] REMOVED (Task properly DELETED -> $reg_path"

    return $hidden_task_names;
}

Write-Host "----------------------------------------------------------------------------------------------------------"
Write-Host $("[*] Starting Tarrask Hunter...")
Write-Host "----------------------------------------------------------------------------------------------------------"
$Process_Dump_Path = "C:\\Windows\\Temp\\svchost_task_scheduler.dmp";

# Dump Task Scheduler memory
$dump_files = Get-TaskSchedulerDump($Process_Dump_Path)

# Process all dump files (There should be 1 only, but you never know)
$dump_files | ForEach-Object { 
    
    $dump_file = $_;

    # get Task Names from process memory dump
    $task_names_mem = Get-ScheduledTaskNamesFromDump -dump_file $dump_file;

    #$task_names_mem -is [array]

    Write-Host "----------------------------------------------------------------------------------------------------------"
    Write-Host $("[*] Scanning OS for Hidden Tasks...")
    Write-Host "----------------------------------------------------------------------------------------------------------"

    # Get all Tasks supposedly hidden
    $hidden_tasks = Get-HiddenScheduledTasks($task_names_mem);
    
    # Create tarrask_hunter CMD # -i "test2/1136_svchost_test2_removed.dmp" --dump-task --csv -v -n iWASremoved_2
    $dump_name = [System.IO.Path]::GetFileName($dump_file);
    $task_names_param = $hidden_tasks -join '"-|-"'
    $task_names_param = '"' + $task_names_param + '"'
    
    $tarrask_hunter_cmd = $("-i $dump_name --dump-task --csv -v -n $task_names_param");
    
    Write-Host "----------------------------------------------------------------------------------------------------------"
    Write-Host $("[*] GetTasks Comman-Line:")
    Write-Host "----------------------------------------------------------------------------------------------------------"
    $tarrask_hunter_cmd


    #Write-Host $("[*] Tarrask_Hunter Test:")
    #$task_names_mem | ForEach-Object {
    #    Get-ScheduledTaskInfo("$_");
    #}


    # "\TestTask4"
    # Get-ScheduledTaskInfo("\TestTask");

} 



# https://docs.microsoft.com/en-us/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptorhelper

