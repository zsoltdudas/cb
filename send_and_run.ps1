<#
    .Synopsis
        This script sends a file to a VM and runs it.
    .Description
        This script will get the IP from the guest machine and then it will 
         use pscp to send the script and keys. plink will be used to run the AIO script. 
    .Parameter vmName
        Name of the VM
    .Parameter SourcePath
        The path to files we want to upload. They must be in the same folder
    .Parameter server
        Just type in localhost
    .Parameter ip
        For SLES it's optional, for RHEL and Ubuntu it must be present (IPv4 of VM)
    .Example
        .\script_ps.ps1 -vmname rhel60 -SourcePath \Path\To\Folder -server localhost -ip 0.0.0.0
#>


param ([string]$SourcePath, [String] $vmName, [String] $server, [String] $ip)


function GetIPv4ViaKVP( [String] $vmName, [String] $server)
{
    <#
    .Synopsis
        Try to determine a VMs IPv4 address with KVP Intrinsic data.
    .Description
        Try to determine a VMs IPv4 address with KVP Intrinsic data.
    .Parameter vmName
        Name of the VM
    .Parameter server
        Name of the server hosting the VM
    .Example
        GetIpv4ViaKVP "myTestVM" "localhost"
    #>

    $vmObj = Get-WmiObject -Namespace root\virtualization\v2 -Query "Select * From Msvm_ComputerSystem Where ElementName=`'$vmName`'" -ComputerName $server

    if (-not $vmObj)
    {   
        Write-Error -Message "GetIPv4ViaKVP: Unable to create Msvm_ComputerSystem object" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    $kvp = Get-WmiObject -Namespace root\virtualization\v2 -Query "Associators of {$vmObj} Where AssocClass=Msvm_SystemDevice ResultClass=Msvm_KvpExchangeComponent" -ComputerName $server
    if (-not $kvp)
    {
        Write-Error -Message "GetIPv4ViaKVP: Unable to create KVP exchange component" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    $rawData = $Kvp.GuestIntrinsicExchangeItems
    if (-not $rawData)
    {
        Write-Error -Message "GetIPv4ViaKVP: No KVP Intrinsic data returned" -Category ReadError -ErrorAction SilentlyContinue
        return $null
    }

    $name = $null
    $addresses = $null

    foreach ($dataItem in $rawData)
    {

        $found = 0
        $xmlData = [Xml] $dataItem
        foreach ($p in $xmlData.INSTANCE.PROPERTY)
        {
            if ($p.Name -eq "Name" -and $p.Value -eq "NetworkAddressIPv4")
            {
                $found += 1
            }

            if ($p.Name -eq "Data")
            {
                $addresses = $p.Value
                $found += 1
            }

            if ($found -eq 2)
            {
                $addrs = $addresses.Split(";")
                foreach ($addr in $addrs)
                {
                    if ($addr.StartsWith("127."))
                    {
                        Continue
                    }
                     Write-Host "GetIPv4ViaKVP: $addr"
                    return $addr
                }
            }
        }
    }

    Write-Error -Message "GetIPv4ViaKVP: No IPv4 address found for VM ${vmName}" -Category ObjectNotFound -ErrorAction SilentlyContinue
    return $null
}

function GetIPv4ViaICASerial( [String] $vmName, [String] $server)
{
    $ipv4 = $null

    #
    # Make sure icaserial.exe exists
    #
    if (-not (Test-Path .\bin\icaserial.exe))
    {
        Write-Error -Message "GetIPv4ViaICASerial: File .\bin\icaserial.exe not found" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    #
    # Get the MAC address of the VMs NIC
    #
    # if (-not $vm)
    # {
    #     Write-Error -Message "GetIPv4ViaICASerial: Unable to get VM ${vmName}" -Category ObjectNotFound -ErrorAction SilentlyContinue
    #     return $null
    # }
    $vmnic = Get-VMNIC -VM $vmName -Server $server -ErrorAction SilentlyContinue
    $macAddr = $vmnic[0].Address
    if (-not $macAddr)
    {
        Write-Error -Message "GetIPv4ViaICASerial: Unable to determine MAC address of first NIC" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    #
    # Get the Pipe name for COM1
    #
    $vm = Get-VM -Name $vmName -Server $server -ErrorAction SilentlyContinue
    $port = Get-VMSerialPort -VM $vmName -server $server -PortNumber 2
    $pipeName = $port.Connection
    if (-not $pipeName)
    {
        Write-Error -Message "GetIPv4ViaICASerial: VM ${vmName} does not have a pipe associated with COM1" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    #
    # Use ICASerial and ask the VM for it's IPv4 address
    #
    # Note: ICASerial is returning an array of strings rather than a single
    #       string.  Use the @() to force the response to be an array.  This
    #       will prevent breaking the following code when ICASerial is fixed.
    #       Remove the @() once ICASerial is fixed.
    #
    $timeout = "5"
    $response = @(bin\icaserial SEND $pipeName $timeout "get ipv4 macaddr=${macAddr}")
    if ($response)
    {
        #
        # The array indexing on $response is because icaserial returning an array
        # To be removed once icaserial is corrected
        #
        $tokens = $response[0].Split(" ")
        if ($tokens.Length -ne 3)
        {
            Write-Error -Message "GetIPv4ViaICASerial: Invalid ICAserial response: ${response}" -Category ReadError -ErrorAction SilentlyContinue
            return $null
        }

        if ($tokens[0] -ne "ipv4")
        {
            Write-Error -Message "GetIPv4ViaICASerial: ICAserial response does not match request: ${response}" -Category ObjectNotFound -ErrorAction SilentlyContinue
            return $null
        }

        if ($tokens[1] -ne "0")
        {
            Write-Error -Message "GetIPv4ViaICASerial: ICAserical returned an error: ${response}" -Category ReadError -ErrorAction SilentlyContinue
            return $null
        }
            
        $ipv4 = $tokens[2].Trim()
    }
    Write-Host "GetIPv4ViaICASerial: $ipv4"
    return $ipv4
}


function GetIPv4ViaHyperV([String] $vmName, [String] $server)
{
    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm)
    {
        Write-Error -Message "GetIPv4ViaHyperV: Unable to create VM object for VM ${vmName}" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    $networkAdapters = $vm.NetworkAdapters
    if (-not $networkAdapters)
    {
        Write-Error -Message "GetIPv4ViaHyperV: No network adapters found on VM ${vmName}" -Category ObjectNotFound -ErrorAction SilentlyContinue
        return $null
    }

    foreach ($nic in $networkAdapters)
    {
        $ipAddresses = $nic.IPAddresses
        if (-not $ipAddresses)
        {
            Continue
        }

        foreach ($address in $ipAddresses)
        {
            # Ignore address if it is not an IPv4 address
            $addr = [IPAddress] $address
            if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork)
            {
                Continue
            }

            # Ignore address if it a loopback address
            if ($address.StartsWith("127."))
            {
                Continue
            }

            # See if it is an address we can access
            $ping = New-Object System.Net.NetworkInformation.Ping
            $sts = $ping.Sent($address)
            if ($sts -and $sts.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
            {
                Write-Host "GetIPv4ViaHyperV: $address"
                return $address
            }
        }
    }

    Write-Error -Message "GetIPv4ViaHyperV: No IPv4 address found on any NICs for VM ${vmName}" -Category ObjectNotFound -ErrorAction SilentlyContinue
    return $null
}

function GetIPv4([String] $vmName, [String] $server)
{
    Write-Host "Am intrat in GetIpv4"
    $errMsg = $null
    $addr = GetIPv4ViaKVP $vmName $server
    if (-not $addr)
    {
        $errMsg += $error[0].Exception.Message
        $addr = GetIPv4ViaICASerial $vmName $server
        if (-not $addr)
        {
            $errMsg += ("`n" + $error[0].Exception.Message)
            $addr = GetIPv4ViaHyperV $vmName $server
            if (-not $addr)
            {
                $errMsg += ("`n" + $error[0].Exception.Message)
                Write-Error -Message ("GetIPv4: Unable to determin IP address for VM ${vmNAme}`n" + $errmsg) -Category ReadError -ErrorAction SilentlyContinue
                return $null
            }
        }
    }

    return $addr
}


function GetIpFromKeyboard (){   
    do{
        $IP = Read-Host "Enter the IP of the virtual machine"

        if($IP -match '[0-9]+[0-9]*[0-9]*\.[0-9]+[0-9]*[0-9]*\.[0-9]+[0-9]*[0-9]*\.[0-9]+[0-9]*[0-9]*') {
           return $IP
        }else{
            write-output "$IP is not an ip"
        }
    }
    while(1)
}



function SendToVM([string]$SourcePath, [String] $vmName, [String] $server, [String] $IP){
    Write-Host "IP:$IP"
    ./pscp.exe -pw Passw0rd $SourcePath"\AIO.sh" root@$IP
    ./pscp.exe -pw Passw0rd $SourcePath"\rhel5_id_rsa.pub" root@$IP
    ./pscp.exe -pw Passw0rd $SourcePath"\rhel5_id_rsa" root@$IP
}


function RunScriptOnVM($vmName, $server, $IP){
    ./plink.exe -pw Passw0rd root@$IP "chmod +x /root/AIO.sh"
    ./plink.exe -pw Passw0rd root@$IP /root/AIO.sh
}



#   CreateVM
param ([string]$vhdpath="", [string]$name="New-VM", [int64]$mem = 2147483648, [int]$gen=1, [string]$locpath="C:\Hyper-V")

Function CreateVM([string]$vhdpath, [string]$name, [int64]$mem, [int]$gen, [string]$locpath){
    if(($vhdpath.len -eq 0)){
        write-output "-vhdpath required"
        exit
    }
    if( -not(Test-Path -path $vhdpath)){
        write-output "Invalid VHD path"
        exit
    }

    New-VM -Name $name -MemoryStartupBytes $mem -Generation $gen -VHDPath $vhdpath -Path $locpath
    SET-VMProcessor -VMname $name -count 2
    enable-vmintegrationservice -vmname $name -name "Guest Service Interface"
    
}

write-output "Creating the new virtual machine..."
CreateVM $vhdpath $name $mem $gen $locpath

#   StartVM
write-output "Starting the virtual machine..."
Start-VM -Name $name


$ip = GetIPv4 $vmName $server

if( -not $ip ){
    $ip = GetIpFromKeyboard
}

$ipAux = "$ipAux" + ":"

SendToVM $SourcePath $vmName $server $ipAux
RunScriptOnVM $vmName $server $ip
