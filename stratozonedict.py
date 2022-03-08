""" Copyright 2021 Google LLC.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""


vm_basic_info = {
    'MachineId':'',
    'MachineName':'',
    'PrimaryIPAddress':'',
    'PublicIPAddress':'',
    'IpAddressListSemiColonDelimited':'',
    'TotalDiskAllocatedGiB':0,
    'TotalDiskUsedGiB':0,
    'MachineTypeLabel':'',
    'AllocatedProcessorCoreCount':0,
    'MemoryGiB':0,
    'HostingLocation':'',
    'OsType':'',
    'OsPublisher':'',
    'OsName':'',
    'OsVersion':'',
    'MachineStatus':'',
    'ProvisioningState':'',
    'CreateDate':'',
    'IsPhysical':0,
    'Source':'AWS'
}

vm_tag = {
    'MachineId':'',
    'Key':'',
    'Value':''
}

vm_disk = {
    'MachineId':'',
    'DiskLabel':'',
    'SizeInGib':'',
    'UsedInGib':'',
    'StorageTypeLabel':''
}

vm_perf = {
    'MachineId':'',
    'TimeStamp':'',
    'CpuUtilizationPercentage':'',
    'AvailableMemoryBytes':'',
    'DiskReadOperationsPerSec':'',
    'DiskWriteOperationsPerSec':'',
    'NetworkBytesPerSecSent':'',
    'NetworkBytesPerSecReceived':''
}