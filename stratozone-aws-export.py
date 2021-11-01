"""
Copyright 2021 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

version 1.0

"""

import boto3
import csv
import datetime
import sys
import logging
import stratozonedict
import os
import zipfile

# global variables
vm_list = []
vm_tag_list = []
vm_disk_list = []
vm_perf_list = []


# setup directories
def create_directory(dir_name):
  """Create output directory.

  Args:
    dir_name: Destination directory
  """
  try:
    if not os.path.exists(dir_name):
      os.makedirs(dir_name)
  except Exception as e:
    logging.error(e)


# retrieve VM source image information
def get_image_info(image_id, l_vm_instance):
  """Get source image info.

  Args:
    image_id: ID of the source image
    l_vm_instance: instance dictionary object

  Returns:
      Dictionary object.
  """
  disk_image = client.describe_images(ImageIds=[image_id,]).get('Images')
  l_vm_instance['OsType'] = disk_image[0].get('PlatformDetails')
  l_vm_instance['OsPublisher'] = disk_image[0].get('Description')
  return l_vm_instance


# retrieve information on the VM size (cpu, memory)
def get_image_size_details(instance_type, l_vm_instance):
  """Get image size details.

  Args:
    instance_type: instance type
    l_vm_instance: instance dictionary object

  Returns:
      Dictionary object.
  """
  instance_type_info = (
      client.describe_instance_types(
          InstanceTypes=[instance_type,]).get('InstanceTypes'))
  l_vm_instance['MemoryMiB'] = instance_type_info[0]['MemoryInfo']['SizeInMiB']
  l_vm_instance['AllocatedProcessorCoreCount'] = (
      instance_type_info[0]['VCpuInfo']['DefaultCores'])
  return l_vm_instance


# write data contained in dictionary list into csv file
def report_writer(dictionary_data, fiel_dname_list, file_name):
  """Get image size details.

  Args:
    dictionary_data: dictionary object
    fiel_dname_list: column names
    file_name: file name to be created

  Returns:
      Dictionary object.
  """
  try:
    logging.info('Writing %s to the disk', file_name)
    with open('./output/'+file_name, 'w', newline='') as csvfile:
      writer = csv.DictWriter(csvfile, fieldnames=fiel_dname_list)
      writer.writeheader()
      for dictionary_value in dictionary_data:
        writer.writerow(dictionary_value)
  except Exception as e:
    logging.error(e)


# retrieve information on disk attached to VM
def get_disk_info(vm_id, block_device_list, root_device_name):
  """Get network interface data.

  Args:
    vm_id: Instance ID
    block_device_list: list of attached disks
    root_device_name: name of the primary (OS) disk

  Returns:
      Disk create date.
  """
  try:
    disk_create_date = datetime.datetime.now()
    for block_device in block_device_list:
      disk = stratozonedict.vm_disk.copy()

      volume = client.describe_volumes(
          VolumeIds=[block_device['Ebs']['VolumeId'],]).get('Volumes')

      disk['MachineId'] = vm_id
      disk['DiskLabel'] = block_device['DeviceName']
      disk['SizeInGib'] = volume[0]['Size']
      disk['StorageTypeLabel'] = volume[0]['VolumeType']

      vm_disk_list.append(disk)

      if root_device_name == block_device['DeviceName']:
        disk_create_date = block_device['Ebs']['AttachTime']

    return disk_create_date

  except Exception as e:
    logging.error(e)


# retrieve information on the nic attached to the VM
def get_network_interface_info(interface_list, l_vm_instance):
  """Get network interface data.

  Args:
    interface_list: List of network interfaces
    l_vm_instance: instance dictionary object

  """
  try:
    ip_list = ''
    nic_count = 0

    for interface in interface_list:
      if nic_count == 0:
        l_vm_instance['PrimaryIPAddress'] = interface['PrivateIpAddress']

      ip_list = ip_list + interface['PrivateIpAddress'] + ';'
      if len(interface['Association']['PublicIp']) > 0:
        l_vm_instance['PublicIPAddress'] = interface['Association']['PublicIp']

      nic_count = nic_count + 1

    l_vm_instance['IpAddressListSemiColonDelimited'] = (
        ip_list.rstrip(ip_list[-1]))

  except Exception as e:
    logging.error(e)


# retrieve all the tags assigned to the VM
def get_instance_tags(vm_id, tag_dictionary, l_vm_instance):
  """Get tags assigned to instance.

  Args:
    vm_id: Instance ID
    tag_dictionary: list of assigned tags
    l_vm_instance: instance dictionary object

  Returns:
      Dictionary object.
  """
  try:
    # if there is no name tag assigned use instance id as name
    l_vm_instance['MachineName'] = vm_id

    for tag in tag_dictionary:
      tmp_tag = stratozonedict.vm_tag.copy()
      tmp_tag['MachineId'] = vm_id
      tmp_tag['Key'] = tag['Key']
      tmp_tag['Value'] = tag['Value']

      if tag['Key'] == 'Name':
        l_vm_instance['MachineName'] = tag['Value']

    vm_tag_list.append(tmp_tag)
    return l_vm_instance

  except Exception as e:
    logging.error(e)


def get_metric_data_query(namespace, metric_name,
                          dimension_name, dimension_value, unit, query_id=''):
  """Get performance matrics JSON query for the VM.

  Args:
    namespace: Query Namespace
    metric_name: Metric name
    dimension_name: Dimension name
    dimension_value: Dimension value
    unit: Unit of measure
    query_id: Optional unique ID for the query

  Returns:
      Formatted JSON query.
  """
  if not query_id:
    query_id = metric_name.lower()

  data_query = {
      'Id': query_id,
      'MetricStat': {
          'Metric': {
              'Namespace': namespace,
              'MetricName': metric_name,
              'Dimensions': [
                  {
                      'Name': dimension_name,
                      'Value': dimension_value
                  },]
          },
          'Period': 1800,
          'Stat': 'Average',
          'Unit': unit
      },
      'ReturnData': True,
  }
  return data_query


def get_performance_info(vm_id, region_name, block_device_list):
  """Query system for VM performance data.

  Args:
    vm_id: instance id.
    region_name: name of the AWS region
    block_device_list: list of devices (disks) attached to the vm
  """
  try:
    perf_client = boto3.client('cloudwatch', region_name)

    perf_queries = []
    disk_count = 0

    perf_queries.append(get_metric_data_query('AWS/EC2', 'CPUUtilization',
                                              'InstanceId', vm_id, 'Percent'))
    perf_queries.append(get_metric_data_query('AWS/EC2', 'NetworkOut',
                                              'InstanceId', vm_id,
                                              'Bytes'))
    perf_queries.append(get_metric_data_query('AWS/EC2', 'NetworkIn',
                                              'InstanceId', vm_id, 'Bytes'))
    for block_device in block_device_list:
      perf_queries.append(get_metric_data_query('AWS/EBS', 'VolumeReadOps',
                                                'VolumeId',
                                                block_device['Ebs']['VolumeId'],
                                                'Count',
                                                'volumereadops'
                                                + str(disk_count)))
      perf_queries.append(get_metric_data_query('AWS/EBS', 'VolumeWriteOps',
                                                'VolumeId',
                                                block_device['Ebs']['VolumeId'],
                                                'Count',
                                                'volumewriteops'
                                                + str(disk_count)))
      disk_count = disk_count + 1

      response = perf_client.get_metric_data(
          MetricDataQueries=perf_queries,
          StartTime=datetime.datetime.utcnow() - datetime.timedelta(days=30),
          EndTime=datetime.datetime.utcnow(),
          ScanBy='TimestampAscending'
      )

    first_arr_size = len(response['MetricDataResults'][0]['Values'])

    if (len(response['MetricDataResults'][1]['Values']) >= first_arr_size and
        len(response['MetricDataResults'][2]['Values']) >= first_arr_size and
        len(response['MetricDataResults'][3]['Values']) >= first_arr_size):

      for i in range(0, first_arr_size):
        vm_perf_info = stratozonedict.vm_perf.copy()
        vm_perf_info['MachineId'] = vm_id
        vm_perf_info['TimeStamp'] = (
            response['MetricDataResults'][0]['Timestamps'][i].strftime(
                '%m/%d/%Y, %H:%M:%S'))
        vm_perf_info['CpuUtilizationPercentage'] = (
            response['MetricDataResults'][0]['Values'][i])
        vm_perf_info['NetworkBytesPerSecSent'] = (
            response['MetricDataResults'][1]['Values'][i])
        vm_perf_info['NetworkBytesPerSecReceived'] = (
            response['MetricDataResults'][2]['Values'][i])

        tmp_read_io = 0
        tmp_write_io = 0

        for j in range(0, disk_count):
          tmp_read_io = tmp_read_io + (
              response['MetricDataResults'][3 + j]['Values'][i])
          tmp_write_io = tmp_write_io + (
              response['MetricDataResults'][4 + j]['Values'][i])

        vm_perf_info['DiskReadOperationsPerSec'] = (tmp_read_io /1800)
        vm_perf_info['DiskWriteOperationsPerSec'] = (tmp_write_io /1800)
        vm_perf_info['AvailableMemoryBytes'] = 0

        vm_perf_list.append(vm_perf_info)

  except Exception as e:
    logging.error(e)


# display progress on the screen
def display_script_progress():
  """Display collection progress."""
  try:
    sys.stdout.write('\r')
    sys.stdout.write('%s[%s%s] %i/%i\r' % ('Regions: ', '#'*region_counter,
                                           '.'*(total_regions-region_counter),
                                           region_counter, total_regions))
    sys.stdout.flush()
  except Exception as e:
    logging.error(e)


# check if region is enabled
def region_is_available(l_region):
  """Compress generated files into zip file for import into stratozone.

  Args:
    l_region: name of the region

  Returns:
    true/false

  """
  regional_sts = boto3.client('sts', l_region)
  try:
    regional_sts.get_caller_identity()
    return True
  except Exception as e:
    logging.error(e)
    return False


def zip_files(dir_name, zip_file_name):
  """Compress generated files into zip file for import into stratozone.

  Args:
    dir_name: source directory
    zip_file_name: name of the file to be created

  """
  csv_filter = lambda name: 'csv' in name

  if os.path.exists(zip_file_name):
    os.remove(zip_file_name)

  with zipfile.ZipFile(zip_file_name, 'w') as zip_obj:
    # Iterate over all the files in directory
    for folder_name, subfolders, file_names in os.walk(dir_name):
      for file_name in file_names:
        if csv_filter(file_name):
          file_path = os.path.join(folder_name, file_name)
          zip_obj.write(file_path, os.path.basename(file_path))


###########################################################################
# Collect information about deployed instances
###########################################################################

# create output and log directory
create_directory('./output')

logging.basicConfig(filename='./output/stratozone-aws-export.log',
                    level=logging.DEBUG)
logging.debug('Starting collection at: %s', datetime.datetime.now())


ec2_client = boto3.client('ec2')

logging.info('Get all regions')
regions = ec2_client.describe_regions(AllRegions=True)

logging.info('Get Organization ID')

region_counter = 0
total_regions = len(regions['Regions'])

# loop through all the regions and for each region get a list of deployed VMs
# process each VM retrieving all basic data as well as performance matrics.

for region in regions['Regions']:
  region_counter += 1
  if not region_is_available(region['RegionName']):
    continue

  client = boto3.client('ec2', region['RegionName'])

  display_script_progress()

  specific_instance = client.describe_instances()

  for reservation in specific_instance['Reservations']:
    for instance in reservation['Instances']:
      vm_instance = stratozonedict.vm_basic_info.copy()

      vm_instance['MachineId'] = instance.get('InstanceId')
      vm_instance['HostingLocation'] = region.get('RegionName')
      vm_instance['MachineTypeLabel'] = instance.get('InstanceType')
      vm_instance['MachineStatus'] = instance.get('State').get('Name')
      vm_instance = get_image_info(instance.get('ImageId'), vm_instance)
      vm_instance = get_image_size_details(instance.get('InstanceType'),
                                           vm_instance)

      if 'Tags' in instance:
        vm_instance = get_instance_tags(instance.get('InstanceId'),
                                        instance['Tags'],
                                        vm_instance)

        if 'NetworkInterfaces' in instance:
          get_network_interface_info(instance['NetworkInterfaces'],
                                     vm_instance)

      get_performance_info(instance['InstanceId'],
                           region['RegionName'],
                           instance['BlockDeviceMappings'])

      vm_create_timestamp = get_disk_info(instance['InstanceId'],
                                          instance['BlockDeviceMappings'],
                                          instance['RootDeviceName'])
      vm_instance['CreateDate'] = vm_create_timestamp

      vm_list.append(vm_instance)

# write collected data to files

field_names = ['MachineId', 'MachineName', 'PrimaryIPAddress',
               'PublicIPAddress', 'IpAddressListSemiColonDelimited',
               'TotalDiskAllocatedGiB', 'TotalDiskUsedGiB', 'MachineTypeLabel',
               'AllocatedProcessorCoreCount', 'MemoryMiB', 'HostingLocation',
               'OsType', 'OsPublisher', 'OsName', 'OsVersion',
               'MachineStatus', 'ProvisioningState', 'CreateDate', 'IsPhysical']

report_writer(vm_list, field_names, 'vmInfo.csv')

if vm_tag_list:
  field_names = ['MachineId', 'Key', 'Value']
  report_writer(vm_tag_list, field_names, 'tagInfo.csv')

field_names = ['MachineId', 'DiskLabel', 'SizeInGib', 'UsedInGib',
               'StorageTypeLabel']

report_writer(vm_disk_list, field_names, 'diskInfo.csv')

field_names = ['MachineId', 'TimeStamp', 'CpuUtilizationPercentage',
               'AvailableMemoryBytes', 'DiskReadOperationsPerSec',
               'DiskWriteOperationsPerSec', 'NetworkBytesPerSecSent',
               'NetworkBytesPerSecReceived']

report_writer(vm_perf_list, field_names, 'perfInfo.csv')

zip_files('./output/', 'aws-import-files.zip')

logging.debug('Collection completed at: %s', datetime.datetime.now())
