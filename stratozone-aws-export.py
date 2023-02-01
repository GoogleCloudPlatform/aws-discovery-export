"""Copyright 2021 Google LLC.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

version 1.5.1

"""

import argparse
from concurrent.futures import ThreadPoolExecutor, wait
import csv
import datetime
import json
import logging
import os
import sys
import time
import zipfile
import signal
import concurrent.futures.thread

import boto3
from pkg_resources import parse_version as version
from db.rds_scanner import RdsScanner
import stratozonedict
import aws_resource_scan 


# global variables
vm_list = []
vm_tag_list = []
vm_disk_list = []
vm_perf_list = []
region_list = []

run_script = True

start = time.time()
# Initiate the parser
parser = argparse.ArgumentParser()
parser.add_argument(
    '-m',
    '--collection_mode',
    help='Choose if you want to run virtual machine collection or managed services collection.',
    choices=['VirtualMachine', 'ManagedService'],
    default='VirtualMachine')

parser.add_argument(
    '-n',
    '--no_perf',
    help='Do Not collect performance data.',
    action='store_true')
parser.add_argument(
    '-t',
    '--thread_limit',
    help='Number of threads for performance collection.',
    type=int,
    default=30)
parser.add_argument(
    '-p',
    '--no_public_ip',
    help='Do Not collect Public IP addresses.',
    action='store_true')
parser.add_argument(
    '-r',
    '--resources',
    help='Do Not collect deployed resources.',
    dest='resources',
    action='store',
    default='basic')

def handler_stop_signals(signum, frame):
    global run_script
    run_script = False
    print('Exiting application')
    sys.exit(0)

def create_directory(dir_name):
  """Create output directory.

  Args:
    dir_name: Destination directory
  """
  try:
    if not os.path.exists(dir_name):
      os.makedirs(dir_name)
  except Exception as e:
    logging.error('error in create_directory')
    logging.error(e)


def get_image_info(image_id, l_vm_instance):
  """Get source image info.

  Args:
    image_id: ID of the source image
    l_vm_instance: instance dictionary object

  Returns:
      Dictionary object.
  """
  try:
    disk_image = client.describe_images(ImageIds=[image_id,]).get('Images')
    if len(disk_image) > 0:
      l_vm_instance['OsType'] = disk_image[0].get('PlatformDetails')
      l_vm_instance['OsPublisher'] = disk_image[0].get('Description')
    else:
      l_vm_instance['OsType'] = 'unknown'
      l_vm_instance['OsPublisher'] = 'unknown'
    return l_vm_instance

  except Exception as e:
    logging.error('error in get_image_info')
    logging.error(e)
    l_vm_instance['OsType'] = 'unknown'
    l_vm_instance['OsPublisher'] = 'unknown'
    return l_vm_instance


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
  l_vm_instance['MemoryGiB'] = '{:.1f}'.format(
      instance_type_info[0]['MemoryInfo']['SizeInMiB']/1024)
  l_vm_instance['AllocatedProcessorCoreCount'] = (
      instance_type_info[0]['VCpuInfo']['DefaultVCpus'])
  return l_vm_instance


def report_writer(dictionary_data, field_name_list, file_name, directory = './output/vm/'):
  """write data contained in dictionary list into csv file.

  Args:
    dictionary_data: dictionary object
    field_name_list: column names
    file_name: file name to be created
    directory: parent directory

  Returns:
      Dictionary object.
  """
  try:
    logging.info('Writing %s to the disk', file_name)
    with open(directory + file_name, 'w', newline='') as csvfile:
      writer = csv.DictWriter(
          csvfile, fieldnames=field_name_list, extrasaction='ignore')
      writer.writeheader()
      for dictionary_value in dictionary_data:
        writer.writerow(dictionary_value)
  except Exception as e:
    logging.error('error in report_writer')
    logging.error(e)


def generate_disk_data(vm_id):
  """If no disk is found generate disk data to prevent import errors.

  Args:
    vm_id: Instance ID
  """
  disk = stratozonedict.vm_disk.copy()
  disk['MachineId'] = vm_id
  disk['DiskLabel'] = '/dev/xvda'
  disk['SizeInGib'] = '52.5'
  disk['StorageTypeLabel'] = 'gp2'
  vm_disk_list.append(disk)


def get_disk_info(vm_id, block_device_list, root_device_name):
  """Get attached disk data.

  Args:
    vm_id: Instance ID
    block_device_list: list of attached disks
    root_device_name: name of the primary (OS) disk

  Returns:
      Disk create date.
  """
  disk_count = 0

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
      disk_count = disk_count + 1
      if root_device_name == block_device['DeviceName']:
        disk_create_date = block_device['Ebs']['AttachTime']

    if disk_count == 0:
      generate_disk_data(vm_id)

    return disk_create_date

  except Exception as e:
    if disk_count == 0:
      generate_disk_data(vm_id)

    logging.error('error in get_disk_info')
    logging.error(e)
    return disk_create_date


def get_network_interface_info(interface_list, l_vm_instance):
  """Get network interface data.

  Args:
    interface_list: List of network interfaces
    l_vm_instance: instance dictionary object

  """
  try:
    ip_list = []

    for nic_count, interface in enumerate(interface_list):
      if nic_count == 0:
        l_vm_instance['PrimaryIPAddress'] = interface['PrivateIpAddress']
        l_vm_instance['PrimaryMACAddress'] = interface['MacAddress']

      ip_list.append(interface['PrivateIpAddress'])

      if not args.no_public_ip:
        if 'Association' in interface:
          if len(interface['Association']['PublicIp']) > 0:
            l_vm_instance['PublicIPAddress'] = (
                interface['Association']['PublicIp'])
            ip_list.append(interface['Association']['PublicIp'])

    l_vm_instance['IpAddressListSemiColonDelimited'] = (';'.join(ip_list))

  except Exception as e:
    logging.error('error in get_network_interface_info')
    logging.error(e)


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
    logging.error('error in get_instance_tags')
    logging.error(e)
    return l_vm_instance


def get_metric_data_query(namespace, metric_name,
                          dimension_name, dimension_value, unit, query_id=''):
  """Get performance metrics JSON query for the VM.

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
    global vm_perf_list
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
                                                block_device,
                                                'Count',
                                                'volumereadops'
                                                + str(disk_count)))
      perf_queries.append(get_metric_data_query('AWS/EBS', 'VolumeWriteOps',
                                                'VolumeId',
                                                block_device,
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
                '%Y/%m/%d, %H:%M:%S'))
        vm_perf_info['CpuUtilizationPercentage'] = '{:.2f}'.format(
            response['MetricDataResults'][0]['Values'][i])
        vm_perf_info['NetworkBytesPerSecSent'] = '{:.4f}'.format(
            response['MetricDataResults'][1]['Values'][i])
        vm_perf_info['NetworkBytesPerSecReceived'] = '{:.4f}'.format(
            response['MetricDataResults'][2]['Values'][i])

        tmp_read_io = 0
        tmp_write_io = 0

        for j in range(0, disk_count):
          tmp_read_io = tmp_read_io + (
              response['MetricDataResults'][3 + j]['Values'][i])
          tmp_write_io = tmp_write_io + (
              response['MetricDataResults'][4 + j]['Values'][i])

        vm_perf_info['DiskReadOperationsPerSec'] = '{:.4f}'.format(
            (tmp_read_io /1800))
        vm_perf_info['DiskWriteOperationsPerSec'] = '{:.4f}'.format(
            (tmp_write_io /1800))
        vm_perf_info['AvailableMemoryBytes'] = ''
        vm_perf_info['MemoryUtilizationPercentage'] = ''

        vm_perf_list.append(vm_perf_info)

  except Exception as e:
    logging.error('error in get_performance_info')
    logging.error(e)


def display_script_progress():
  """Display collection progress."""
  try:
    sys.stdout.write('\r')
    sys.stdout.write('%s[%s%s] %i/%i\r' % ('Regions: ', '#'*region_counter,
                                           '.'*(total_regions-region_counter),
                                           region_counter, total_regions))
    sys.stdout.flush()
  except Exception as e:
    logging.error('error in display_script_progress')
    logging.error(e)


def region_is_available(l_region):
  """Check if region is enabled.

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
    logging.error('error in region_is_available')
    logging.error(e)
    return False


def zip_files(dir_name, zip_file_name):
  """Compress generated files into zip file for import into stratozone.

  Args:
    dir_name: source directory
    zip_file_name: name of the file to be created

  """
  csv_filter = lambda name: 'csv' in name or 'json' in name

  if os.path.exists(zip_file_name):
    os.remove(zip_file_name)

  with zipfile.ZipFile(zip_file_name, 'w') as zip_obj:
    # Iterate over all the files in directory
    for folder_name, sub_folder, file_names in os.walk(dir_name):
      for file_name in file_names:
        if csv_filter(file_name):
          file_path = os.path.join(folder_name, file_name)
          zip_obj.write(file_path, os.path.basename(file_path))


###########################################################################
# Collect information about deployed instances
###########################################################################

signal.signal(signal.SIGINT, handler_stop_signals)
signal.signal(signal.SIGTERM, handler_stop_signals)

# Read arguments from the command line
args = parser.parse_args()


if version(boto3.__version__) < version('1.20.20'):
  print('You are using version of AWS Python SDK that is too old.'
        '\nVersion installed: {}'
        '\nPlease upgrade to the latest version.'
        '\nhttps://boto3.amazonaws.com/v1/documentation/api/'
        'latest/guide/quickstart.html'.format(boto3.__version__))
  exit()

while run_script:
  # create output and log directory
  create_directory('./output/vm')
  create_directory('./output/services')

  log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  logging.basicConfig(filename='./output/stratozone-aws-export.log',
                      format=log_format,
                      level=logging.ERROR)
  logging.debug('Starting collection at: %s', datetime.datetime.now())
  ec2_client = boto3.client('ec2')

  logging.info('Get all regions')
  regions = ec2_client.describe_regions(AllRegions=True)
  region_list = list(map(lambda x:x['RegionName'], regions['Regions']))

  if args.collection_mode == 'VirtualMachine':

    logging.info('Get Organization ID')

    region_counter = 0
    total_regions = len(regions['Regions'])

    # loop through all the regions and for each region get a list of deployed VMs
    # process each VM retrieving all basic data as well as performance metrics.


    for region in regions['Regions']:
      region_counter += 1
      if not region_is_available(region['RegionName']):
        continue
      
      region_list.append(region['RegionName'])

      client = boto3.client('ec2', region['RegionName'])

      display_script_progress()

      specific_instance = client.describe_instances()

      for reservation in specific_instance['Reservations']:
        for instance in reservation['Instances']:
          if instance.get('State').get('Name') == 'terminated':
            continue

          vm_instance = stratozonedict.vm_basic_info.copy()

          vm_instance['MachineId'] = instance.get('InstanceId')
          vm_instance['HostingLocation'] = region.get('RegionName')
          vm_instance['MachineTypeLabel'] = instance.get('InstanceType')
          vm_instance['MachineStatus'] = instance.get('State').get('Name')
          vm_instance = get_image_info(instance.get('ImageId'), vm_instance)

          if vm_instance['OsType'] == 'unknown':
            tmp_os_value = 'Linux'
            if ('windows' in instance.get('PlatformDetails').lower() or
                'sql' in instance.get('PlatformDetails').lower()):
              tmp_os_value = 'Windows'

            vm_instance['OsType'] = tmp_os_value
            vm_instance['OsPublisher'] = tmp_os_value

          vm_instance = get_image_size_details(instance.get('InstanceType'),
                                              vm_instance)

          if 'Tags' in instance:
            vm_instance = get_instance_tags(instance.get('InstanceId'),
                                            instance['Tags'],
                                            vm_instance)
          else:
            vm_instance['MachineName'] = vm_instance['MachineId']

          if 'NetworkInterfaces' in instance:
            get_network_interface_info(instance['NetworkInterfaces'],
                                      vm_instance)

          disk_id_list = []
          for tt in instance['BlockDeviceMappings']:
            disk_id_list.append(tt['Ebs']['VolumeId'])

          vm_create_timestamp = get_disk_info(instance['InstanceId'],
                                              instance['BlockDeviceMappings'],
                                              instance['RootDeviceName'])
          vm_instance['CreateDate'] = vm_create_timestamp.strftime('%Y/%m/%d, %H:%M:%S')
          vm_instance['DiskIDs'] = disk_id_list

          vm_list.append(vm_instance)


    if not args.no_perf:
      processes = []
      print('Inventory collection completed.'
            ' Collecting performance using {} threads'.format(args.thread_limit))

      with ThreadPoolExecutor(max_workers=args.thread_limit) as executor:
        try:
          for cvm in vm_list:
            processes.append(executor.submit(get_performance_info,
                                            cvm['MachineId'],
                                            cvm['HostingLocation'],
                                            cvm['DiskIDs']))
        except KeyboardInterrupt:
          executor._threads.clear()
          concurrent.futures.thread._threads_queues.clear()
          sys.exit()
          raise

      wait(processes)

    # write collected data to files
    created_files = 4

    field_names = ['MachineId', 'MachineName', 
                  'PrimaryIPAddress', 'PrimaryMACAddress',
                  'PublicIPAddress', 'IpAddressListSemiColonDelimited',
                  'TotalDiskAllocatedGiB', 'TotalDiskUsedGiB', 
                  'MachineTypeLabel', 'AllocatedProcessorCoreCount',
                  'MemoryGiB', 'HostingLocation', 'OsType',
                  'OsPublisher', 'OsName', 'OsVersion', 'MachineStatus',
                  'ProvisioningState', 'CreateDate', 'IsPhysical', 'Source']

    report_writer(vm_list, field_names, 'vmInfo.csv')

    if vm_tag_list:
      field_names = ['MachineId', 'Key', 'Value']
      report_writer(vm_tag_list, field_names, 'tagInfo.csv')

    field_names = ['MachineId', 'DiskLabel', 'SizeInGib', 'UsedInGib',
                  'StorageTypeLabel']

    report_writer(vm_disk_list, field_names, 'diskInfo.csv')

    field_names = ['MachineId', 'TimeStamp', 'CpuUtilizationPercentage',
                  'MemoryUtilizationPercentage','AvailableMemoryBytes', 
                  'DiskReadOperationsPerSec', 'DiskWriteOperationsPerSec',
                  'NetworkBytesPerSecSent', 'NetworkBytesPerSecReceived']

    if not args.no_perf:
      report_writer(vm_perf_list, field_names, 'perfInfo.csv')
    else:
      created_files = 3

    zip_files('./output/', 'vm-aws-import-files.zip')
    logging.debug('Collection completed at: %s', datetime.datetime.now())
    print('\nExport Completed. \n')
    print('vm-aws-import-files.zip generated successfully containing {} files.'
          .format(created_files))

    if args.no_perf:
      print('Performance data was not collected.')

    if args.no_public_ip:
      print('Public IP address data was not collected.')
    break
  elif args.collection_mode == 'ManagedService':
    start_time = datetime.datetime.now()
    created_files = 0

    if args.resources != 'none':
      aws_resource_scan.scan_aws(args.resources, region_list, args.thread_limit)
      created_files = created_files + 1 
    else:
      print('Skipping resource collection.            ')

    end_time = datetime.datetime.now()

    time_delta = end_time - start_time
    logging.info('Completing resource collection.')
    logging.info(time_delta) 

    if os.path.isfile('db_secrets.json'):
      with open('db_secrets.json', 'r') as f:
        data = json.load(f)

      for region in data:
        for secret in region['secrets']:
          scanner = RdsScanner()
          if scanner.scan(secret, region['region']):
            created_files += 1
    else:
      print('Skipping database collection.')

    zip_files('./output/services/', 'services-aws-import-files.zip')
    logging.debug('Collection completed at: %s', datetime.datetime.now())
    print('\nExport Completed. \n')
    print('services-aws-import-files.zip generated successfully containing {} files.'
          .format(created_files))
    break