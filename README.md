<!--
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
-->

For automated AWS EC2 instances collection and assessment, use the [Migration Center discovery client CLI](https://cloud.google.com/migration-center/docs/discovery-client-cli-overview) to [discover EC2 instances](https://cloud.google.com/migration-center/docs/discover-aws-vms).

Contact mcdc-feedback-external@google.com for feedback and support.

## Solution Overview
__Warning:__ This project is currently in beta. Please open an issue if you would like to report a bug or documentation issue, request a feature, or have a question.

This script collects information from provided AWS account and generates csv/json files for import into StratoZone portal for analysis.
Generated files will be placed in ./output directory. For ease of use a compress zip file will be created that can be imported directly to StratoZone using the import procedure. 
Script will collect data only on the instances user executing the script has access to. 

Default thread setting is very conservative to allow for cloud shell execution. If the script is executed on desktop/server consider increasing the thread count using --thread_limit parameter. 

**NOTE** - Due to the unavailability of instance memory utilization, that metric will be ignored by the StratoZone recommendation engine.

- [Solution Overview](#solution-overview)
- [StratoZone AWS export usage](#stratozone-aws-export-usage)
- [Prerequisites](#prerequisites)
- [AWS Permissions](#aws-permissions)
- [Support](#support)

## Stratozone AWS export usage

- Step 1: Login to AWS Console

- Step 2: Launch Cloud Shell \
!["Image of Cloud Shell Console highlighting an icon with a greater-than and underscore"](images/aws-cloudshell.png)

> __NOTE:__ For RDS collection, please use an ec2 instance that can connect to the database.

- Step 3: Clone project to local shell
```
git clone https://github.com/GoogleCloudPlatform/aws-to-stratozone-export.git
```

- Step 4: Access cloned project directory
```
cd aws-to-stratozone-export/
```
- Step 5: Install required components
    - Step 5a: For RDS collection, use `python3 -m pip install -r requirements2.txt` to install the required components
    - Step 5b: Otherwise, use `python3 -m pip install -r requirements.txt` to install the required components
- Step 6: Run script to start collection
    - Step 6a: For virtual machine collection
      ```
      python3 stratozone-aws-export.py
      ```

      __NOTE:__ To skip performance data collection add `--no_perf` switch 
      ```
      python3 stratozone-aws-export.py --no_perf
      ```
    - Step 6b: For RDS and/or managed service collection
      ```
      python3 stratozone-aws-export.py -m ManagedService
      ```
      __NOTE:__ For database collection, rename db_secrets.sample.json to db_secrets.json and update the contents to include the list of regions and database connection info secret key names 

- Step 6: Verify output file has been generated
```
 ls ./*.zip
```

- Step 7: When the script completes, select download file from the Actions dropdown in upper right corner. \

!["Image of Cloud Shell Actions, download file"](images/aws-actions.png)

- Step 8: Enter the path to the output file.
    - Step 8a: For virtual machine collection
      ```
      ~/aws-to-stratozone-export/vm-aws-import-files.zip
      ```
    - Step 8b: For RDS and/or managed service collection
      ```
      ~/aws-to-stratozone-export/services-aws-import-files.zip
      ```    

- Step 9: Click Download. File is ready for import into StratoZone portal.

## Script Optional Parameters
* --no_perf (-n) - Default False. Use to indicate whether performance data will collected.
```
python3 stratozone-aws-export.py --no_perf
```
* --thread_limit (-t) - Default 30. Use to set the maximum number of threads to start during performance data collection.
```
python3 stratozone-aws-export.py --thread_limit 40
```
* --no_public_ip (-p) - Default False. Use to indicate whether public IP address will be collected.
```
python3 stratozone-aws-export.py --no_public_ip
```
* --resources (-p) - Default basic. Use to indicate resource collection type. Valid options (none, basic, all).
Basic option collects resources from following services: ec2, s3, route53, apigatewayv2, appconfig, appstream, 
        appconfigdata, application-autoscaling, autoscaling, eks, efs, ebs, lambda, rds, sns,
        cloudfront, elasticbeanstalk, iam, glacier, kinesis,dynamodb, elasticache, redshift, sagemaker, sqs,
        lightsail, cloudwatch, chime, clouddirectory
For other services use --resources=all option.
```
python3 stratozone-aws-export.py --resources=none
```

## Prerequisites

  For virtual machine collection, AWS Cloud Shell is the recommended environment to execute the collection script as it has all required components (Python3, AWS SDK) already installed.  Although, for RDS  collection, it might be easier to use an ec2 instance that has network connectivity to the databases.

  If the script will be executed from a workstation following components will need to be installed
  - Python 3.6 or later
  - AWS SDK version 1.20.20 or newer for Python (https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html)
  - You can use `python3 -m pip install -r requirements.txt` to install the required components

  For RDS collection, use AWS Secrets Manager to store database credentials (https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html) and create a file `db_secrets.json` to list the regions and secret names of the databases using [`db_secrets.schema.json`](db_secrets.schema.json).

## AWS Permissions
The script needs read-only access to the AWS organization where collection will be performed.

For database collection, the user running the script should have read-only permissions to connect to the database and there should be network connectivity configured between the databases and the ec2 instance running the script.

## Support
If the execution of the script fails please contact stratozone-support@google.com and attach log file located in ./output directory.
