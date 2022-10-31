# Changelog

### 1.4.3 (2022-10-31)
### Bug Fixes
* Add graceful script exit on cancel.
* Fix thread count parameter for resource collection.

### 1.4.2 (2022-10-04)
### Bug Fixes
* Set instance memory utilization to blank instead of 0 to indicate that this is not a value for powered off VM.

### 1.4.1 (2022-07-14)

### Improvement
* Add resource collection. List of deployed resource will be imported along with VM data to provide possible mapping to GCP resources.
* By default resources from following services are collected: 
        ec2, s3, route53, apigatewayv2, appconfig,
        appstream, appconfigdata, application-autoscaling,
        autoscaling, eks, efs, ebs, lambda, rds, sns,
        cloudfront, elasticbeanstalk, iam, glacier, kinesis,
        dynamodb, elasticache, redshift, sagemaker, sqs,
        lightsail, cloudwatch, chime, clouddirectory


### 1.3.4 (2022-06-22)

### Bug Fixes
* use DefaultVCpus instead of DefaultCores for vCPU count.


### 1.3.3 (2022-05-12)

### Improvement
* Increase VM performance data collection using threads.
* Add ability to skip public IP address collection. 
* Check installed version of boto3 sdk. 

### 1.1.8 (2022-03-08)

### Bug Fixes
* Add handling for vms with deleted ami source image.


### 1.1.6 (2022-02-22)

### Bug Fixes
* Set name for vms with no tags assigned.
* Support stopped VMs.
* Handling of vm disk errors.

### Documentation
* Update README with option to skip performance collection.

