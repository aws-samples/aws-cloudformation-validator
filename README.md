# aws-cloudformation-validator
this is source code of python script use for validation CF template => more in the blog https://aws.amazon.com/blogs/devops/validating-aws-cloudformation-templates...

```
Usage python cf-validator.py --cf_path CF_Template_File --cf_rules Rules_File --cf_res Resource_File --allow_cap no --region us-east-1
```
### Parameters:

**--cf_path** [Required]: is the location of CloudFormation template in JSON format. Supported location:
* File system – path to CF template on file sytem
* Web – url to the file on the web e.g. http(s)://my-file.com/my_cf.json
* S3 – path to file in AWS S3 bucket e.g. s3://my_bucket/my_cf.json

**--cf_rules** [Required]: is the location of JSON file with validation rules. Supporting the same locations like above. See example in cf-rules.json

**--cf_res** [Optional]: is the location of JSON file with define AWS resources that existence need to be confirm before launch CF template. See example in cf-resources.json

**--allow_cap** [Optional][yes/no]: this parameter control if you allow create IAM resources such as: policy, rules, IAM user by CF template. Default value is no

**--region** [Optional]: AWS region where existing resources were created. Default value: us-east-1
