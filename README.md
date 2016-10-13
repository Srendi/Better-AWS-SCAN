# Better-AWS-SCAN
This is a single python script which takes your AWS credentials and [a Slack Api Key] (https://get.slack.help/hc/en-us/articles/215770388-Create-and-regenerate-API-tokens) and recreates self signed certificates for some services, and only notifies on a CA signed certificate.
It can be used to automatically update SSL certs for the configured services. It is trivial to add other services.
