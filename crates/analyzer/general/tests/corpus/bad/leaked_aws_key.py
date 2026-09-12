# EXPECT: gen_hardcoded_secret
import boto3

client = boto3.client(
    "s3",
    aws_access_key_id="AKIAJ4X7Z2K9M1P3Q5R7",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzK8Dv2nQp9",
)
